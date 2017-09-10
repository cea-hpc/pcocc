import os
import logging
import subprocess
import socket
import re
import signal
import struct
import shlex

from .Networks import  VNetwork
from .Error import PcoccError, InvalidConfigurationError
from .Config import Config
from .Misc import IDAllocator
from .NetUtils import NetworkSetupError

# These network types are deprecated and should no longer be used

class VPVNetwork(VNetwork):
    _schema="""
properties:
  type:
      enum:
        - pv

  settings:
    type: object
    properties:
      mac-prefix:
       type: string
       default-value: '52:54:00'
       pattern: '^([0-9a-fA-F]{2}:){0,3}[0-9a-fA-F]{2}$'
      bridge-prefix:
       type: string
      tap-prefix:
       type: string
      mtu:
       type: integer
       default-value: 1500
      host-if-suffix:
       type: string
    additionalProperties: false
    required:
     - bridge-prefix
     - tap-prefix

additionalProperties: false
"""

    def __init__(self, name, settings):
        super(VPVNetwork, self).__init__(name)

        self._mac_prefix = settings.get("mac-prefix", "52:54:00")
        self._bridge_prefix = settings["bridge-prefix"]
        self._tap_prefix = settings["tap-prefix"]
        self._mtu = int(settings.get("mtu", 1500))
        self._host_if_suffix = settings["host-if-suffix"]
        self._min_key = 1024
        self._max_key = 2 ** 16 - 1
        self._type = "ethernet"
        self._ida = IDAllocator(self._get_type_key_path('key_alloc_state'),
                                self._max_key - self._min_key + 1)

    def init_node(self):
        pass

    def cleanup_node(self):
        #TODO: What to do if there are unexpected taps or bridges left
        self._cleanup_stray_bridges()
        self._cleanup_stray_taps()

    def alloc_node_resources(self, cluster):
        batch = Config().batch

        bridge_name = find_free_dev_name(self._bridge_prefix)
        tap_user = batch.batchuser
        net_res = {}
        host_tunnels = {}
        local_ports = []
        master = -1

        for vm in cluster.vms:
            if self.name in vm.networks:
                if master == -1:
                    master = vm.get_host_rank()
                if vm.is_on_node():
                    break
        else:
            #No vm on node, nothing to do
            return

        if batch.node_rank == master:
            logging.info("Node is master for PV network %s",
                         self.name)
        try:
            tun_id = self._min_key + self._ida.coll_alloc_one(
                master,
                '{0}_key'.format(self.name))
        except PcoccError as e:
            raise NetworkSetupError('{0}: {1}'.format(
                self.name,
                str(e)
            ))


        bridge_created = False
        for vm in cluster.vms:
            if not self.name in vm.networks:
                continue

            if not bridge_created:
                ovs_add_bridge(bridge_name)
                ip_set_mtu(bridge_name, self._mtu)
                bridge_created = True

            hwaddr = self._gen_vm_hwaddr(vm)
            if vm.is_on_node():
                tap_name = find_free_dev_name(self._tap_prefix)
                tun_create_tap(tap_name, tap_user)
                dev_enable(tap_name)
                ip_set_mtu(tap_name, self._mtu)
                port_id = ovs_add_port(tap_name, bridge_name)

                local_ports.append(port_id)

                # Incoming packets to the VM are directly
                # sent to the destination tap
                ovs_add_flow(bridge_name,
                             0, 3000,
                             "idle_timeout=0,hard_timeout=0,"
                             "dl_dst=%s,actions=output:%s"
                             % (hwaddr, port_id))

                # Flood packets sent from the VM without a known
                # destination
                # FIXME: answer
                # directly to ARP requests and drop other broadcast
                # packets as this is too inefficient
                ovs_add_flow(bridge_name,
                             0, 2000,
                             "in_port=%s,"
                             "idle_timeout=0,hard_timeout=0,"
                             "actions=flood" % (
                        port_id))


                vm_label = self._vm_res_label(vm)
                net_res[vm_label] = {'tap_name': tap_name,
                                     'hwaddr': hwaddr,
                                     'port_id': port_id}

            else:
                host = vm.get_host()
                if host not in host_tunnels:
                    tunnel_port_id = ovs_add_tunnel(bridge_name,
                                                    "htun-%s-%s" % (
                                                        bridge_name,
                                                        len(host_tunnels)),
                                                    "vxlan",
                                                    "%s%s" % (
                            host,
                            self._host_if_suffix),
                                                    tun_id)
                    host_tunnels[host] = tunnel_port_id

                # Directly forward packets for a remote VM to the
                # correct destination
                ovs_add_flow(bridge_name,
                             0, 3000,
                             "idle_timeout=0,hard_timeout=0,"
                             "dl_dst=%s,actions=output:%s"
                             % (hwaddr, host_tunnels[host]))

        # Incoming broadcast packets: output to all local VMs
        # TODO: answer directly to ARP requests and drop other
        # broadcast packets
        if local_ports:
            ovs_add_flow(bridge_name,
                         0, 1000,
                         "idle_timeout=0,hard_timeout=0,"
                         "actions=output:%s" % (
                    ','.join([str(port) for port in local_ports])))

        net_res['global'] = {'bridge_name': bridge_name,
                             'tun_id': tun_id,
                             'master': master}
        self.dump_resources(net_res)

    def free_node_resources(self, cluster):
        net_res = None
        bridge_name = None
        master = -1
        for vm in cluster.vms:
            if not vm.is_on_node():
                continue

            if not self.name in vm.networks:
                continue

            if not net_res:
                net_res = self.load_resources()
                bridge_name = net_res['global']['bridge_name']
                master = net_res['global']['master']

            vm_label = self._vm_res_label(vm)

            # Remove the tap from the bridge
            tap_name = net_res[vm_label]['tap_name']
            ovs_del_port(tap_name, bridge_name)
            tun_delete_tap(tap_name)

        if bridge_name:
            ovs_del_bridge(bridge_name)

        if master == Config().batch.node_rank:
            # Free tunnel key
            try:
                self._ida.free_one(int(net_res['global']['tun_id']) - self._min_key)
            except PcoccError as e:
                raise NetworkSetupError('{0}: {1}'.format(
                    self.name,
                    str(e)
                ))

            # Cleanup keystore
            Config().batch.delete_dir(
                'cluster',
                self._get_net_key_path(''))

    def load_node_resources(self, cluster):
        net_res = None
        for vm in cluster.vms:
            if not vm.is_on_node():
                continue

            if not self.name in vm.networks:
                continue

            if not net_res:
                net_res = self.load_resources()

            vm_label = self._vm_res_label(vm)
            vm.add_eth_if(self.name,
                          net_res[vm_label]['tap_name'],
                          net_res[vm_label]['hwaddr'])

    def _cleanup_stray_bridges(self):
        # Look for remaining bridges to cleanup
        for bridge_id in find_used_dev_ids(self._bridge_prefix):
            logging.warning(
                'Deleting leftover bridge for %s network', self.name)
            # Delete the bridge
            bridge_name = dev_name_from_id(self._bridge_prefix,
                                           bridge_id)
            ovs_del_bridge(bridge_name)

    def _cleanup_stray_taps(self):
        # Look for remaining taps to cleanup
        for tap_id in find_used_dev_ids(self._tap_prefix):
            logging.warning(
                'Deleting leftover tap for %s network', self.name)

            # Delete the tap
            tap_name = dev_name_from_id(self._tap_prefix,
                                        tap_id)
            tun_delete_tap(tap_name)

    def _gen_vm_hwaddr(self, vm):
        hw_prefix = self._mac_prefix # Complete prefixes only
        prefix_len = len(hw_prefix.replace(':', ''))
        suffix_len = 12 - prefix_len
        hw_suffix = ("%x"%(vm.rank)).zfill(suffix_len)
        hw_suffix = ':'.join(
            hw_suffix[i:i+2] for i in xrange(0, len(hw_suffix), 2))

        return hw_prefix + ':' + hw_suffix


class VNATNetwork(VNetwork):
    _schema="""
properties:
  type:
      enum:
        - nat

  settings:
    type: object
    properties:
      nat-network:
       type: string
      vm-network:
       type: string
      vm-network-gw:
       type: string
      vm-ip:
       type: string
      vm-hwaddr:
       type: string
       default-value: '52:54:00:44:AE:5E'
       pattern: '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'
      bridge:
       type: string
      bridge-hwaddr:
       type: string
       default-value: '52:54:00:C0:C0:C0'
       pattern: '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'
      tap-prefix:
       type: string
      mtu:
       type: integer
       default-value: 1500
      domain-name:
       type: string
       default-value: ''
      dns-server:
       type: string
       default-value: ''
      ntp-server:
       type: string
       default-value: ''
      reverse-nat:
       type: object
      allow-outbound:
       type: string
       default-value: 'all'
    additionalProperties: false
    required:
     - nat-network
     - vm-network
     - vm-network-gw
     - vm-ip
     - bridge
     - tap-prefix
additionalProperties: false
"""
    def __init__(self, name, settings):
        super(VNATNetwork, self).__init__(name)

        self._type = "ethernet"
        self._bridge_name = settings["bridge"]


        self._nat_network = settings["nat-network"].split("/")[0]
        self._nat_network_bits = int(settings["nat-network"].split("/")[1])
        self._vm_network = settings["vm-network"].split("/")[0]
        self._vm_network_bits = int(settings["vm-network"].split("/")[1])


        self._vm_network_gw = settings["vm-network-gw"]
        self._vm_ip = settings["vm-ip"]
        self._tap_prefix = settings["tap-prefix"]

        self._mtu = int(settings.get("mtu", 1500))


        self._vm_hwaddr = settings.get("vm-hwaddr", "52:54:00:44:AE:5E")
        self._bridge_hwaddr = settings.get("bridge-hwaddr", "52:54:00:C0:C0:C0")
        self._dnsmasq_pid_filename = "/var/run/pcocc_dnsmasq.pid"
        self._domain_name = settings.get('domain-name', '')
        self._dns_server = settings.get('dns-server', '')
        self._ntp_server = settings.get('ntp-server', '')
        self._allow_outbound = settings.get('allow-outbound', 'all')

        if self._allow_outbound == 'none':
            self._allow_outbound = False
        elif self._allow_outbound == 'all':
            self._allow_outbound = True
        else:
            raise InvalidConfigurationError(
                '%s is not a valid value '
                'for allow-outbound' % self._allow_outbound)

        if "reverse-nat" in settings:
            self._vm_rnat_port = int(settings["reverse-nat"]["vm-port"])
            self._host_rnat_port_range = (
                int(settings["reverse-nat"]["min-host-port"]),
                int(settings["reverse-nat"]["max-host-port"]))

    def kill_dnsmasq(self):
        # Terminate dnsmasq
        if os.path.isfile(self._dnsmasq_pid_filename):
            with open(self._dnsmasq_pid_filename, 'r') as f:
                pid = f.read()
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except (OSError ,ValueError):
                    pass
            os.remove(self._dnsmasq_pid_filename)

    def has_dnsmasq(self):
        if os.path.isfile(self._dnsmasq_pid_filename):
            with open(self._dnsmasq_pid_filename, 'r') as f:
                pid = f.read()
                try:
                    os.kill(int(pid), 0)
                    return True
                except (OSError, ValueError):
                    return False
        else:
            return False

    def init_node(self):
        if not ovs_bridge_exists(self._bridge_name):
            # Create nat bridge
            ovs_add_bridge(self._bridge_name, self._bridge_hwaddr)
            self.kill_dnsmasq()
        else:
            #Check bridge settings
            ovs_add_bridge(self._bridge_name, self._bridge_hwaddr)

        # Configure the bridge with the GW ip on the VM network
        ip_add_idemp(self._vm_network_gw,
                     self._vm_network_bits,
                     self._bridge_name)

        # Also give the bridge an IP on the NAT network with unique
        # IPs for each VM
        bridge_nat_ip = get_ip_on_network(self._nat_network, 1)
        ip_add_idemp(bridge_nat_ip,
                     self._vm_network_bits,
                     self._bridge_name)

        if not self.has_dnsmasq():
            # Start a dnsmasq server to answer DHCP requests
            dnsmasq_opts = ""
            if self._ntp_server:
                dnsmasq_opts+="--dhcp-option=option:ntp-server,{0} ".format(
                    self._ntp_server)

            if self._dns_server:
                dnsmasq_opts+="--dhcp-option=option:dns-server,{0} ".format(
                    self._dns_server)

            subprocess.check_call(
                shlex.split("/usr/sbin/dnsmasq --strict-order "
                            "--bind-interfaces "
                            "--pid-file=%s "
                            "--conf-file= --interface=%s "
                            "--except-interface=lo --leasefile-ro "
                            "--dhcp-lease-max=512 "
                            "--dhcp-no-override "
                            "--dhcp-host %s,%s "
                            "--dhcp-option=option:domain-name,%s "
                            "--dhcp-option=119,%s "
                            "%s"
                            "--dhcp-option=option:netmask,%s "
                            "--dhcp-option=option:router,%s "
                            "-F %s,static " %(
                        self._dnsmasq_pid_filename,
                        self._bridge_name,
                        self._vm_hwaddr,
                        self._vm_ip,
                        self._domain_name.split(',')[0],
                        self._domain_name,
                        dnsmasq_opts,
                        num_to_dotted_quad(make_mask(self._vm_network_bits)),
                        self._vm_network_gw,
                        self._vm_ip)))

        # Enable Routing for the bridge only
        subprocess.check_call("echo 1 > /proc/sys/net/ipv4/ip_forward",
                      shell=True)
        subprocess.check_call("iptables -P FORWARD DROP",
                      shell=True)

        ipt_append_rule_idemp("-d %s/%d -o %s -p tcp -m tcp --dport 22 "
                              "-m state --state NEW -j ACCEPT"
                              % (self._nat_network,
                                 self._vm_network_bits,
                                 self._bridge_name),
                              "FORWARD")

        ipt_append_rule_idemp("-d %s/%d -o %s "
                              "-m state --state RELATED,ESTABLISHED "
                              "-j ACCEPT"
                              % (self._nat_network,
                                 self._vm_network_bits,
                                 self._bridge_name),
                              "FORWARD")

        if self._allow_outbound:
            ipt_append_rule_idemp("-s %s/%d -i %s -j ACCEPT"
                                  % (self._nat_network,
                                     self._vm_network_bits,
                                     self._bridge_name),
                                  "FORWARD")
        else:
            ipt_append_rule_idemp("-s %s/%d -i %s "
                                  "-m state --state RELATED,ESTABLISHED -j ACCEPT"
                                  % (self._nat_network,
                                     self._vm_network_bits,
                                     self._bridge_name),
                                  "FORWARD")

        # Enable NAT to/from the bridge for unique vm adresses
        ipt_append_rule_idemp("-s %s/%d ! -d %s/%d -p tcp -j MASQUERADE "
                              "--to-ports 1024-65535"
                              % (self._nat_network,
                                 self._vm_network_bits,
                                 self._nat_network,
                                 self._vm_network_bits),
                              "POSTROUTING", "nat")

        ipt_append_rule_idemp("-s %s/%d ! -d %s/%d -p udp -j MASQUERADE "
                              "--to-ports 1024-65535" % (self._nat_network,
                                                         self._vm_network_bits,
                                                         self._nat_network,
                                                         self._vm_network_bits),
                              "POSTROUTING", "nat")

        ipt_append_rule_idemp("-s %s/%d ! -d %s/%d -j MASQUERADE"
                              % (self._nat_network,
                                 self._vm_network_bits,
                                 self._nat_network,
                                 self._vm_network_bits),
                              "POSTROUTING", "nat")

        # Deliver ARP requests from each port to the bridge and only
        # to the bridge
        ovs_add_flow(self._bridge_name,
                     0, 1000,
                     "idle_timeout=0,hard_timeout=0,"
                     "dl_type=0x0806,nw_dst=%s,actions=local"
                     % (self._vm_network_gw))

        # Flood ARP answers from the bridge to each port
        ovs_add_flow(self._bridge_name,
                     0, 1000,
                     "in_port=local,idle_timeout=0,hard_timeout=0,"
                     "dl_type=0x0806,nw_dst=%s,actions=flood"%(self._vm_ip))

        # Flood DHCP answers from the bridge to each port
        ovs_add_flow(self._bridge_name,
                     0, 0,
                     "idle_timeout=0,hard_timeout=0,"
                     "in_port=LOCAL,udp,tp_dst=68,actions=FLOOD")




    def cleanup_node(self):
        # Disable routing
        subprocess.check_call("echo 0 > /proc/sys/net/ipv4/ip_forward",
                      shell=True)
        subprocess.check_call("iptables -P FORWARD ACCEPT",
                      shell=True)

        # Remove bridge
        ovs_del_bridge(self._bridge_name)

        # Remove routing rules
        ipt_delete_rule_idemp("-d %s/%d -o %s -m state "
                              "--state RELATED,ESTABLISHED "
                              "-j ACCEPT"
                              % (self._nat_network,
                                 self._nat_network_bits,
                                 self._bridge_name),
                              "FORWARD")

        if self._allow_outbound:
            ipt_delete_rule_idemp("-s %s/%d -i %s -j ACCEPT"
                                  % (self._nat_network,
                                     self._vm_network_bits,
                                     self._bridge_name),
                                  "FORWARD")
        else:
            ipt_delete_rule_idemp("-s %s/%d -i %s "
                                  "-m state --state RELATED,ESTABLISHED "
                                  "-j ACCEPT"
                                  % (self._nat_network,
                                     self._vm_network_bits,
                                     self._bridge_name),
                                  "FORWARD")

        # Remove NAT rules
        ipt_delete_rule_idemp("-d %s/%d -o %s -p tcp -m tcp "
                              "--dport 22 -m state "
                              "--state NEW -j ACCEPT"
                              % (self._nat_network,
                                 self._nat_network_bits,
                                 self._bridge_name),
                              "FORWARD")

        ipt_delete_rule_idemp("-s %s/%d ! -d %s/%d -p tcp -j MASQUERADE "
                              "--to-ports 1024-65535"
                              % (self._nat_network,
                                 self._nat_network_bits,
                                 self._nat_network,
                                self._nat_network_bits),
                              "POSTROUTING", "nat")

        ipt_delete_rule_idemp("-s %s/%d ! -d %s/%d -p udp -j MASQUERADE "
                              "--to-ports 1024-65535"
                              % (self._nat_network,
                                 self._nat_network_bits,
                                 self._nat_network,
                                 self._nat_network_bits),
                              "POSTROUTING", "nat")

        ipt_delete_rule_idemp("-s %s/%d ! -d %s/%d -j MASQUERADE"
                              % (self._nat_network,
                                 self._nat_network_bits,
                                 self._nat_network,
                                 self._nat_network_bits),
                              "POSTROUTING", "nat")

        # Look for remaining taps to cleanup
        for tap_id in find_used_dev_ids(self._tap_prefix):
            logging.warning(
                'Deleting leftover tap for %s network', self.name)

            # Delete the tap
            tun_delete_tap(dev_name_from_id(self._tap_prefix,
                                            tap_id))


        self.kill_dnsmasq()

    def alloc_node_resources(self, cluster):
        net_res = {}
        for vm in cluster.vms:
            if not vm.is_on_node():
                continue

            if not self.name in vm.networks:
                continue

            vm_label = self._vm_res_label(vm)
            net_res[vm_label] = self._alloc_vm_res(vm)

        self.dump_resources(net_res)

    def free_node_resources(self, cluster):
        net_res = None
        for vm in cluster.vms:
            if not vm.is_on_node():
                continue

            if not self.name in vm.networks:
                continue

            if not net_res:
                net_res = self.load_resources()

            vm_label = self._vm_res_label(vm)
            self._cleanup_vm_res(net_res[vm_label])

    def load_node_resources(self, cluster):
        net_res = None
        for vm in cluster.vms:
            if not vm.is_on_node():
                continue

            if not self.name in vm.networks:
                continue

            if not net_res:
                net_res = self.load_resources()

            vm_label = self._vm_res_label(vm)

            if 'host_port' in net_res[vm_label]:
                vm.add_eth_if(self.name,
                              net_res[vm_label]['tap_name'],
                              net_res[vm_label]['hwaddr'],
                              net_res[vm_label]['host_port'])
            else:
                vm.add_eth_if(self.name,
                              net_res[vm_label]['tap_name'],
                              net_res[vm_label]['hwaddr'])


    def _alloc_vm_res(self, vm):
        # Allocate a local VM id unique on this node
        nat_id = find_free_dev_id(self._tap_prefix)

        # Define the VM tap name and unique IP based on the VM id
        tap_name = dev_name_from_id(self._tap_prefix, nat_id)
        vm_nat_ip = self._vm_ip_from_id(nat_id)

        # Create and enable the tap
        tun_create_tap(tap_name, Config().batch.batchuser)
        dev_enable(tap_name)

        # Connect it to the bridge
        vm_port_id = ovs_add_port(tap_name, self._bridge_name)

        # Rewrite outgoing packets with the VM unique IP
        ovs_add_flow(self._bridge_name,
                     0, 1000,
                     "in_port=%d,idle_timeout=0,hard_timeout=0,"
                     "dl_type=0x0800,nw_src=%s,actions=mod_nw_src:%s,local"
                     % (vm_port_id,
                        self._vm_ip,
                        vm_nat_ip))

        # Rewrite incoming packets with the VM real IP
        ovs_add_flow(self._bridge_name,
                     0, 1000,
                     "in_port=local,idle_timeout=0,hard_timeout=0,"
                     "dl_type=0x0800,nw_dst=%s,actions=mod_nw_dst:%s,output:%d"
                     % (vm_nat_ip,
                        self._vm_ip,
                        vm_port_id))

        # Handle DHCP requests from the VM locally
        ovs_add_flow(self._bridge_name,
                     0, 1000,
                     "in_port=%d,idle_timeout=0,hard_timeout=0,"
                     "udp,tp_dst=67,priority=0,actions=local"
                     % (vm_port_id))

        # Add a permanent ARP entry for the VM unique IP
        # so that its packets are injected in the bridge
        ip_arp_add(vm_nat_ip, self._vm_hwaddr, self._bridge_name)


        alloc_res = {'tap_name': tap_name,
                     'hwaddr': self._vm_hwaddr,
                     'nat_ip': vm_nat_ip}

        # Reverse NAT towards a VM port
        if hasattr(self, '_vm_rnat_port'):
            #TODO: how to better reserve and select a free port ?
            host_port = ( self._host_rnat_port_range[0] +
                          id_from_dev_name(self._tap_prefix, tap_name) )

            if host_port > self._host_rnat_port_range[1]:
                raise NetworkSetupError('Unable to find a free host port for '
                                        'reverse NAT')

            ipt_append_rule_idemp(
                "-d %s/32 -p tcp -m tcp --dport %s "
                "-j DNAT --to-destination %s:%d"
                % (resolve_host(socket.gethostname()),
                   host_port,
                   vm_nat_ip, self._vm_rnat_port),
                "PREROUTING", "nat")

            ipt_append_rule_idemp(
                "-d %s/32 -p tcp -m tcp --dport %s "
                "-j DNAT --to-destination %s:%d"
                % (resolve_host(socket.gethostname()),
                   host_port,
                   vm_nat_ip, self._vm_rnat_port),
                "OUTPUT", "nat")

            alloc_res['host_port'] =  host_port
            Config().batch.write_key(
                'cluster',
                'rnat/{0}/{1}'.format(vm.rank, self._vm_rnat_port),
                host_port
            )

        return alloc_res

    def _cleanup_vm_res(self, resources):
        tap_name = resources['tap_name']
        vm_nat_ip = resources['nat_ip']

        # Compute the port id on the bridge
        vm_port_id = ovs_get_port_id(tap_name, self._bridge_name)

        # Delete flows on the OVS bridge
        ovs_del_flows(self._bridge_name,
                      "table=0,in_port=%d,dl_type=0x0800,nw_src=%s" % (
                vm_port_id, self._vm_ip))
        ovs_del_flows(self._bridge_name,
                      "table=0,in_port=local,dl_type=0x0800,nw_dst=%s" % (
                vm_nat_ip))

        # Remove the tap from the bridge
        ovs_del_port(tap_name, self._bridge_name)

        # Delete the tap
        tun_delete_tap(tap_name)

        # Delete the permanent ARP entry
        ip_arp_del(vm_nat_ip, self._vm_hwaddr, self._bridge_name)

        # Delete the reverse NAT rule if needed
        if('host_port' in resources):
            host_port = int(resources['host_port'])
            ipt_delete_rule_idemp("-d %s/32 -p tcp -m tcp"
                                  " --dport %s -j DNAT "
                                  "--to-destination %s:%d"
                                  % (resolve_host(socket.gethostname()),
                                     host_port, vm_nat_ip, self._vm_rnat_port),
                                  "PREROUTING", "nat")

            ipt_delete_rule_idemp("-d %s/32 -p tcp -m tcp"
                                  " --dport %s -j DNAT "
                                  "--to-destination %s:%d"
                                  % (resolve_host(socket.gethostname()),
                                     host_port, vm_nat_ip, self._vm_rnat_port),
                                  "OUTPUT", "nat")


    def _vm_ip_from_id(self, nat_id):
        # First IP is for the bridge
        return get_ip_on_network(self._nat_network, nat_id + 2)

    @staticmethod
    def get_rnat_host_port(vm_rank, port):
        return Config().batch.read_key(
            'cluster',
            'rnat/{0}/{1}'.format(vm_rank, port),
            blocking=False)

def netns_decorate(func):
    def wrap_netns(*args, **kwargs):
        if 'netns' in kwargs:
            kwargs['exec_wrap'] = ['ip', 'netns', 'exec', kwargs['netns']]
        else:
            kwargs['exec_wrap'] = []
        return func(*args, **kwargs)
    return wrap_netns

def make_mask(num_bits):
    "return a mask of num_bits as a long integer"
    return ((2<<num_bits-1) - 1) << (32 - num_bits)

def dotted_quad_to_num(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('!L', socket.inet_aton(ip))[0]

def num_to_dotted_quad(addr):
    "convert long int to dotted quad string"
    return socket.inet_ntoa(struct.pack('!L', addr))

def network_mask(ip, bits):
    "Convert a network address to a long integer"
    return dotted_quad_to_num(ip) & make_mask(bits)

def address_in_network(ip, net):
    "Is an address in a network"
    return ip & net == net

def mac_prefix_len(prefix):
    return len(prefix.replace(':', ''))

def mac_suffix_len(prefix):
    return 12 - mac_prefix_len(prefix)

def mac_suffix_count(prefix):
    return 16 ** mac_suffix_len(prefix)

def mac_gen_hwaddr(prefix, num):
    max_id = mac_suffix_count(prefix)
    if num < 0:
        num = max_id + num
    if num < 0 or num >= max_id:
        raise ValueError('Invalid id for this MAC prefix')
    suffix = ("%x"%(num)).zfill(mac_suffix_len(prefix))
    suffix = ':'.join(
        suffix[i:i+2] for i in xrange(0, len(suffix), 2))
    return prefix + ':' + suffix

def ovs_add_bridge(brname, hwaddr=None):
    cmd = ["ovs-vsctl", "--may-exist", "add-br", brname]
    if not (hwaddr is None):
        cmd += [ "--", "set", "bridge", brname,
                 "other-config:hwaddr={0}".format(hwaddr)]
    subprocess.check_call(cmd)
    # Drop the ovs default flow, only allow packets that we want
    # TODO: Is it possible to create an ovs bridge without this
    # rule ?
    ovs_del_flows(brname, "--strict priority=0")
    subprocess.check_call(["ip", "link", "set",  brname, "up"])

def ovs_del_bridge(brname):
    subprocess.check_call(["ovs-vsctl", "--if-exist", "del-br", brname])

def ovs_enable_bridge_stp(brname):
    subprocess.check_call(["ovs-vsctl", "set", "bridge", brname,
                           "stp_enable=true"])

def bridge_exists(brname):
    """ returns whether brname is a bridge (linux or ovs) """
    return (os.path.exists('/sys/devices/virtual/net/{0}/bridge/'.format(brname)) or
           ovs_bridge_exists(brname))

def ovs_bridge_exists(brname):
    match = re.search(r'Bridge %s' % (brname),
                  subprocess.check_output(["ovs-vsctl", "show"]))
    if match:
        return True
    else:
        return False

def ovs_create_group(brname, group_id):
    subprocess.check_call(["ovs-ofctl", "add-group", "-OOpenFlow13",
                           brname,
                           'group_id={0},type=all'.format(group_id)])

def ovs_set_group_members(brname, group_id, members):
    bucket=''
    for m in members:
        bucket += ',bucket=output:{0}'.format(m)

    subprocess.check_call(["ovs-ofctl", "mod-group", "-OOpenFlow13",
                           brname,
                           'group_id={0},type=all'.format(group_id) + bucket])

def ovs_add_flow(brname, table, priority, match, action=None, cookie=None):
    if action:
        action = "actions="+action

    if cookie:
        cookie = "cookie="+cookie

    flow = 'table={0}, priority={1}, {2}, {3}'.format(
        table, priority, match, action)
    subprocess.check_call(["ovs-ofctl", "add-flow", "-OOpenFlow13", brname, flow])

def ovs_del_flows(brname, flow):
    subprocess.check_call(["ovs-ofctl", "del-flows", brname] + flow.split())

def ovs_get_port_id(tapname, brname):
    match = re.search(r'(\d+)\(%s\)' % (tapname),
                  subprocess.check_output(["ovs-ofctl", "show", brname]))
    if match:
        return int(match.group(1))
    else:
        raise KeyError('{0} not found on {1}'.format(tapname, brname))

def ovs_add_port(tapname, brname):
    subprocess.check_call(["ovs-vsctl", "add-port", brname, tapname])
    return ovs_get_port_id(tapname, brname)

def ovs_del_port(tapname, brname):
    subprocess.check_call(["ovs-vsctl", "del-port", brname, tapname])

def ovs_add_tunnel(brname, tun_name, tun_type, host, tun_id):
    subprocess.check_call(["ovs-vsctl", "add-port", brname,
                       tun_name, "--", "set", "interface", tun_name,
                       "type=%s" % (tun_type),
                       "options:remote_ip=%s" % (
            resolve_host(host)), "options:key=%s" % (tun_id)])
    return ovs_get_port_id(tun_name, brname)

def ipt_append_rule(rule, chain, table = None):
    if table:
        table_args = ["-t", table]
    else:
        table_args = []

    subprocess.check_call(["iptables"] + table_args + ["-A",
                                                       chain] +
                          rule.split())

def ipt_rule_exists(rule, chain, table = None):
    if table:
        table_args = ["-t", table]
    else:
        table_args = []

    try:
        subprocess.check_call(["iptables"] + table_args + ["-C",
                                                           chain] +
                              rule.split(), stderr=open(os.devnull))
        return True
    except subprocess.CalledProcessError:
        return False

def ipt_append_rule_idemp(rule, chain, table = None):
    if not ipt_rule_exists(rule, chain, table):
        ipt_append_rule(rule, chain, table)

def ipt_delete_rule(rule, chain, table = None):
    if table:
        table_args = ["-t", table]
    else:
        table_args = []

    subprocess.check_call(["iptables"] + table_args + ["-D",
                                                       chain] +
                          rule.split())

def ipt_delete_rule_idemp(rule, chain, table = None):
    if ipt_rule_exists(rule, chain, table):
        ipt_delete_rule(rule, chain, table)

def ipt_flush_table(table = None):
    if table:
        table_args = ["-t", table]
    else:
        table_args = []

    subprocess.check_call(["iptables"] + table_args + ["-F"])


def static_var(varname, value):
    """Used as a decorator to provide the equivalent of a static variable"""
    def decorate(func):
        setattr(func, varname, value)
        return func
    return decorate

@static_var("ipversion", 0)
def ip_has_tuntap():
    """Returns True if the iproute tool supports the tuntap command"""
    if ip_has_tuntap.ipversion==0:
        version_string = subprocess.check_output(['ip', '-V'])
        match = re.search(r'iproute2-ss(\d+)', version_string)
        ip_has_tuntap.ipversion = int(match.group(1))

    return ip_has_tuntap.ipversion >= 100519

def bridge_add_port(tapname, bridgename):
    subprocess.check_call(["ip", "link", "set", tapname, "master",
                           bridgename])

@netns_decorate
def veth_delete(name, **kwargs):
    subprocess.check_call(kwargs['exec_wrap'] + ["ip", "link", "del", name],
                          stdout=open(os.devnull))

def veth_create_pair(name1, name2):
    subprocess.check_call(["ip", "link", "add", name1, "type", "veth",
                           "peer", "name", name2], stdout=open(os.devnull))

def tun_create_tap(name, user):
    if ip_has_tuntap():
        subprocess.check_call(["ip", "tuntap", "add", name, "mode", "tap",
                               "user", user], stdout=open(os.devnull))
    else:
        subprocess.check_call(["tunctl", "-u", user, "-t", name],
                              stdout=open(os.devnull))

def tun_delete_tap(name):
    if ip_has_tuntap():
        subprocess.check_call(["ip", "tuntap", "del", name, "mode", "tap"])
    else:
        subprocess.check_call(["tunctl", "-d", name])

@netns_decorate
def dev_enable(name, **kwargs):
    subprocess.check_call(kwargs['exec_wrap'] +
                          ["ip", "link", "set", name, "up"])

def dev_set_hwaddr(name, hwaddr):
    subprocess.check_call(["ip", "link", "set", name, "address", hwaddr])

def dev_set_netns(name, netns):
    subprocess.check_call(["ip", "link", "set", name, "netns", netns])

def netns_create(name):
    subprocess.check_call(["ip", "netns", "add", name])

def netns_delete(name):
    subprocess.check_call(["ip", "netns", "delete", name])

@netns_decorate
def ip_set_mtu(dev, mtu, **kwargs):
    subprocess.check_call(kwargs['exec_wrap'] +
                          ["ip", "link", "set", dev, "mtu", "%d" % (mtu)])


@netns_decorate
def ip_route_add(networkbits, gw, **kwargs):
    subprocess.check_output(kwargs['exec_wrap'] +
                            ["ip", "route", "add", networkbits, "via", gw],
                            stderr=subprocess.STDOUT)

@netns_decorate
def ip_add(ip, bits, dev, **kwargs):
    subprocess.check_output(kwargs['exec_wrap'] +
                            ["ip", "addr", "add",
                             "%s/%d" % (ip, bits), "broadcast",
                             get_ip_on_network(
                num_to_dotted_quad(network_mask(ip, bits)),
                2**(32-bits) - 1), "dev", dev],
                            stderr=subprocess.STDOUT)

def ip_add_idemp(ip, bits, dev, **kwargs):
    try:
        ip_add(ip, bits, dev, **kwargs)
    except subprocess.CalledProcessError as err:
        if err.output != "RTNETLINK answers: File exists\n":
            raise

def ip_arp_add(ip, hwaddr, dev):
    subprocess.check_call(["ip", "neigh", "replace", ip, "lladdr", hwaddr,
                       "nud", "permanent", "dev", dev])

def ip_arp_del(ip, hwaddr, dev):
    subprocess.check_call(["ip", "neigh", "del", ip, "lladdr", hwaddr,
                       "nud", "permanent", "dev", dev])

def get_ip_on_network(netaddr, offset):
    return num_to_dotted_quad(dotted_quad_to_num(netaddr) + offset)


def resolve_host(host):
    data = socket.gethostbyname_ex(host)
    return data[2][0]


def dev_name_from_id(prefix, dev_id):
    return "%s%d" % (prefix, dev_id)

def id_from_dev_name(prefix, devname):
    assert(prefix)

    match = re.match(r"%s(\d+)" % (prefix), devname)
    if match:
        return int(match.group(1))
    else:
        return -1

def find_free_dev_id(prefix):
    used_ids = find_used_dev_ids(prefix)

    for pos, nat_id in enumerate(sorted(used_ids)):
        if (pos < nat_id):
            return pos

    return len(used_ids)

def find_used_dev_ids(prefix):
    return [  id_from_dev_name(prefix, devname)
              for devname in os.listdir("/sys/devices/virtual/net")
              if id_from_dev_name(prefix, devname) != -1 ]

def find_free_dev_name(prefix):
    dev_id = find_free_dev_id(prefix)
    return dev_name_from_id(prefix, dev_id)

