#  Copyright (C) 2014-2017 CEA/DAM/DIF
#
#  This file is part of PCOCC, a tool to easily create and deploy
#  virtual machines using the resource manager of a compute cluster.
#
#  PCOCC is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  PCOCC is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with PCOCC. If not, see <http://www.gnu.org/licenses/>

import socket
import subprocess
import logging
import tempfile
import os
import shlex
import yaml

from .Networks import VNetwork
from .Error import PcoccError, InvalidConfigurationError
from .Config import Config
from .Misc import IDAllocator
from .NetUtils import OVSBridge, TAP, VEth, OVSCookie, IPTableRule, NetNameSpace
from .NetUtils import NetPort, PidDaemon, NetworkSetupError
from .NetUtils import get_ip_on_network, mac_gen_hwaddr, resolve_host
from .NetUtils import make_mask, dotted_quad_to_num, num_to_dotted_quad

class VEthNetwork(VNetwork):
    _schema = yaml.load(r"""
properties:
  type:
      enum:
        - eth
        - ethernet

  settings:
    type: object
    properties:
      ext-network:
       type: string
       default-value: '10.201.0.0/16'
       pattern: '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
      int-network:
       type: string
       default-value: '10.200.0.0/16'
       pattern: '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
      mac-prefix:
       type: string
       default-value: '52:54:00'
       pattern: '^([0-9a-fA-F]{2}:){0,3}[0-9a-fA-F]{2}$'
      dev-prefix:
       type: string
       pattern: '^([a-zA-Z][a-zA-Z_0-9]{0,7})$'
      host-if-suffix:
       type: string
      mtu:
       type: integer
       default-value: 1500
      domain-name:
       type: string
      dns-search:
       type: string
      dns-server:
       type: string
       pattern: '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
      ntp-server:
       type: string
      reverse-nat:
       type: object
      network-layer:
       enum:
          - L3
          - L2
       default-value: 'L3'
      gateway:
       enum:
          - local-nat
       default-value: 'local-nat'
      allow-outbound:
       type: string
       default-value: 'all'
      manage-ip-forward:
       type: boolean
       default-value: true
    additionalProperties: false
    required:
     - dev-prefix

additionalProperties: false
""", Loader=yaml.CLoader)

    def __init__(self, name, settings):
        super(VEthNetwork, self).__init__(name)

        self._type = 'ethernet'

        self._parse_settings(settings)

        self._min_key = 1024
        self._max_key = 2 ** 16 - 1

        self._key_ida = IDAllocator(self._get_type_key_path('key_alloc_state'),
                                    self._max_key - self._min_key + 1)

        self._natip_ida = IDAllocator(self._get_type_key_path('natip_alloc_state'),
                                      2 ** (32 - self._ext_network_bits) - 2)

        self._ext_br_name = self._dev_prefix + '_xbr'
        self._int_br_prefix = self._dev_prefix + '_ibr'
        self._tap_prefix = self._dev_prefix + '_tap'
        self._veth_prefix = self._dev_prefix + '_veth'
        self._netns_prefix = self._dev_prefix + '_ns'

        self._ext_br_hwaddr = mac_gen_hwaddr(self._mac_prefix, -1)
        self._int_br_hwaddr = mac_gen_hwaddr(self._mac_prefix, -2)
        self._int_host_hwaddr = mac_gen_hwaddr(self._mac_prefix, -3)

        self._ext_gw_ip = get_ip_on_network(self._ext_network,
                                            2 ** (32 - self._ext_network_bits)
                                            - 2)

        self._int_gw_ip = get_ip_on_network(self._int_network,
                                            2 ** (32 - self._int_network_bits)
                                            - 2)

        self._int_host_ip = get_ip_on_network(self._int_network,
                                            2 ** (32 - self._int_network_bits)
                                            - 3)

        self._classifier_table = 0
        self._l3_forward_table = 20
        self._l2_forward_table = 30
        self._arp_table = 50

    def init_node(self):
        if self._network_layer == 'L3':
            self._init_routing()

    def cleanup_node(self):
        if self._network_layer == 'L3':
            self._cleanup_routing()

        self._cleanup_stray_bridges()
        self._cleanup_stray_taps()
        self._cleanup_stray_veths()

    def alloc_node_resources(self, cluster):
        batch = Config().batch
        tracker = Config().tracker

        net_res = {}
        hosts = set()
        net_vms_attrs = {}
        num_vms = 0
        for vm in self._net_vms(cluster):
            hosts.add(vm.get_host_rank())
            net_vms_attrs[vm.rank] = {
                'net_rank': num_vms,
                'mac_addr': mac_gen_hwaddr(
                    self._mac_prefix,
                    num_vms),
                'int_ip': get_ip_on_network(
                    self._int_network,
                    num_vms + 1)
                }

            num_vms += 1

        # Add a record for a host interface in the VM network
        net_vms_attrs[-1] =  {
            'net_rank': num_vms,
            'mac_addr': self._int_host_hwaddr,
            'int_ip': self._int_host_ip,
            }

        #No VM on node nothing to do
        if not batch.node_rank in hosts:
            return

        # Compute master node
        master = min(hosts)
        if batch.node_rank == master:
            logging.info("Node is master for PV network %s",
                         self.name)

        key_id = self._alloc_tun_key(master)

        # Create internal bridge
        int_br = OVSBridge.prefix_find_free(self._int_br_prefix)
        int_br.defer()
        tracker.create_with_ref(batch.batchid, int_br)
        int_br.set_mtu(self._mtu)
        int_br.enable()

        vm_ext_ips = []
        if self._network_layer == 'L3':
            # Allocate IPs on the external network
            vm_ext_ips = self._alloc_ext_ips(net_vms_attrs, master)

            # Reference to external bridge which should have already been created
            ext_br = OVSBridge(self._ext_br_name)
            ext_br.defer()
            # Cookie to track entries on the shared external bridge
            ext_cookie = tracker.create_with_ref(batch.batchid,
                                                 OVSCookie(batch.batchid,
                                                           ext_br.name))


            # Create veth between ext and int bridges
            int_veth = VEth.prefix_find_free(self._veth_prefix)
            _, ext_veth = tracker.create_with_ref(batch.batchid, int_veth)

            int_veth_port = int_br.add_port(int_veth.name)
            ext_veth_port = ext_br.add_port(ext_veth.name)

            int_veth.enable()
            ext_veth.enable()

            int_veth.set_mtu(self._mtu)
            ext_veth.set_mtu(self._mtu)

        # On the master node setup network namespace
        # with an interface on the guest network
        if batch.node_rank == master:
            netns_name = '{0}_{1}_{2}'.format(self._netns_prefix,
                                              self.name,
                                              batch.batchid)
            tracker.create_with_ref(batch.batchid, NetNameSpace(netns_name))

            br_veth = VEth.prefix_find_free(self._veth_prefix)
            _, host_veth = tracker.create_with_ref(batch.batchid, br_veth)

            br_veth.enable()
            br_veth_port = int_br.add_port(br_veth.name)

            host_veth.set_hwaddr(self._int_host_hwaddr)
            host_veth.set_netns(netns_name)
            host_veth.enable()

            if self._network_layer == 'L3':
                host_veth.add_ip(self._int_host_ip, self._int_network_bits)
                host_veth.add_route('default', self._int_gw_ip)

        # Classify packets on the internal bridge
        # ARP requests go to ARP responder
        int_br.add_flow(table=self._classifier_table,
                        match='dl_type=0x0806,arp_op=0x1',
                        action='goto_table={0}'.format(self._arp_table))

        # Packets for the virtual gateway go to L3 forwarding
        int_br.add_flow(table=self._classifier_table,
                     match='dl_dst={0}'.format(self._int_br_hwaddr),
                     action='goto_table={0}'.format(self._l3_forward_table))

        # Other packets go to L2 forwarding
        int_br.add_flow(table=self._classifier_table,
                        priority=0,
                        match=None,
                        action='goto_table={0}'.format(self._l2_forward_table))

        if self._network_layer == 'L3':
            #ARP responders for VMs and host IPs on both bridges
            for vm_attrs in net_vms_attrs.itervalues():
                self._setup_arp_responders(int_br,
                                           vm_attrs['mac_addr'],
                                           vm_attrs['int_ip'],
                                           ext_br,
                                           vm_attrs['ext_ip'],
                                           ext_cookie)


            # ARP responder for virtual gateway on internal bridge
            self._add_arp_responder_entry(int_br,
                                          self._int_br_hwaddr,
                                          self._int_gw_ip)

        # Continue processing packet in L2 forwarding table
        int_br.add_flow(table=self._arp_table,
                        priority=0,
                        match=None,
                        action='resubmit(,{0})'.format(self._l2_forward_table))


        # L2 forwarding
        # TODO: Learn unknown unicast
        local_ports = []
        remote_ports = []
        host_tunnels = {}

        # local ports
        int_br.create_group(1)

        for vm in self._net_vms(cluster):
            if vm.is_on_node():
                # Create a TAP interface for each local VM
                tap = TAP.prefix_find_free(self._tap_prefix)
                tracker.create_with_ref(batch.batchid, tap)
                tap.enable()
                tap.set_mtu(self._mtu)
                port_id = int_br.add_port(tap.name)

                local_ports.append(port_id)
                int_br.create_group(vm.rank + 100)

                # Deliver unicast packets for each local VM
                int_br.add_flow(table=self._l2_forward_table,
                                match='dl_dst={0}'.format(net_vms_attrs[vm.rank]['mac_addr']),
                                action='output:{0}'.format(port_id))

                # Flood Broadcasts from each local VM internally
                int_br.add_flow(table=self._l2_forward_table,
                                match='in_port={0},'
                                'dl_dst=01:00:00:00:00:00/01:00:00:00:00:00'.format(port_id),
                                action='group={0}'.format(vm.rank + 100))

                # Flood unknown unicast on local and remote interfaces
                int_br.add_flow(table=self._l2_forward_table, priority=100,
                                match='in_port={0}'.format(port_id),
                                action='group={0}'.format(vm.rank + 100))

                vm_label = self._vm_res_label(vm)
                net_res[vm_label] = {'tap_name': tap.name,
                                     'hwaddr': net_vms_attrs[vm.rank]['mac_addr'],
                                     'port_id': port_id}

                if self._network_layer == 'L3':
                    net_res[vm_label]['domain-name'] = self._domain_name


            else:
                # For remote VMs, create a tunnel to the remote host if needed
                host = vm.get_host()
                if host not in host_tunnels:
                    tunnel_port_id = int_br.add_tunnel(
                        '{0}_{1}'.format(int_br.name, len(host_tunnels)),
                        "vxlan",
                        "{0}{1}".format(host, self._host_if_suffix),
                        key_id)
                    host_tunnels[host] = tunnel_port_id

                    remote_ports.append(tunnel_port_id)
                    # Deliver remote broadcasts from this tunnel to local VMs
                    int_br.add_flow(table=self._l2_forward_table,
                                    match='in_port={0},'
                                    'dl_dst=01:00:00:00:00:00/01:00:00:00:00:00'.format(
                                        tunnel_port_id),
                                    action='group=1')

                    # Flood unknown unicast on local interfaces
                    int_br.add_flow(table=self._l2_forward_table, priority=100,
                                    match='in_port={0}'.format(tunnel_port_id),
                                    action='group=1')

                    # Deliver packets for the host interface on the virtual net
                    if vm.get_host_rank() == master:
                        int_br.add_flow(table=self._l2_forward_table,
                                        match='dl_dst={0}'.format(self._int_host_hwaddr),
                                        action='output:{0}'.format(tunnel_port_id))

                #Deliver unicast packets for remote VMs
                int_br.add_flow(table=self._l2_forward_table,
                                match='dl_dst={0}'.format(net_vms_attrs[vm.rank]['mac_addr']),
                                action='output:{0}'.format(host_tunnels[host]))


        # Hande the host interface on the virtual network
        if batch.node_rank == master:
            local_ports.append(br_veth_port)
            int_br.create_group(2)

            # Deliver packets for the host interface on virtual network
            int_br.add_flow(table=self._l2_forward_table,
                            match='dl_dst={0}'.format(self._int_host_hwaddr),
                            action='output:{0}'.format(br_veth_port))

            # Flood broadcasts from host interface on virtual network
            int_br.add_flow(table=self._l2_forward_table,
                            match='in_port={0},'
                            'dl_dst=01:00:00:00:00:00/01:00:00:00:00:00'.format(br_veth_port),
                            action='group=2')

            # Flood unknown unicast on local and remote interfaces
            int_br.add_flow(table=self._l2_forward_table, priority=100,
                            match='in_port={0}'.format(br_veth_port),
                            action='group=2')


        # Define flood port groups for each VM
        int_br.set_group_members(1, local_ports)
        i=0
        for vm in self._net_vms(cluster):
            if vm.is_on_node():
                int_br.set_group_members(vm.rank + 100,
                                         local_ports[:i] + local_ports[i + 1:] +
                                         remote_ports)
                i+=1

        # Flood port group for the host interface
        if batch.node_rank == master:
            int_br.set_group_members(2, local_ports[:-1] + remote_ports)

        if self._network_layer == 'L3':
            # Deliver packets for the external bridge
            int_br.add_flow(table=self._l2_forward_table,
                            match='dl_dst={0}'.format(self._ext_br_hwaddr),
                            action='output:{0}'.format(int_veth_port))

        if self._network_layer == 'L3' and batch.node_rank == master:
            self._setup_dnsmasq(cluster, net_vms_attrs, netns_name)

        # L3 forwarding
        if self._network_layer == 'L3':
            self._add_gateway_l3_rules(int_br, net_vms_attrs, ext_br,
                                       ext_veth_port, ext_cookie)

        # Reverse NAT towards a VM port
        if self._network_layer == 'L3' and hasattr(self, '_vm_rnat_port'):
            for vm in self._net_vms(cluster):
                if vm.is_on_node():
                    try:
                        host_port = tracker.create_with_ref(
                            batch.batchid,
                            NetPort.range_find_free(
                                tracker,
                                self._host_rnat_port_range[0],
                                self._host_rnat_port_range[1]))

                    except ValueError:
                        raise NetworkSetupError('Unable to find a free host port for '
                                                'reverse NAT')

                    tracker.create_with_ref(batch.batchid,
                                             IPTableRule(
                            "-d %s/32 -p tcp -m tcp --dport %s "
                            "-j DNAT --to-destination %s:%d"
                            % (resolve_host(socket.gethostname()),
                               host_port.number,
                               net_vms_attrs[vm.rank]['ext_ip'],
                               self._vm_rnat_port),
                            "PREROUTING", "nat"))


                    tracker.create_with_ref(batch.batchid,
                                             IPTableRule(
                        "-d %s/32 -p tcp -m tcp --dport %s "
                        "-j DNAT --to-destination %s:%d"
                        % (resolve_host(socket.gethostname()),
                           host_port.number,
                           net_vms_attrs[vm.rank]['ext_ip'],
                           self._vm_rnat_port),
                        "OUTPUT", "nat"))

                    vm_label = self._vm_res_label(vm)
                    net_res[vm_label]['host_port'] =  host_port.number

                    Config().batch.write_key(
                        'cluster',
                        'rnat/{0}/{1}'.format(vm.rank, self._vm_rnat_port),
                        host_port.number
                    )

        int_br.push_flows()
        if self._network_layer == 'L3':
            ext_br.push_flows()

        net_res['global'] = {'int_br_name': int_br.name,
                             'key_id': key_id,
                             'ext_ips': vm_ext_ips,
                             'master': master}

        self.dump_resources(net_res)

    def free_node_resources(self, cluster):
        master = -1
        for _ in self._local_net_vms(cluster):
            net_res = self.load_resources()
            master = net_res['global']['master']
            break

        if master == Config().batch.node_rank:
            # Free tunnel key
            try:
                self._key_ida.free_one(int(net_res['global']['key_id']) - self._min_key)
            except PcoccError as e:
                raise NetworkSetupError('{0}: {1}'.format(
                    self.name,
                    str(e)
                ))

            # Free IDs for external IPs
            try:
                self._natip_ida.free(net_res['global']['ext_ips'])
            except PcoccError as e:
                raise NetworkSetupError('{0}: {1}'.format(
                    self.name,
                    str(e)
                ))

    def load_node_resources(self, cluster):
        net_res = None
        for vm in self._local_net_vms(cluster):
            if not net_res:
                net_res = self.load_resources()

            vm_label = self._vm_res_label(vm)
            vm.add_eth_if(self.name,
                          net_res[vm_label]['tap_name'],
                          net_res[vm_label]['hwaddr'])

            if 'domain-name' in net_res[vm_label]:
                vm.domain_name = net_res[vm_label]['domain-name']

    def _alloc_tun_key(self, master):
        # Allocate tunnel key
        try:
            key_id = self._min_key + self._key_ida.coll_alloc_one(
                master,
                '{0}_tun_key'.format(self.name))
        except PcoccError as e:
            raise NetworkSetupError('{0}: {1}'.format(
                self.name,
                str(e)
            ))

        return key_id

    def _alloc_ext_ips(self, net_vms_attrs, master):
        try:
            vm_ext_ips = self._natip_ida.coll_alloc(
                len(net_vms_attrs),
                master,
                '{0}_extip_key'.format(self.name))
        except PcoccError as e:
            raise NetworkSetupError('{0}: {1}'.format(
                self.name,
                str(e)
            ))

        # Define VM external IPs from the allocated IDs
        for vm_attr in net_vms_attrs.itervalues():
            vm_attr['ext_ip'] = get_ip_on_network(
                self._ext_network,
                vm_ext_ips[vm_attr['net_rank']] + 1)

        return vm_ext_ips

    def _add_gateway_l3_rules(self, int_br, net_vms_attrs, ext_br,
                              ext_veth_port, ext_cookie):
        # Rewrite external gateway -> VM  to internal gateway -> VM
        int_br.add_flow(table=self._l3_forward_table,
                        priority=2000,
                        match='dl_type=0x0800, '
                        'nw_dst={0}/{1},nw_src={2}'.format(
                self._ext_network,
                self._ext_network_bits,
                self._ext_gw_ip),
                        action='mod_nw_src={0}, goto_table={1}'.format(
                self._int_gw_ip, self._l3_forward_table + 2))


        # Rewrite VM -> internal gateway to VM -> external gateway
        int_br.add_flow(table=self._l3_forward_table,
                        priority=2000,
                        match='dl_type=0x0800, '
                        'nw_src={0}/{1},nw_dst={2}'.format(
                self._int_network,
                self._int_network_bits,
                self._int_gw_ip),
                        action='mod_nw_dst={0}, goto_table={1}'.format(
                self._ext_gw_ip, self._l3_forward_table + 3))

        # For internal -> internal traffic go straight to L2
        int_br.add_flow(table=self._l3_forward_table,
                        match='dl_type=0x0800, '
                        'nw_dst={0}/{1}, '
                        'nw_src={0}/{1}'.format(self._int_network,
                                                self._int_network_bits),
                        action='goto_table={0}'.format(self._l2_forward_table))

        # Rules for packets entering internal net targeting an external ip
        int_br.add_flow(table=self._l3_forward_table,
                        match='dl_type=0x0800, '
                        'nw_dst={0}/{1}, '.format(self._ext_network,
                                                  self._ext_network_bits),
                        action='goto_table={0}'.format(self._l3_forward_table + 2))

        # Rules for packets leaving internal net with an internal source ip
        int_br.add_flow(table=self._l3_forward_table,
                        match='dl_type=0x0800, '
                        'nw_src={0}/{1}' .format(self._int_network,
                                                 self._int_network_bits),
                        action='goto_table={0}'.format(self._l3_forward_table + 3))

        # Drop what we cannot route
        int_br.add_flow(table=self._l3_forward_table,
                        priority=0,
                        match=None,
                        action='drop')


        # Add rewrite rules for each VM
        for vm_attr in net_vms_attrs.itervalues():
            self._add_rewrite_rules(int_br,
                                    vm_attr['int_ip'],
                                    vm_attr['ext_ip'])

        # Special case for rewrites: VM -> external gateway must match outbound rule
        # even though destination is an external IP in the VM range
        int_br.add_flow(table=self._l3_forward_table + 2,
                        match='dl_type=0x0800,'
                        'nw_dst={0}'.format(self._ext_gw_ip),
                        action='goto_table={0}'.format(self._l3_forward_table + 3))


        # Route from internal gateway: set internal gateway MAC as source
        int_br.add_flow(table=self._l3_forward_table + 5,
                        match='dl_type=0x0800,',
                        action='mod_dl_src:{0},goto_table={1}'.format(
                self._int_br_hwaddr,
                self._l3_forward_table + 7))

        # Forward from gateways: set destination MAC addr
        for vm_attr in net_vms_attrs.itervalues():
            self._add_forwarding_entries(int_br,
                                         vm_attr['int_ip'],
                                         vm_attr['mac_addr'],
                                         ext_br,
                                         vm_attr['ext_ip'],
                                         ext_veth_port,
                                         ext_cookie)

        # Other IPs are considered external and forwarded to the external bridge
        int_br.add_flow(table=self._l3_forward_table + 7,
                        priority=0,
                        match='dl_type=0x0800,',
                        action='mod_dl_dst:{0},goto_table={1}'.format(
                            self._ext_br_hwaddr,
                            self._l2_forward_table
                        ))

    def _setup_dnsmasq(self, cluster, net_vms_attrs, netns_name):
        # Start a dnsmasq server to answer DHCP requests
        dnsmasq_opts = ""
        if self._ntp_server:
            dnsmasq_opts+="--dhcp-option=option:ntp-server,{0} ".format(
                self._ntp_server)

        if self._dns_server:
            dnsmasq_opts+="--server={0} ".format(self._dns_server)

        if not self._allow_outbound or self._dns_server:
            dnsmasq_opts+="--no-resolv "

        search_opt = self._domain_name
        if self._dns_search:
            search_opt+= ',' + self._dns_search

        fd, dhcpconf = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as f:
            for vm in self._net_vms(cluster):
                f.write('{0},{1},{2},infinite\n'.format(
                        net_vms_attrs[vm.rank]['mac_addr'],
                        net_vms_attrs[vm.rank]['int_ip'],
                        'vm{0}.{1}'.format(vm.rank, self._domain_name)))

        fd, dnsconf = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as f:
            for vm in self._net_vms(cluster):
                f.write('{0} {1}\n'.format(
                        net_vms_attrs[vm.rank]['int_ip'],
                        'vm{0}.{1}'.format(vm.rank, self._domain_name)))

        os.chmod(dhcpconf, 0o644)
        os.chmod(dnsconf, 0o644)
        pid_file = '/var/run/pcocc_dnsmasq_{0}.pid'.format(netns_name)
        Config().tracker.create_with_ref(Config().batch.batchid,
                                         PidDaemon(pid_file))
        subprocess.check_call(
            shlex.split("ip netns exec {netns} /usr/sbin/dnsmasq "
                        "--dhcp-authoritative "
                        "--pid-file={pid_file} "
                        "--conf-file= "
                        "--leasefile-ro "
                        "--dhcp-lease-max=65536 "
                        "--dhcp-hostsfile {hostsfile} "
                        "--domain={domainname} "
                        "--dhcp-option=15,{domainname} "
                        "--dhcp-option=119,{search} "
                        "--dhcp-option=26,{mtu} "
                        "--dhcp-option=option:dns-server,{dnssrv} "
                        "{addopts} "
                        "--dhcp-option=option:netmask,{netmask} "
                        "--dhcp-option=option:router,{router} "
                        "-F {dhcpnetwork},static "
                        "-h -E -H {addnhosts}".format(
                    netns = netns_name,
                    pid_file = pid_file,
                    hostsfile = dhcpconf,
                    domainname = self._domain_name.split(',')[0]+'.',
                    search = search_opt,
                    mtu = self._mtu - 50,
                    dnssrv = self._int_host_ip,
                    addopts = dnsmasq_opts,
                    netmask = num_to_dotted_quad(make_mask(self._int_network_bits)),
                    router = self._int_gw_ip,
                    dhcpnetwork = self._int_network,
                    addnhosts = dnsconf)))

    def _add_forwarding_entries(self, int_br, int_ip, hwaddr,
                                ext_br, ext_ip, ext_port, ext_cookie):
        # From internal gateway to internal host/VM
        int_br.add_flow(table=self._l3_forward_table + 7,
                        match='dl_type=0x0800,'
                        'nw_dst={0}'.format(int_ip),
                        action='mod_dl_dst:{0},goto_table={1}'.format(
                hwaddr,
                self._l2_forward_table
                ))

        # From external gw to internal bridge
        ext_br.add_flow(table=self._l3_forward_table,
                        cookie=(ext_cookie.value if ext_cookie else None),
                        match='dl_type=0x0800,'
                        'nw_dst={0}'.format(ext_ip),
                        action='output:{0}'.format(ext_port))


    def _add_rewrite_rules(self, int_br, int_ip, ext_ip):
        # Rewrite packets: use internal IP instead of external IP
        int_br.add_flow(table=self._l3_forward_table + 2,
                        match='dl_type=0x0800,'
                        'nw_dst={0}'.format(ext_ip),
                        action='mod_nw_dst:{0},goto_table={1}'.format(
                int_ip,
                self._l3_forward_table + 5))

        # Rewrite packets: use external IP instead of internal IP
        int_br.add_flow(table=self._l3_forward_table + 3,
                        match='dl_type=0x0800,'
                        'nw_src={0}'.format(int_ip),
                        action='mod_nw_src:{0},goto_table={1}'.format(
                ext_ip,
                self._l3_forward_table + 5))

    def _add_arp_responder_entry(self, br, mac_addr, ip, cookie=None):
        hex_mac = '0x' + mac_addr.replace(':', '')
        hex_ip = '0x{0:x}'.format(dotted_quad_to_num(ip))

        br.add_flow(table=self._arp_table,
                    match='dl_type=0x0806, nw_dst={0}'.format(ip),
                    cookie=(cookie.value if cookie else None),
                    action='move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[], '
                    'mod_dl_src:{0}, '
                    'load:0x2->NXM_OF_ARP_OP[], '
                    'move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[], '
                    'move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[], '
                    'load:{1}->NXM_NX_ARP_SHA[], '
                    'load:{2}->NXM_OF_ARP_SPA[], '
                    'in_port'.format(mac_addr,
                                      hex_mac,
                                      hex_ip))

    def _setup_arp_responders(self, int_br, hwaddr, int_ip, ext_br, ext_ip,
                              ext_cookie):
        self._add_arp_responder_entry(int_br,
                                       hwaddr,
                                       int_ip)

        self._add_arp_responder_entry(ext_br,
                                       self._int_br_hwaddr,
                                       ext_ip,
                                       ext_cookie)


    def _iptables_routing_rules(self):
        rules = []

        # External -> Internal
        # Always allow established traffic
        rules.append(IPTableRule('-d %s/%d -o %s '
                    '-m state --state RELATED,ESTABLISHED '
                    '-j ACCEPT'
                    % (self._ext_network,
                       self._ext_network_bits,
                       self._ext_br_name),
                    'FORWARD'))

        rules.append(IPTableRule('-d %s/%d -o %s '
                                 '-m state --state RELATED,ESTABLISHED '
                                 '-j ACCEPT'
                                 % (self._ext_network,
                                    self._ext_network_bits,
                                    self._ext_br_name),
                                 'OUTPUT'))

        # Allow new connections only on the reverse nat port if any
        if hasattr(self, '_vm_rnat_port'):
            rules.append(IPTableRule('-d %s/%d -o %s -p tcp -m tcp --dport %d '
                                     '-m state --state NEW -j ACCEPT'
                                     % (self._ext_network,
                                        self._ext_network_bits,
                                        self._ext_br_name,
                                        self._vm_rnat_port),
                                     'FORWARD'))
            rules.append(IPTableRule('-d %s/%d -o %s -p tcp -m tcp --dport %d '
                                     '-m state --state NEW -j ACCEPT'
                                     % (self._ext_network,
                                        self._ext_network_bits,
                                        self._ext_br_name,
                                        self._vm_rnat_port),
                                     'OUTPUT'))

        # Allow local ping
        rules.append(IPTableRule('-d %s/%d -o %s '
                                 '-p icmp --icmp-type echo-request -j ACCEPT'
                                 % (self._ext_network,
                                    self._ext_network_bits,
                                    self._ext_br_name),
                                 'OUTPUT'))

        # Everything else is dropped locally
        # (and not forwarded by default drop policy)
        rules.append(IPTableRule('-d %s/%d -o %s -j DROP'
                                 % (self._ext_network,
                                    self._ext_network_bits,
                                    self._ext_br_name),
                                 'OUTPUT'))

        if self._allow_outbound:
            # Route all outbound packets
            rules.append(IPTableRule('-s %s/%d -i %s -j ACCEPT'
                                     % (self._ext_network,
                                        self._ext_network_bits,
                                        self._ext_br_name),
                                     'FORWARD'))
        else:
            # Only accept and route established connections
            rules.append(IPTableRule('-s %s/%d -i %s '
                                     '-m state --state RELATED,ESTABLISHED -j ACCEPT'
                                     % (self._ext_network,
                                        self._ext_network_bits,
                                        self._ext_br_name),
                                     'FORWARD'))

            rules.append(IPTableRule('-s %s/%d -i %s '
                                     '-m state --state RELATED,ESTABLISHED -j ACCEPT'
                                     % (self._ext_network,
                                        self._ext_network_bits,
                                        self._ext_br_name),
                                     'INPUT'))

            # Allow local ping
            rules.append(IPTableRule('-s %s/%d -i %s '
                                     '-p icmp --icmp-type echo-request -j ACCEPT'
                                     % (self._ext_network,
                                        self._ext_network_bits,
                                        self._ext_br_name),
                                     'INPUT'))

            # Everything else is dropped locally
            # (and not forwarded by default drop policy)
            rules.append(IPTableRule('-s %s/%d -i %s -j DROP'
                                     % (self._ext_network,
                                        self._ext_network_bits,
                                        self._ext_br_name),
                                     'INPUT'))


        # Enable NAT
        rules.append(IPTableRule('-s %s/%d ! -d %s/%d -p tcp -j MASQUERADE '
                                 '--to-ports 1024-65535'
                                 % (self._ext_network,
                                    self._ext_network_bits,
                                    self._ext_network,
                                    self._ext_network_bits),
                                 'POSTROUTING', 'nat'))

        rules.append(IPTableRule('-s %s/%d ! -d %s/%d -p udp -j MASQUERADE '
                                 '--to-ports 1024-65535' % (self._ext_network,
                                                            self._ext_network_bits,
                                                            self._ext_network,
                                                            self._ext_network_bits),
                                 'POSTROUTING', 'nat'))

        rules.append(IPTableRule('-s %s/%d ! -d %s/%d -p icmp '
                                 '--icmp-type echo-request -j MASQUERADE'
                                 % (self._ext_network,
                                    self._ext_network_bits,
                                    self._ext_network,
                                    self._ext_network_bits),
                                 'POSTROUTING', 'nat'))

        return rules

    def _init_routing(self):
        # Create external bridge
        ext_br = OVSBridge(self._ext_br_name)
        ext_br.create()
        ext_br.set_hwaddr(self._ext_br_hwaddr)
        ext_br.enable()

        # Configure the bridge with the GW ip on the VM network
        ext_br.add_ip_idemp(self._ext_gw_ip,
                            self._ext_network_bits)

        # ARP requests go to ARP responder
        ext_br.add_flow(table=self._classifier_table,
                        match='dl_type=0x0806',
                        action='goto_table={0}'.format(self._arp_table))

        # Packets for the external gateway go to L3 forwarding
        ext_br.add_flow(table=self._classifier_table,
                        match='dl_src={0}'.format(self._ext_br_hwaddr),
                        action='goto_table={0}'.format(self._l3_forward_table))

        # Default: L2 forwarding
        ext_br.add_flow(table=self._classifier_table,
                        priority=0,
                        match=None,
                        action='goto_table={0}'.format(self._l2_forward_table))

        # L2 forwarding: packets for the gateway are output locally
        ext_br.add_flow(table=self._l2_forward_table,
                        match='dl_dst={0}'.format(self._ext_br_hwaddr),
                        action='output:LOCAL')

        # ARP responder
        self._add_arp_responder_entry(ext_br,
                                      self._ext_br_hwaddr,
                                      self._ext_gw_ip)

        # Enable Routing for the external bridge only
        if self._manage_ip_forward:
            subprocess.check_call('echo 1 > /proc/sys/net/ipv4/ip_forward',
                                  shell=True)
            subprocess.check_call('iptables -P FORWARD DROP',
                                  shell=True)

        for rule in self._iptables_routing_rules():
            rule.create()

    def _cleanup_routing(self):
        # Remove external bridge
        OVSBridge(self._ext_br_name).delete()


        # Disable routing
        if self._manage_ip_forward:
            subprocess.check_call("echo 0 > /proc/sys/net/ipv4/ip_forward",
                                  shell=True)
            subprocess.check_call("iptables -P FORWARD ACCEPT",
                                  shell=True)

        for rule in self._iptables_routing_rules():
            rule.delete()

    def _parse_settings(self, settings):
        self._dev_prefix = settings.get('dev-prefix', self.name)
        self._mac_prefix = settings.get('mac-prefix', '52:54:00')
        self._host_if_suffix = settings.get('host-if-suffix', '')
        self._mtu = int(settings.get("mtu", 1500))

        ext_network = settings.get('ext-network', '10.201.0.0/16')
        self._ext_network = ext_network.split("/")[0]
        self._ext_network_bits = int(ext_network.split("/")[1])

        int_network = settings.get('int-network', '10.200.0.0/16')
        self._int_network = int_network.split("/")[0]
        self._int_network_bits = int(int_network.split("/")[1])

        self._network_layer = settings.get("network-layer", "L3")

        self._manage_ip_forward = settings.get("manage-ip-forward", True)

        # defaults to pcocc.dnsdomainname
        self._domain_name = settings.get('domain-name', 'pcocc.{0}'.format(
            '.'.join(socket.getfqdn().split('.')[1:]) ))

        if self._domain_name.endswith('.'):
            self._domain_name = self._domain_name[:-1]

        self._dns_search = settings.get("dns-search", '')
        self._dns_server = settings.get("dns-server", '')
        self._ntp_server = settings.get("ntp-server", '')

        # TODO: Add ip/port range filters
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


        if self._ext_network_bits < self._int_network_bits:
            raise InvalidConfigurationError('On network {0}: '
                    'External network IP range must be larger than Internal network IP range')

    def _cleanup_stray_bridges(self):
        # Look for remaining bridges to cleanup
        count = OVSBridge.prefix_cleanup(self._int_br_prefix)
        if count:
            logging.warning('Deleted %s leftover bridge(s) for %s network',
                            count,
                            self.name)

    def _cleanup_stray_taps(self):
        # Look for remaining taps to cleanup
        count = TAP.prefix_cleanup(self._tap_prefix)
        if count:
            logging.warning('Deleted %s leftover TAP(s) for %s network',
                            count,
                            self.name)

    def _cleanup_stray_veths(self):
        # Look for remaining veths to cleanup
        count = VEth.prefix_cleanup(self._veth_prefix)
        if count:
            logging.warning('Deleted %s leftover veth(s) for %s network',
                            count,
                            self.name)

    @staticmethod
    def get_rnat_host_port(vm_rank, port):
        return Config().batch.read_key(
            'cluster',
            'rnat/{0}/{1}'.format(vm_rank, port),
            blocking=False)
