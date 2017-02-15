#  Copyright (C) 2014-2015 CEA/DAM/DIF
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

import yaml
import os
import re
import struct
import socket
import string
import subprocess
import shlex
import signal
import time
import pwd
import etcd
import random
import logging
import tempfile
import shutil
import stat
import jsonschema
import psutil

from Backports import subprocess_check_output
from Error import PcoccError, InvalidConfigurationError
from Config import Config



network_config_schema = """
type: object
patternProperties:
  "^([a-zA-Z_0-9--])+$":
    oneOf:
      - $ref: '#/definitions/nat'
      - $ref: '#/definitions/pv'
      - $ref: '#/definitions/ib'
      - $ref: '#/definitions/bridged'
      - $ref: '#/definitions/hostib'
additionalProperties: false

definitions:
  nat:
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
          bridge:
           type: string
          bridge-hwaddr:
           type: string
          tap-prefix:
           type: string
          mtu:
           type: integer
          domain-name:
           type: string
          dns-server:
           type: string
          reverse-nat:
           type: object
          allow-outbound:
           type: string
        additionalProperties: false

    additionalProperties: false

  pv:
    properties:
      type:
          enum:
            - pv

      settings:
        type: object
        properties:
          mac-prefix:
           type: string
          bridge-prefix:
           type: string
          tap-prefix:
           type: string
          mtu:
           type: integer
          host-if-suffix:
           type: string
        additionalProperties: false

    additionalProperties: false

  ib:
    properties:
      type:
          enum:
            - ib

      settings:
        type: object
        properties:
          host-device:
           type: string
          min-pkey:
           type: string
          max-pkey:
           type: string
          license:
           type: string
          opensm-daemon:
           type: string
          opensm-partition-cfg:
           type: string
          opensm-partition-tpl:
           type: string
        additionalProperties: false

    additionalProperties: false

  bridged:
    properties:
      type:
          enum:
            - bridged

      settings:
        type: object
        properties:
          host-bridge:
           type: string
          tap-prefix:
           type: string
          mtu:
           type: integer
        additionalProperties: false

    additionalProperties: false

  hostib:
    properties:
      type:
          enum:
            - hostib

      settings:
        type: object
        properties:
          host-device:
           type: string
        additionalProperties: false

    additionalProperties: false
"""

class NetworkSetupError(PcoccError):
    def __init__(self, error):
        super(NetworkSetupError, self).__init__(
            'Failed to setup network on node: ' + error)


class VNetworkConfig(dict):
    """Manages the network configuration"""
    def load(self, filename):
        """Loads the network config

        Instantiates a dict holding a VNetwork class for each configured
        network

        """
        try:
            stream = file(filename, 'r')
            net_config = yaml.safe_load(stream)
        except yaml.parser.ParserError as err:
            raise InvalidConfigurationError(str(err))
        except IOError as err:
            raise InvalidConfigurationError(str(err))

        try:
            jsonschema.validate(net_config,
                                yaml.safe_load(network_config_schema))
        except jsonschema.exceptions.ValidationError as err:
            raise InvalidConfigurationError(str(err))

        for name, net_attr in net_config.iteritems():
            self[name] = VNetwork.create(net_attr['type'],
                                         name,
                                         net_attr['settings'])

class VNetwork(object):
    """Base class for all network types"""
    def __init__(self, name):
        self.name = name

    def create(ntype, name, settings):
        """Factory function to create subclasses"""
        if ntype == "pv":
            return VPVNetwork(name, settings)
        if ntype == "nat":
            return VNATNetwork(name, settings)
        if ntype == "ib":
            return VIBNetwork(name, settings)
        if ntype == "bridged":
            return VBridgedNetwork(name, settings)
        if ntype == "hostib":
            return VHostIBNetwork(name, settings)


        assert 0, "Unknown network type: " + ntype

    create = staticmethod(create)

    def get_license(self, cluster):
        """Returns a list of batch licenses that must be allocated
        to instantiate the network"""
        return []

    def dump_resources(self, res):
        """Store config data describing the allocated resources
        in the key/value store

        Called when setting up a node for a virtual cluster

        """
        batch = Config().batch
        batch.write_key(
            'cluster',
            '{0}/{1}'.format(self.name, batch.node_rank),
            yaml.dump(res))

    def load_resources(self):
        """Read config data describing the allocated resources
        from the key/value store"""
        batch = Config().batch
        data = batch.read_key(
            'cluster',
            '{0}/{1}'.format(self.name, batch.node_rank))

        if not data:
            raise NetworkSetupError('unable to load resources for network '
                                    + self.name)

        return yaml.safe_load(data)


    def _vm_res_label(self, vm):
        return "vm-%d" % vm.rank

    def _do_alloc_pkey(self, key_alloc_state):
        """Helper to allocate a unique key using the key/value store"""
        batch = Config().batch

        if not key_alloc_state:
            key_alloc_state = []
        else:
            key_alloc_state = yaml.safe_load(key_alloc_state)

        jsonschema.validate(key_alloc_state,
                            yaml.safe_load(pkey_allocation_schema))

        num_keys_preclean = len(key_alloc_state)
        # Cleanup completed jobs
        try:
            joblist = batch.list_all_jobs()
            key_alloc_state = [ pk for pk in key_alloc_state
                                 if int(pk['batchid']) in joblist ]
        except Batch.BatchError:
            pass

        num_keys = len(key_alloc_state)
        stray_keys = num_keys_preclean - num_keys
        if stray_keys > 0:
            logging.warning(
                'Found {0} leftover Keys, will try to cleanup'.format(
                    stray_keys))

        total_keys = self._max_pkey - self._min_pkey + 1
        if len(key_alloc_state) >= total_keys:
            raise NetworkSetupError('Unable to find a free key')

        key_index = len(key_alloc_state)
        for i, allocated_key in enumerate(key_alloc_state):
            if i != allocated_key['pkey_index']:
                key_index = i
                break

        key_alloc_state.insert(key_index,
                                      {'pkey_index': key_index,
                                       'batchid': batch.batchid})


        return yaml.dump(key_alloc_state), key_index

    def _do_free_pkey(self, key_index, key_alloc_state):
        """Helper to free a unique key using the key/value store"""
        key_alloc_state = yaml.safe_load(key_alloc_state)
        jsonschema.validate(key_alloc_state,
                            yaml.safe_load(pkey_allocation_schema))
        for i, allocated_key in enumerate(key_alloc_state):
            if allocated_key['pkey_index'] == key_index:
                key_alloc_state.pop(i)
                break
        else:
            raise NetworkSetupError(
                "key at index {0}, for network {1} "
                "is no longer allocated".format(
                    key_index, self.name))

        return yaml.dump(key_alloc_state), None

    def _get_net_key_path(self, key):
        """Returns path in the key/value store for a per network instance
        key

        """
        return  'net/name/{0}/{1}'.format(self.name, key)

    def _get_type_key_path(self, key):
        """Returns path in the key/value store for a per network type
        key

        """
        return  'net/type/{0}/{1}'.format(self._type, key)


class VBridgedNetwork(VNetwork):
    def __init__(self, name, settings):
        super(VBridgedNetwork, self).__init__(name)

        self._host_bridge = settings["host-bridge"]
        self._tap_prefix = settings["tap-prefix"]
        self._mtu = int(settings["mtu"])
        self._type = "direct"

    def init_node(self):
        pass

    def cleanup_node(self):
        self._cleanup_stray_taps()

    def alloc_node_resources(self, cluster):
        batch = Config().batch
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

            try:
                hwaddr = os.environ['PCOCC_NET_{0}_HWADDR'.format(
                              self.name.upper())]
            except KeyError:
                hwaddr = [ 0x52, 0x54, 0x00,
		           random.randint(0x00, 0x7f),
		           random.randint(0x00, 0xff),
		           random.randint(0x00, 0xff) ]
	        hwaddr = ':'.join(map(lambda x: "%02x" % x, hwaddr))

            vm.add_eth_if(self.name,
                          net_res[vm_label]['tap_name'],
                          hwaddr)

    def _cleanup_stray_taps(self):
        # Look for remaining taps to cleanup
        for tap_id in find_used_dev_ids(self._tap_prefix):
            logging.warning(
                'Deleting leftover tap for {0} network'.format(self.name))

            # Delete the tap
            tap_name = dev_name_from_id(self._tap_prefix,
                                        tap_id)
            tun_delete_tap(tap_name)

    def _alloc_vm_res(self, vm):
        # Allocate a local VM id unique on this node
        tap_id = find_free_dev_id(self._tap_prefix)
        # Define the VM tap name and unique IP based on the VM id
        tap_name = dev_name_from_id(self._tap_prefix, tap_id)

        # Create and enable the tap
        tun_create_tap(tap_name, Config().batch.batchuser)
        tun_enable_tap(tap_name)
        ip_set_mtu(tap_name, self._mtu)
        bridge_add_port(tap_name, self._host_bridge)
        return {'tap_name': tap_name}

    def _cleanup_vm_res(self, resources):
        tap_name = resources['tap_name']
        # Delete the tap
        tun_delete_tap(tap_name)


class VPVNetwork(VNetwork):
    def __init__(self, name, settings):
        super(VPVNetwork, self).__init__(name)

        self._mac_prefix = settings.get("mac-prefix", "52:54:00")
        self._bridge_prefix = settings["bridge-prefix"]
        self._tap_prefix = settings["tap-prefix"]
        self._mtu = int(settings["mtu"])
        self._host_if_suffix = settings["host-if-suffix"]
        self._min_pkey = 1024
        self._max_pkey = 2 ** 16 - 1
        self._type = "pv"

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

        # Master allocates a pkey and broadcasts to the others
        if batch.node_rank == master:
            logging.info("Node is master for PV network {0}".format(
                    self.name))

            tun_id = self._min_pkey + batch.atom_update_key(
                'global',
                self._get_type_key_path('key_alloc_state'),
                self._do_alloc_pkey)

            batch.write_key(
                'cluster',
                self._get_net_key_path('key'),
                tun_id)
        else:
            tun_id = int(batch.read_key(
                'cluster',
                self._get_net_key_path('key'),
                blocking=True,
                timeout=30))

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
                tun_enable_tap(tap_name)
                ip_set_mtu(tap_name, self._mtu)
                port_id = ovs_add_port(tap_name, bridge_name)

                local_ports.append(port_id)

                # Incoming packets to the VM are directly
                # sent to the destination tap
                ovs_add_flow(bridge_name,
                             "table=0,idle_timeout=0,hard_timeout=0,"
                             "priority=3000,"
                             "dl_dst=%s,actions=output:%s"
                             % (hwaddr, port_id))

                # Flood packets sent from the VM without a known
                # destination
                # FIXME: answer
                # directly to ARP requests and drop other broadcast
                # packets as this is too inefficient
                ovs_add_flow(bridge_name,
                             "table=0,in_port=%s,"
                             "idle_timeout=0,hard_timeout=0,"
                             "priority=2000," "actions=flood" % (
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
                             "table=0,idle_timeout=0,hard_timeout=0,"
                             "priority=3000,"
                             "dl_dst=%s,actions=output:%s"
                             % (hwaddr, host_tunnels[host]))

        # Incoming broadcast packets: output to all local VMs
        # TODO: answer directly to ARP requests and drop other
        # broadcast packets
        if local_ports:
            ovs_add_flow(bridge_name,
                         "table=0,idle_timeout=0,hard_timeout=0,"
                         "priority=1000," "actions=output:%s" % (
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
            Config().batch.atom_update_key(
                'global',
                self._get_type_key_path('key_alloc_state'),
                self._do_free_pkey,
                int(net_res['global']['tun_id']) - self._min_pkey)

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
                'Deleting leftover bridge for {0} network'.format(self.name))
            # Delete the bridge
            bridge_name = dev_name_from_id(self._bridge_prefix,
                                           bridge_id)
            ovs_del_bridge(bridge_name)

    def _cleanup_stray_taps(self):
        # Look for remaining taps to cleanup
        for tap_id in find_used_dev_ids(self._tap_prefix):
            logging.warning(
                'Deleting leftover tap for {0} network'.format(self.name))

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
    def __init__(self, name, settings):
        super(VNATNetwork, self).__init__(name)

        self._type = "nat"
        self._bridge_name = settings["bridge"]
        self._nat_network = settings["nat-network"].split("/")[0]
        self._nat_network_bits = int(settings["nat-network"].split("/")[1])
        self._vm_network_gw = settings["vm-network-gw"]
        self._vm_network = settings["vm-network"].split("/")[0]
        self._vm_network_bits = int(settings["vm-network"].split("/")[1])
        self._vm_ip = settings["vm-ip"]
        self._tap_prefix = settings["tap-prefix"]
        self._mtu = int(settings["mtu"])
        self._vm_hwaddr = settings["vm-hwaddr"]
        self._domain_name = settings["domain-name"]
        self._dns_server = settings["dns-server"]
        self._dnsmasq_pid_filename = "/var/run/pcocc_dnsmasq.pid"
        self._bridge_hwaddr = settings.get("bridge-hwaddr", "52:54:00:C0:C0:C0")

        if "allow-outbound" in settings:
            if settings["allow-outbound"] == 'none':
                self._allow_outbound = False
            else:
                raise InvalidConfigurationError(
                    '%s is not a valid value '
                    'for allow-outbound' % settings["allow-outbound"])
        else:
            self._allow_outbound = True

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
                except OSError,ValueError:
                    pass
            os.remove(self._dnsmasq_pid_filename)

    def has_dnsmasq(self):
        if os.path.isfile(self._dnsmasq_pid_filename):
            with open(self._dnsmasq_pid_filename, 'r') as f:
                pid = f.read()
                try:
                    os.kill(int(pid), 0)
                    return True
                except OSError,ValueError:
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
                            "--dhcp-option=option:dns-server,%s  "
                            "--dhcp-option=option:netmask,%s "
                            "--dhcp-option=option:router,%s "
                            "-F %s,static " %(
                        self._dnsmasq_pid_filename,
                        self._bridge_name,
                        self._vm_hwaddr,
                        self._vm_ip,
                        self._domain_name.split(',')[0],
                        self._domain_name,
                        self._dns_server,
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
                     "table=0,idle_timeout=0,hard_timeout=0,"
                     "dl_type=0x0806,nw_dst=%s,actions=local"
                     % (self._vm_network_gw))

        # Flood ARP answers from the bridge to each port
        ovs_add_flow(self._bridge_name,
                     "table=0,in_port=local,idle_timeout=0,hard_timeout=0,"
                     "dl_type=0x0806,nw_dst=%s,actions=flood"%(self._vm_ip))

        # Flood DHCP answers from the bridge to each port
        ovs_add_flow(self._bridge_name,
                     "table=0,idle_timeout=0,hard_timeout=0,"
                     "priority=0,in_port=LOCAL,udp,tp_dst=68,actions=FLOOD")




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
                'Deleting leftover tap for {0} network'.format(self.name))

            # Delete the tap
            tun_delete_tap(dev_name_from_id(self._tap_prefix,
                                            tap_id))


        self.kill_dnsmasq()

    def alloc_node_resources(self, cluster):
        batch = Config().batch

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
        tun_enable_tap(tap_name)

        # Connect it to the bridge
        vm_port_id = ovs_add_port(tap_name, self._bridge_name)

        # Rewrite outgoing packets with the VM unique IP
        ovs_add_flow(self._bridge_name,
                     "table=0,in_port=%d,idle_timeout=0,hard_timeout=0,"
                     "dl_type=0x0800,nw_src=%s,actions=mod_nw_src:%s,local"
                     % (vm_port_id,
                        self._vm_ip,
                        vm_nat_ip))

        # Rewrite incoming packets with the VM real IP
        ovs_add_flow(self._bridge_name,
                     "table=0,in_port=local,idle_timeout=0,hard_timeout=0,"
                     "dl_type=0x0800,nw_dst=%s,actions=mod_nw_dst:%s,output:%d"
                     % (vm_nat_ip,
                        self._vm_ip,
                        vm_port_id))

        # Handle DHCP requests from the VM locally
        ovs_add_flow(self._bridge_name,
                     "table=0,in_port=%d,idle_timeout=0,hard_timeout=0,"
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
                                  "--to-destination %s:22"
                                  % (resolve_host(socket.gethostname()),
                                     host_port, vm_nat_ip),
                                  "PREROUTING", "nat")

            ipt_delete_rule_idemp("-d %s/32 -p tcp -m tcp"
                                  " --dport %s -j DNAT "
                                  "--to-destination %s:22"
                                  % (resolve_host(socket.gethostname()),
                                     host_port, vm_nat_ip),
                                  "OUTPUT", "nat")


    def _vm_ip_from_id(self, nat_id):
        # First IP is for the bridge
        return get_ip_on_network(self._nat_network, nat_id + 2)

    def get_rnat_host_port(vm_rank, port):
        return Config().batch.read_key(
            'cluster',
            'rnat/{0}/{1}'.format(vm_rank, port),
            blocking=False)

    get_rnat_host_port = staticmethod(get_rnat_host_port)


"""Schema to validate individual pkey entries in the key/value store"""
pkey_entry_schema = """
type: object
properties:
  vf_guids:
    type: array
    items:
      type: string
      pattern: "^0x[0-9a-zA-Z]{16}$"
  host_guids:
    type: array
    items:
      type: string
      pattern: "^0x[0-9a-zA-Z]{16}$"
required:
    - vf_guids
    - host_guids
"""

"""Schema to validate the global pkey state in the key/value store"""
pkey_allocation_schema = """
type: array
items:
  type: object
  properties:
    pkey_index:
      type: integer
    batchid:
       type: integer
  required:
    - pkey_index
    - batchid
"""

class VHostIBNetwork(VNetwork):
    def __init__(self, name, settings):
        super(VHostIBNetwork, self).__init__(name)

        self._type = "hostib"
        self._device_name = settings["host-device"]

    def init_node(self):
        # We can probably remove this once we get kernels with the
        # driver_override feature.  For now we need to use new_id but
        # this binds all unbound devices so we start by binding them
        # to pci-stub.
        vf_enable_driver(self._device_name, 'pci-stub')
        vf_enable_driver(self._device_name, 'vfio-pci')

    def cleanup_node(self):
        deleted_vfs = cleanup_all_vfs(self._device_name)
        if len(deleted_vfs) > 0:
            logging.warning(
                'Deleted {0} leftover VFs for {1} network'.format(
                    len(deleted_vfs), self.name))

    @property
    def _dev_vf_type(self):
        return device_vf_type(self._device_name)

    def _gen_guid_suffix(self):
        return ''.join(['%02x' % random.randint(0,0xff) for _ in xrange(6)])

    def alloc_node_resources(self, cluster):
        batch = Config().batch
        net_res = {}

        if (self._dev_vf_type != VFType.MLX5):
            raise NetworkSetupError('Direct host IB network access is only '
                                    'available for mlx5 devices')

        for vm in cluster.vms:
            if not vm.is_on_node():
                continue

            if not self.name in vm.networks:
                continue

            try:
                port_guid = os.environ['PCOCC_NET_{0}_PORT_GUID'.format(
                                        self.name.upper())]
            except KeyError:
                port_guid ='0xc1cc' + self._gen_guid_suffix()

            try:
                node_guid = os.environ['PCOCC_NET_{0}_NODE_GUID'.format(
                                        self.name.upper())]
            except KeyError:
                node_guid ='0xd1cc' + self._gen_guid_suffix()

            try:
                device_name = self._device_name
                vf_name = find_free_vf(device_name)

                vf_bind_vfio(vf_name, batch.batchuser)
                vf_set_guid(device_name, vf_name,
                            port_guid,
                            node_guid)

                vm_label = self._vm_res_label(vm)
                net_res[vm_label] = {'vf_name': vf_name}
            except Exception as e:
                self.dump_resources(net_res)
                raise

        self.dump_resources(net_res)

    def _free_node_vfs(self, cluster):
        net_res = None
        batch = Config().batch
        for vm in cluster.vms:
            if not vm.is_on_node():
                continue

            if not self.name in vm.networks:
                continue

            if not net_res:
                net_res = self.load_resources()

            vm_label = self._vm_res_label(vm)

            device_name = self._device_name
            vf_name = net_res[vm_label]['vf_name']

            vf_unbind_vfio(vf_name)
            if (self._dev_vf_type == VFType.MLX4):
                vf_unset_pkey(device_name, vf_name)
            else:
                vf_unset_guid(device_name, vf_name)


    def free_node_resources(self, cluster):
        return self._free_node_vfs(cluster)

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
            vm.add_vfio_if(self.name,
                           net_res[vm_label]['vf_name'])

class VIBNetwork(VHostIBNetwork):
    def __init__(self, name, settings):
        super(VIBNetwork, self).__init__(name, settings)

        self._type = "ib"
        self._device_name = settings["host-device"]
        self._min_pkey   = int(settings["min-pkey"], 0)
        self._max_pkey   = int(settings["max-pkey"], 0)
        self._license_name = settings.get("license", None)
        self._opensm_partition_cfg = settings["opensm-partition-cfg"]
        self._opensm_partition_tpl = settings["opensm-partition-tpl"]
        self._opensm_daemon = settings["opensm-daemon"]

    def get_license(self, cluster):
        if self._license_name:
            for vm in cluster.vms:
                if self.name in vm.networks:
                    return [self._license_name]

        return []

    def alloc_node_resources(self, cluster):
        batch = Config().batch
        net_res = {}

        # First pass, find out which Hosts/VMs need to be managed
        net_hosts = set()
        net_vms = []
        for vm in cluster.vms:
            if not self.name in vm.networks:
                continue
            net_hosts.add(vm.get_host_rank())
            if vm.is_on_node():
                net_vms.append(vm)

        # No VM on node, nothing to do
        if not net_vms:
            return

        # First host becomes master for setting up this network
        master = False
        if batch.node_rank == sorted(net_hosts)[0]:
            master = True

        # Master allocates a pkey and broadcasts to the others
        if master:
            logging.info("Node is master for IB network {0}".format(
                    self.name))

            pkey_index = batch.atom_update_key(
                'global',
                self._get_net_key_path('pkey_alloc_state'),
                self._do_alloc_pkey)

            batch.write_key(
                'cluster',
                self._get_net_key_path('pkey'),
                pkey_index)
        else:
            pkey_index = int(batch.read_key('cluster',
                                            self._get_net_key_path('pkey'),
                                            blocking=True,
                                            timeout=30))

        my_pkey = self._min_pkey + pkey_index
        logging.info("Using PKey 0x{0:04x} for network {1}".format(
            my_pkey,
            self.name))

        # Write guids needed for our host
        host_guid = get_phys_port_guid(self._device_name)
        batch.write_key(
            'cluster',
            self._get_net_key_path('guids/' + str(batch.node_rank)),
            host_guid)

        # Master waits until all hosts have written their guids
        # and updates opensm
        if master:
            logging.info("Collecting GUIDs from all hosts".format(
                    self.name))
            global_guids = batch.wait_child_count('cluster',
                                                  self._get_net_key_path('guids'),
                                                  len(net_hosts))
            sm_config = {}
            sm_config['host_guids'] = [ str(child.value) for child
                                       in global_guids.children ]
            sm_config['vf_guids'] = [ vm_get_guid(vm, my_pkey) for vm
                                      in cluster.vms
                                      if self.name in vm.networks ]

            logging.info("Requesting OpenSM update".format(
                    self.name))
            batch.write_key('global', 'opensm/pkeys/' + str(hex(my_pkey)),
                            sm_config)

        net_res['master'] = master
        net_res['pkey'] = my_pkey
        net_res['pkey_index'] = pkey_index

        # Setup VFs for our VMs
        for vm in net_vms:
            try:
                device_name = self._device_name
                vf_name = find_free_vf(device_name)
                vf_bind_vfio(vf_name, batch.batchuser)

                if (self._dev_vf_type == VFType.MLX4):
                    # We may have to retry if opensm is slow to propagate PKeys
                    for i in range(5):
                        try:
                            vf_set_pkey(device_name, vf_name, my_pkey)
                            break
                        except NetworkSetupError:
                            if i == 4:
                                raise
                            logging.warning("PKey not yet ready, sleeping...")
                            time.sleep(1 + i*2)
                            pass
                else:
                    vf_set_guid(device_name, vf_name,
                                vm_get_guid(vm, my_pkey),
                                vm_get_node_guid(vm, my_pkey))

                vm_label = self._vm_res_label(vm)
                net_res[vm_label] = {'vf_name': vf_name}
            except Exception as e:
                self.dump_resources(net_res)
                raise

        self.dump_resources(net_res)

    def free_node_resources(self, cluster):
        net_res = None
        batch = Config().batch

        self._free_node_vfs(cluster)

        if net_res and net_res['master']:
            # Update opensm
            pkey_key =  'opensm/pkeys/' + str(hex(net_res['pkey']))
            batch.delete_key('global', pkey_key)

            # Free pkey
            pkey_index = batch.atom_update_key(
                'global',
                self._get_net_key_path('pkey_alloc_state'),
                self._do_free_pkey,
                net_res['pkey_index'])

            # Cleanup keystore
            batch.delete_dir(
                'cluster',
                self._get_net_key_path(''))

    def pkey_daemon(self):
        batch = Config().batch

        while True:
            pkeys = {}
            pkey_path = batch.get_key_path('global', 'opensm/pkeys')

            # Read config for all pkeys
            ret, last_index  = batch.read_dir_index('global', 'opensm/pkeys')
            while not ret:
                logging.warning("PKey path doesn't exist")
                ret, last_index  = batch.wait_key_index('global',
                                                        'opensm/pkeys',
                                                        last_index,
                                                        timeout=0)

            logging.info("PKey change detected: refreshing configuration")

            for child in ret.children:
                # Ignore directory key
                if child.key == pkey_path:
                    continue

                # Find keys matching a valid PKey value
                m = re.match(r'{0}/(0x\d\d\d\d)$'.format(pkey_path), child.key)
                if not m:
                    logging.warning("Invalid entry in PKey directory: " +
                                    child.key)
                    continue
                pkey = m.group(1)

                # Load configuration and validate against schema
                try:
                    config = yaml.safe_load(child.value)
                    jsonschema.validate(config,
                                        yaml.safe_load(pkey_entry_schema))
                    pkeys[pkey] = config
                except yaml.YAMLError as e:
                    logging.warning("Misconfigured PKey {0}: {1}".format(
                             pkey, e))
                    continue
                except jsonschema.ValidationError as e:
                    logging.warning("Misconfigured PKey {0}: {1}".format(
                            pkey, e))
                    continue

            tmp = tempfile.NamedTemporaryFile(delete=False)
            with open(self._opensm_partition_tpl) as f:
                lines = f.readlines()
                tmp.writelines(lines)

            tmp.write('\n')

            for pkey, config in pkeys.iteritems():
                partline = 'PK_{0}={0} , ipoib'.format(pkey)
                for vf_guids in chunks(config['vf_guids'], 128):
                    partline_vf = ', indx0 : ' + ', '.join(g + '=full'
                                                           for g in vf_guids)
                    tmp.write(partline + partline_vf + ' ; \n')

                partline += ': '

                for host_guids in chunks(config['host_guids'], 128):
                    tmp.write(partline +
                              ', '.join(g + '=full'
                                        for g in host_guids) +
                              ' ; \n')

            tmp.close()
            shutil.move(tmp.name, self._opensm_partition_cfg)
            os.chmod(self._opensm_partition_cfg,
                     stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH | stat.S_IRGRP)


            for proc in psutil.process_iter():
                if isinstance(proc.name, basestring):
                    procname = proc.name
                else:
                    procname = proc.name()

                if procname == self._opensm_daemon:
                    proc.send_signal(signal.SIGHUP)

            # Wait for next update
            batch.wait_key_index('global', 'opensm/pkeys', last_index,
                                 timeout=0)

def device_vf_type(device_name):
    if device_name[:4] == 'mlx4':
        return VFType.MLX4
    elif device_name[:4] == 'mlx5':
        return VFType.MLX5

    raise NetworkSetupError('Cannot determine VF type for device %s' % device_name)

def make_mask(num_bits):
    "return a mask of num_bits as a long integer"
    return ((2L<<num_bits-1) - 1) << (32 - num_bits)

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

def ovs_bridge_exists(brname):
    match = re.search(r'Bridge %s' % (brname),
                  subprocess_check_output(["ovs-vsctl", "show"]))
    if match:
        return True
    else:
        return False


def ovs_add_flow(brname, flow):
    subprocess.check_call(["ovs-ofctl", "add-flow", brname, flow])

def ovs_del_flows(brname, flow):
    subprocess.check_call(["ovs-ofctl", "del-flows", brname] + flow.split())

def ovs_get_port_id(tapname, brname):
    match = re.search(r'(\d+)\(%s\)' % (tapname),
                  subprocess_check_output(["ovs-ofctl", "show", brname]))
    if match:
        return int(match.group(1))
    else:
        return -1

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
    except subprocess.CalledProcessError as err:
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
        version_string = subprocess_check_output(['ip', '-V'])
        match = re.search('iproute2-ss(\d+)', version_string)
        ip_has_tuntap.ipversion = int(match.group(1))

    return ip_has_tuntap.ipversion >= 100519

def bridge_add_port(tapname, bridgename):
    subprocess.check_call(["ip", "link", "set", tapname, "master",
                           bridgename])

def tun_create_tap(name, user):
    if ip_has_tuntap():
        subprocess.check_call(["ip", "tuntap", "add", name, "mode", "tap",
                               "user", user], stdout=open(os.devnull))
    else:
        subprocess.check_call(["tunctl", "-u", user, "-t", name],
                              stdout=open(os.devnull))

def tun_enable_tap(name):
    subprocess.check_call(["ip", "link", "set", name, "up"])

def tun_delete_tap(name):
    if ip_has_tuntap():
        subprocess.check_call(["ip", "tuntap", "del", name, "mode", "tap"])
    else:
        subprocess.check_call(["tunctl", "-d", name])

def ip_set_mtu(dev, mtu):
    subprocess.check_call(["ip", "link", "set", dev, "mtu", "%d" % (mtu)])

def ip_add(ip, bits, dev):
    subprocess_check_output(["ip", "addr", "add",
                             "%s/%d" % (ip, bits), "broadcast",
                             get_ip_on_network(
                num_to_dotted_quad(network_mask(ip, bits)),
                2**(32-bits) - 1), "dev", dev],
                            stderr=subprocess.STDOUT)

def ip_add_idemp(ip, bits, dev):
    try:
        ip_add(ip, bits, dev)
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

class VFType:
    MLX4 = 1
    MLX5 = 2

def vf_enable_driver(device_name, driver_name):
    device_path = "/sys/class/infiniband/%s/device/virtfn0" % (device_name)
    driver_path = os.path.join("/sys/bus/pci/drivers", driver_name, 'new_id')

    with open(os.path.join(device_path, 'vendor'), 'r') as f:
        vendor_id=f.read()

    with open(os.path.join(device_path, 'device'), 'r') as f:
        device_id=f.read()

    with open(driver_path, 'w') as f:
        f.write('%s %s' % (vendor_id, device_id))

def find_free_vf(device_name):
    return _perform_on_vfs(device_name, 'find')

def cleanup_all_vfs(device_name):
    return _perform_on_vfs(device_name, 'cleanup')

def _perform_on_vfs(device_name, action, *args):
    device_path = "/sys/class/infiniband/%s/device" % (device_name)
    bound_devices = os.listdir("/sys/bus/pci/drivers/vfio-pci")

    vf_list = []
    for virtfn in os.listdir(device_path):
        m = re.match(r'virtfn(\d+)', virtfn)

        if not re.match(r'virtfn(\d+)', virtfn):
            continue

        vf_id = m.group(1)

        vf_name = os.path.basename(os.readlink(
            os.path.join(device_path, virtfn)))

        if action == 'find' and vf_name not in bound_devices:
            return vf_name
        elif action == 'cleanup' and vf_name in bound_devices:
            vf_unbind_vfio(vf_name)
            vf_list.append(vf_name)
        elif action == 'getid' and vf_name == args[0]:
            return int(vf_id)


    if action == 'find':
        raise NetworkSetupError('unable to find a free '
                                'VF for device %s' % device_name)
    elif action=='cleanup':
        return vf_list

def vf_find_iommu_group(vf_name):
    iommu_group = '/sys/bus/pci/drivers/vfio-pci/%s/iommu_group' % vf_name
    iommu_group = os.path.basename(os.readlink(iommu_group))

    return iommu_group

def vf_bind_vfio(vf_name, batch_user):
    with open('/sys/bus/pci/devices/{0}/driver/unbind'.format(vf_name), 'w') as f:
            f.write(vf_name)

    with open('/sys/bus/pci/drivers/vfio-pci/bind', 'w') as f:
        f.write(vf_name)

    iommu_group = vf_find_iommu_group(vf_name)

    uid = pwd.getpwnam(batch_user).pw_uid
    # FIXME: This seems to be required to prevent a race
    # between char device creation and chown
    time.sleep(0.1)
    os.chown(os.path.join('/dev/vfio/', iommu_group), uid, -1)

def vf_unbind_vfio(vf_name):
    with open('/sys/bus/pci/drivers/vfio-pci/unbind', 'w') as f:
        f.write(vf_name)

    with open('/sys/bus/pci/drivers/pci-stub/bind', 'w') as f:
        f.write(vf_name)

def find_pkey_idx(device_name, pkey_value):
    pkey_idx_path = "/sys/class/infiniband/%s/ports/1/pkeys" % (
        device_name)

    for pkey_idx in os.listdir(pkey_idx_path):
        this_pkey_idx_path=os.path.join(pkey_idx_path, pkey_idx)
        with open(this_pkey_idx_path) as f:
            try:
                this_pkey_value = int(f.read().strip(), 0)
            except ValueError:
                continue

            if this_pkey_value & 0x7fff == pkey_value & 0x7fff:
                return pkey_idx

    raise NetworkSetupError('pkey %s not found on device %s' % (
        hex(pkey_value), device_name))

def vf_set_pkey(device_name, vf_name, pkey_value):
    pkey_idx_path = "/sys/class/infiniband/%s/iov/%s/ports/1/pkey_idx" % (
        device_name, vf_name)

    user_pkey_idx = find_pkey_idx(device_name, pkey_value)
    with open(os.path.join(pkey_idx_path, '0'), 'w') as f:
        f.write(user_pkey_idx)

    def_pkey_idx = find_pkey_idx(device_name, 0xffff)
    with open(os.path.join(pkey_idx_path, '1'), 'w') as f:
        f.write(def_pkey_idx)

def vf_unset_pkey(device_name, vf_name):
    pkey_idx_path = "/sys/class/infiniband/%s/iov/%s/ports/1/pkey_idx" % (
        device_name, vf_name)

    with open(os.path.join(pkey_idx_path, '0'), 'w') as f:
        f.write('none')

    with open(os.path.join(pkey_idx_path, '1'), 'w') as f:
        f.write('none')

def vf_id_from_name(device, vf_name):
    return _perform_on_vfs(device, 'getid', vf_name)

def vf_unset_guid(device_name, vf_name):
    vf_id = vf_id_from_name(device_name, vf_name)
    sriov_path = '/sys/class/infiniband/{0}/device/sriov/{1}'.format(device_name,vf_id)

    with open(os.path.join(sriov_path, 'policy'), 'w') as f:
        f.write('Down\n')

def vf_set_guid(device_name, vf_name, guid, node_guid):
    vf_id = vf_id_from_name(device_name, vf_name)
    sriov_path = '/sys/class/infiniband/{0}/device/sriov/{1}'.format(device_name,vf_id)

    with open(os.path.join(sriov_path, 'policy'), 'w') as f:
        f.write('Follow\n')

    with open(os.path.join(sriov_path, 'node'), 'w') as f:
        f.write(guid_hex_to_col(node_guid))

    with open(os.path.join(sriov_path, 'port'), 'w') as f:
        f.write(guid_hex_to_col(guid))


def vm_get_guid(vm, pkey_id):
    pkey_high = pkey_id / 0x100
    pkey_low = pkey_id % 0x100
    vm_high = vm.rank / 0x100
    vm_low = vm.rank % 0x100

    return '0xc0cc{0:02x}{1:02x}00{2:02x}{3:02x}00'.format(pkey_high, pkey_low,
                                                        vm_high, vm_low)

def vm_get_node_guid(vm, pkey_id):
    pkey_high = pkey_id / 0x100
    pkey_low = pkey_id % 0x100
    vm_high = vm.rank / 0x100
    vm_low = vm.rank % 0x100

    return '0xd0cc{0:02x}{1:02x}00{2:02x}{3:02x}00'.format(pkey_high, pkey_low,
                                                            vm_high, vm_low)

def get_phys_port_guid(device_name):
    return subprocess_check_output(['ibstat', '-p',
                                    device_name]).splitlines()[0]

def guid_hex_to_col(guid):
    res = ':'.join(guid[c:c+2] for c in xrange(2, len(guid), 2))
    return res

def chunks(array, n):
    """Yield successive n-sized chunks from array."""
    for i in range(0, len(array), n):
        yield array[i:i+n]
