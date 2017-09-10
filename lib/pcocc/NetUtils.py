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

import atexit
import logging
import os
import pwd
import re
import shelve
import signal
import socket
import struct
import subprocess
import time
import tempfile

from abc import ABCMeta, abstractmethod
from .Error import PcoccError

class NetworkSetupError(PcoccError):
    def __init__(self, error):
        super(NetworkSetupError, self).__init__(
            'Failed to setup network on node: ' + error)

class Tracker(object):
    """
    Keep track of node network configuration changes performed for each virtual
    cluster and automatically roll them back after a cluster is no longer active.
    """
    _trackable = {}
    @classmethod
    def register_trackable(cls, name, trackable_class):
        cls._trackable[name] = trackable_class

    def __init__(self, store_file):
        self._tracked_objs = shelve.open(store_file)
        for track_key, _ in self.list_objs():
            logging.info('Tracker loaded obj %s from %s',
                         track_key, store_file)

        logging.info('Tracker index is at %s',
                     self._track_index)

        atexit.register(self._tracked_objs.close)

    def create_with_ref(self, ref, trackable):
        self.add_ref(ref, trackable)
        return trackable.create()

    def add_ref(self, ref, trackable):
        track_key = self._track_key(trackable)
        value = self._tracked_objs.get(track_key,
                                       {'index': self._track_index,
                                        'data': trackable.dump_args(),
                                        'refs': set()})

        value['refs'].add(ref)

        self._tracked_objs['index'] = self._track_index + 1
        self._tracked_objs[track_key] = value
        self._tracked_objs.sync()

    def cleanup_ref(self, ref):
        return self.reclaim([ref], True)

    def reclaim(self, active_refs, reverse=False):
        to_reclaim = []
        for obj, value in self.list_objs():
            for ref in value['refs']:
                if not reverse and ref in active_refs:
                    break

                if reverse and ref not in active_refs:
                    break
            else:
                to_reclaim.append((obj, value))

        for obj, value in sorted(to_reclaim, key=lambda x: x[1]['index'],
                                 reverse=True):

            try:
                obj.delete()
                if reverse:
                    logging.info('Deleted %s', obj)
                else:
                    logging.warning('Deleted leftover %s', obj)
            except Exception as e:
                logging.warning('Failed to delete %s: %s', obj, e)

            del self._tracked_objs[self._track_key(obj)]
        self._tracked_objs.sync()

    def list_objs(self, obj_type=None):
        for key, value in self._tracked_objs.iteritems():
            if key == 'index':
                continue

            if obj_type is None  or obj_type == self._key_class_name(key):
                yield self._load_obj(self._key_class_name(key),
                                     value['data']), value

    @property
    def _track_index(self):
        return self._tracked_objs.get('index', 0)

    def _load_obj(self, class_name, data):
        return self._trackable[class_name](**data)

    @staticmethod
    def _track_key(obj):
        return ','.join((obj.__class__.__name__,
                         obj.__repr__()))
    @staticmethod
    def _key_class_name(key):
        return key.split(',')[0]

class TrackableClass(ABCMeta):
    def __init__(cls, name, bases, dct):
        Tracker.register_trackable(name, cls)
        super(TrackableClass, cls).__init__(name, bases, dct)

class TrackableObject(object):
    __metaclass__ = TrackableClass

    def __init__(self, name):
        self._name = name

    @abstractmethod
    def __repr__(self):
        return '{cls}(name={name})'.format(cls=self.__class__.__name__,
                                           name=self._name)

    @abstractmethod
    def dump_args(self):
        pass

    @abstractmethod
    def create(self):
        pass

    @abstractmethod
    def delete(self):
        pass

    def _log_create(self):
        logging.info('Created %s', self)

    @classmethod
    def run(cls, cmd, quiet=False, err_quiet=False):
        kwargs = {}
        if quiet:
            kwargs['stdout'] = open(os.devnull)
        if err_quiet:
            kwargs['stderr'] = open(os.devnull)

        subprocess.check_call(cmd, **kwargs)

    @classmethod
    def run_output(cls, cmd, mixed=False):
        if mixed:
            return subprocess.check_output(cmd,
                                           stderr=subprocess.STDOUT)
        else:
            return subprocess.check_output(cmd)

class VFIODev(TrackableObject):
    @classmethod
    def list_cleanup(cls, dev_list, *args, **kwargs):
        bound_devices = cls._list_vfio_devices()

        count = 0
        for dev_addr in bound_devices:
            if dev_addr in dev_list:
                cls(dev_addr, *args, **kwargs).delete()
                count += 1

        return count

    @classmethod
    def list_find_free(cls, dev_list, *args, **kwargs):
        bound_devices = cls._list_vfio_devices()

        dev_addr = None
        for dev_addr in dev_list:
            if dev_addr not in bound_devices:
                break
        else:
            raise NetworkSetupError('Unable to find a free '
                                    'PCI device among {0}'.format(dev_list))

        return cls(dev_addr, *args, **kwargs)

    def __init__(self, dev_addr, user='root', driver=None):
        self._dev_addr = dev_addr
        self._user = user
        self._driver = driver

    def __repr__(self):
        return '{cls}(dev_addr={dev_addr}, user={user}, driver={driver})'.format(
            cls = self.__class__.__name__,
            dev_addr = self._dev_addr,
            user = self._user,
            driver = self._driver)

    @property
    def dev_addr(self):
        return self._dev_addr

    def dump_args(self):
        return {'dev_addr': self._dev_addr, 'user': self._user, 'driver': self._driver}

    def create(self):
        self._bind_vfio()
        self._log_create()
        return self

    def delete(self):
        self._unbind_vfio()

    def _bind_vfio(self):
        with open('/sys/bus/pci/devices/{0}/driver/unbind'.format(self._dev_addr),
                  'w') as f:
            f.write(self._dev_addr)

        with open('/sys/bus/pci/drivers/vfio-pci/bind', 'w') as f:
            f.write(self._dev_addr)

        uid = pwd.getpwnam(self._user).pw_uid
        # FIXME: This seems to be required to prevent a race
        # between char device creation and chown
        time.sleep(0.1)
        os.chown(os.path.join('/dev/vfio/', self._iommu_group), uid, -1)

    def _unbind_vfio(self):
        with open('/sys/bus/pci/drivers/vfio-pci/unbind', 'w') as f:
            f.write(self._dev_addr)

        with open('/sys/bus/pci/drivers/{0}/bind'.format(self._driver), 'w') as f:
            f.write(self._dev_addr)

    @property
    def _iommu_group(self):
        iommu_group_path = '/sys/bus/pci/drivers/vfio-pci/{0}/iommu_group'.format(
            self._dev_addr)

        return os.path.basename(os.readlink(iommu_group_path))

    @staticmethod
    def _list_vfio_devices():
        return os.listdir("/sys/bus/pci/drivers/vfio-pci")

class VFIOInfinibandVF(VFIODev):
    @classmethod
    def ibdev_cleanup(cls, ibdev_name, *args, **kwargs):
        count = 0
        for vf_addr in cls._ibdev_perform(ibdev_name, 'list'):
            cls(vf_addr, ibdev_name, *args, **kwargs).delete()
            count +=1

        return count

    @classmethod
    def ibdev_find_free(cls, ibdev_name, *args, **kwargs):
        vf_addr = cls._ibdev_perform(ibdev_name, 'find')

        return cls(vf_addr, ibdev_name, *args, **kwargs)

    @classmethod
    def _ibdev_perform(cls, ibdev_name, action, *args):
        device_path = "/sys/class/infiniband/%s/device" % (ibdev_name)
        bound_devices = cls._list_vfio_devices()

        vf_list = []
        for virtfn in os.listdir(device_path):
            m = re.match(r'virtfn(\d+)', virtfn)

            if not re.match(r'virtfn(\d+)', virtfn):
                continue

            vf_id = m.group(1)

            vf_addr = os.path.basename(os.readlink(
                os.path.join(device_path, virtfn)))

            if action == 'find' and vf_addr not in bound_devices:
                return vf_addr
            elif action == 'list' and vf_addr in bound_devices:
                vf_list.append(vf_addr)
            elif action == 'getid' and vf_addr == args[0]:
                return int(vf_id)


        if action == 'find':
            raise NetworkSetupError('unable to find a free '
                                    'VF for device %s' % ibdev_name)
        elif action=='list':
            return vf_list

    def __init__(self, dev_addr, ibdev_name, user='root', port_guid=None,
                 node_guid=None, pkey=None):

        self._dev_addr = dev_addr
        self._user = user
        self._driver = 'pci-stub'
        self._ibdev_name = ibdev_name
        self._port_guid = port_guid
        self._node_guid = node_guid
        self._pkey = pkey

    def __repr__(self):
        return ('{cls}(dev_addr={dev_addr}, ibdev_name={ibdev_name}, '
                'user={user}, port_guid={port_guid}, '
                'node_guid={node_guid}, pkey={pkey})'.format(
                    cls = self.__class__.__name__,
                    dev_addr = self._dev_addr,
                    ibdev_name = self._ibdev_name,
                    user = self._user,
                    port_guid = self._port_guid,
                    node_guid = self._node_guid,
                    pkey = self._pkey))

    def create(self):
        super(VFIOInfinibandVF, self).create()

        if self._ibvf_type == IBVFType.MLX4:
            if self._pkey:
                for i in range(5):
                    try:
                        self._set_pkey()
                        break
                    except NetworkSetupError:
                        if i == 4:
                            raise
                        logging.warning("PKey not yet ready, sleeping...")
                        time.sleep(1 + i*2)
            else:
                self._allow_host_pkeys()
        else:
            self._set_guids()

    def delete(self):
        if self._ibvf_type == IBVFType.MLX4:
            if self._pkey:
                self._unset_pkey()
            else:
                self._clear_host_pkeys()
        else:
            self._unset_guids()

        super(VFIOInfinibandVF, self).delete()

    def dump_args(self):
        return {'dev_addr': self._dev_addr, 'ibdev_name': self._ibdev_name,
                'user': self._user, 'port_guid': self._port_guid,
                'node_guid': self._node_guid, 'pkey': self._pkey}

    @property
    def _id(self):
        return self._ibdev_perform(self._ibdev_name,
                                   'getid', self._dev_addr)

    @property
    def _ibvf_type(self):
        if self._ibdev_name[:4] == 'mlx4':
            return IBVFType.MLX4
        elif self._ibdev_name[:4] == 'mlx5':
            return IBVFType.MLX5

        raise NetworkSetupError('Cannot determine VF type for device {0}'.format(self._ibdev_name))

    def _unset_guids(self):
        sriov_path = '/sys/class/infiniband/{0}/device/sriov/{1}'.format(
            self._ibdev_name,
            self._id)

        with open(os.path.join(sriov_path, 'policy'), 'w') as f:
            f.write('Down\n')

    def _set_guids(self):
        sriov_path = '/sys/class/infiniband/{0}/device/sriov/{1}'.format(
            self._ibdev_name, self._id)

        with open(os.path.join(sriov_path, 'policy'), 'w') as f:
            f.write('Follow\n')

        with open(os.path.join(sriov_path, 'node'), 'w') as f:
            f.write(guid_hex_to_col(self._node_guid))

        with open(os.path.join(sriov_path, 'port'), 'w') as f:
            f.write(guid_hex_to_col(self._port_guid))

    def _set_pkey(self):
        pkey_idx_path = "/sys/class/infiniband/%s/iov/%s/ports/1/pkey_idx" % (
            self._ibdev_name, self._dev_addr)

        user_pkey_idx = ibdev_find_pkey_idx(self._ibdev_name,
                                      self._pkey)
        with open(os.path.join(pkey_idx_path, '0'), 'w') as f:
            f.write(user_pkey_idx)

        def_pkey_idx = ibdev_find_pkey_idx(self._ibdev_name, 0xffff)
        with open(os.path.join(pkey_idx_path, '1'), 'w') as f:
            f.write(def_pkey_idx)

    def _unset_pkey(self):
        pkey_idx_path = "/sys/class/infiniband/%s/iov/%s/ports/1/pkey_idx" % (
            self._ibdev_name, self._dev_addr)

        with open(os.path.join(pkey_idx_path, '0'), 'w') as f:
            f.write('none')

        with open(os.path.join(pkey_idx_path, '1'), 'w') as f:
            f.write('none')

    def _allow_host_pkeys(self):
        device_path = "/sys/class/infiniband/{0}".format(self._ibdev_name)
        num_ports = len(os.listdir(os.path.join(device_path, "ports")))

        for port in xrange(1, num_ports + 1):
            pkeys_path = os.path.join(device_path, "ports", str(port),
                                      "pkeys")
            pkey_idx_path = os.path.join(device_path, "iov", self._dev_addr,
                                         "ports", str(port), "pkey_idx")

            idx = 0
            for pkey_idx in os.listdir(pkeys_path):
                p = os.path.join(pkeys_path, pkey_idx)
                with open(p) as f:
                    try:
                        this_pkey_value = int(f.read().strip(), 0)
                    except ValueError:
                        continue

                    if this_pkey_value:
                        with open(os.path.join(pkey_idx_path, str(idx)), 'w') as f:
                            f.write(pkey_idx)
                        idx+=1

    def _clear_host_pkeys(self):
        device_path = '/sys/class/infiniband/{0}'.format(self._ibdev_name)
        num_ports = len(os.listdir(os.path.join(device_path, 'ports')))

        for port in xrange(1, num_ports+1):
            pkey_idx_path = os.path.join(device_path, 'iov', self._dev_addr,
                                         'ports', str(port), 'pkey_idx')

            for pkey_idx in os.listdir(pkey_idx_path):
                this_pkey_idx_path = os.path.join(pkey_idx_path, pkey_idx)
                with open(this_pkey_idx_path, 'w') as f:
                    f.write('none')


class NetNameSpace(TrackableObject):
    def __init__(self, name):
        self._name = name

    def __repr__(self):
        return '{cls}(name={name})'.format(cls = self.__class__.__name__,
                                           name = self._name)

    def dump_args(self):
        return {'name': self._name}

    def create(self):
        self.run(["ip", "netns", "add", self._name])
        self._log_create()
        return self

    def delete(self):
        self.run(["ip", "netns", "delete", self._name])

class NetPort(TrackableObject):
    def __init__(self, number):
        self._number = number

    def __repr__(self):
        return '{cls}(number={number})'.format(cls = self.__class__.__name__,
                                               number = self._number)

    def dump_args(self):
        return {'number': self._number}

    def create(self):
        self._log_create()
        return self

    def delete(self):
        pass

    @property
    def number(self):
        return self._number

    @classmethod
    def range_find_free(cls, tracker, min_port, max_port):
        alloc = sorted([ port._number for
                         port, _ in tracker.list_objs(cls.__name__)  if
                         port._number >= min_port ])

        for i in xrange(min_port, max_port):
            if i - min_port >= len(alloc):
                return cls(i)

            if alloc[i - min_port] != i:
                return cls(i)
        else:
            raise ValueError('no free port')

class IPTableRule(TrackableObject):
    def __init__(self, rule, chain, table=None, mode='append', rulenum=0):
        self._rule = rule
        self._chain = chain
        self._table = table
        self._mode = mode
        self._rulenum = rulenum

    def __repr__(self):
        return '{cls}(rule={rule}, chain={chain}, table={table})'.format(
            cls = self.__class__.__name__,
            rule = self._rule,
            chain = self._chain,
            table = self._table
        )

    def dump_args(self):
        return {'rule': self._rule,
                'chain': self._chain,
                'table': self._table}

    def create(self):
        self._log_create()
        if not self.rule_exist(self._rule, self._chain, self._table):
            self.run(["iptables"] +
                     self._table_arg(self._table) +
                     self._mode_arg(self._mode, self._rulenum, self._chain) +
                     self._rule.split())
        return self

    def delete(self):
        if self.rule_exist(self._rule, self._chain, self._table):
            self.run(["iptables"] +
                     self._table_arg(self._table) +
	             ["-D", self._chain] +
                     self._rule.split())

    @staticmethod
    def _table_arg(table):
        if table:
            return ["-t", table]
        else:
            return []

    @staticmethod
    def _mode_arg(mode, rulenum, chain):
        if mode == 'append':
            return ["-A", chain]
        elif mode  == 'insert':
            return ["-I", chain, str(rulenum)]

    @classmethod
    def rule_exist(cls, rule, chain, table = None):
        try:
            cls.run(["iptables"] +
                    cls._table_arg(table) +
                    ["-C", chain] +
                    rule.split(), True, True)

            return True
        except subprocess.CalledProcessError:
            return False

class OVSCookie(TrackableObject):
    def __init__(self, value, bridge, netns=None):
        self._value = value
        self._bridge = bridge
        self._netns = netns

    def __repr__(self):
        return '{cls}(value={value}, bridge={bridge}, netns={netns})'.format(
            cls=self.__class__.__name__,
            value=self._value,
            bridge=self._bridge,
            netns=self._netns,
        )

    def dump_args(self):
        return {'value': self._value,
                'bridge': self._bridge,
                'netns': self._netns
        }

    @property
    def value(self):
        return self._value

    def create(self):
        self._log_create()
        return self

    def delete(self):
        OVSBridge(self._bridge, self._netns).del_flows(cookie='{0}/-1'.format(
                self._value))

class PidDaemon(TrackableObject):
    def __init__(self, pid_file):
        self._pid_file = pid_file

    def __repr__(self):
        return '{cls}(pid_file={pid_file})'.format(cls = self.__class__.__name__,
                                               pid_file = self._pid_file)

    def dump_args(self):
        return {'pid_file': self._pid_file}

    def create(self):
        self._log_create()
        return self

    def delete(self):
        if os.path.isfile(self._pid_file):
            with open(self._pid_file, 'r') as f:
                pid = f.read()
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except (OSError ,ValueError):
                    pass
            os.remove(self._pid_file)

class NetDev(TrackableObject):
    @classmethod
    def prefix_cleanup(cls, prefix, *args, **kwargs):
        count = 0

        for dev_id in cls._find_used_dev_ids(prefix):
            cls(cls._dev_name_from_id(prefix,
                                        dev_id)).delete()
            count+=1

        return count

    @classmethod
    def prefix_find_free(cls, prefix, *args, **kwargs):
        return cls(cls._find_free_dev_name(prefix), *args,
                   **kwargs)

    def __repr__(self):
        return '{cls}(name={name}, netns={netns})'.format(cls = self.__class__.__name__,
                                                          name = self._name,
                                                          netns = str(self._netns))

    def __init__(self, name, netns=None):
        self._name = name
        self._netns = netns

    def run_in_ns(self, cmd, quiet=False, err_quiet=False):
        prefix = []
        if self._netns:
            prefix = ['ip', 'netns', 'exec', self._netns]

        return self.run(prefix + cmd, quiet, err_quiet)


    def run_output_in_ns(self, cmd, mixed=False):
        prefix = []
        if self._netns:
            prefix = ['ip', 'netns', 'exec', self._netns]

        return self.run_output(prefix + cmd, mixed)

    def set_netns(self, netns):
        self._netns = netns
        self.run(['ip', 'link', 'set', self._name, 'netns', netns])

    def set_mtu(self, mtu):
        self.run_in_ns(['ip', 'link', 'set', self._name, 'mtu', str(mtu)])

    def add_ip(self, ip, bits):
        self.run_output_in_ns(['ip', 'addr', 'add', '{0}/{1}'.format(ip, bits),
                               'dev', self._name], mixed=True)

    def add_route(self, networkbits, gateway=None):
        cmd = ["ip", "route", "add", networkbits]
        if gateway:
            cmd += ["via", gateway]

        self.run_in_ns(cmd + ["dev", self._name])

    def add_ip_idemp(self, ip, bits):
        try:
            self.add_ip(ip, bits)
        except subprocess.CalledProcessError as err:
            if err.output != "RTNETLINK answers: File exists\n":
                raise

    def set_hwaddr(self, hwaddr):
        self.run_in_ns(["ip", "link", "set", self._name, "address", hwaddr])

    def enable(self):
        self.run_in_ns(['ip', 'link', 'set', self._name, 'up'])

    def dump_args(self):
        return {'name': self._name, 'netns': self._netns}

    def delete(self):
        self.run_in_ns(['ip', 'link', 'del', self._name])

    @property
    def name(self):
        return self._name

    @classmethod
    def _dev_name_from_id(cls, prefix, dev_id):
        return '{0}{1}'.format(prefix, dev_id)

    @classmethod
    def _id_from_dev_name(cls, prefix, dev_name):
        if not prefix:
            raise ValueError('NetDev prefix cannot be empty')

        match = re.match(r"^{0}(\d+)$".format(prefix), dev_name)
        if match:
            return int(match.group(1))
        else:
            return -1

    @classmethod
    def _find_used_dev_ids(cls, prefix):
        return [  cls._id_from_dev_name(prefix, dev_name)
                  for dev_name in os.listdir("/sys/devices/virtual/net")
                  if cls._id_from_dev_name(prefix, dev_name) != -1 ]

    @classmethod
    def _find_free_dev_id(cls, prefix):
        used_ids = cls._find_used_dev_ids(prefix)

        for pos, dev_id in enumerate(sorted(used_ids)):
            if (pos < dev_id):
                return pos

        return len(used_ids)

    @classmethod
    def _find_free_dev_name(cls, prefix):
        dev_id = cls._find_free_dev_id(prefix)
        return cls._dev_name_from_id(prefix, dev_id)

class OVSBridge(NetDev):
    def __init__(self, name, netns=None):
        super(OVSBridge, self).__init__(name, netns)
        self._defer = False
        self._deferred_flows = []

    def create(self):
        self._log_create()
        self.run_in_ns(['ovs-vsctl', '--may-exist', 'add-br', self._name])
        # Drop the ovs default flow
        # TODO: Is it possible to create an ovs bridge without this
        # rule ?
        self.run_in_ns(['ovs-ofctl', 'del-flows', '-OOpenFlow13', self._name,
                        '--strict', 'priority=0'])
        return self

    def set_hwaddr(self, hwaddr):
        self.run_in_ns(['ovs-vsctl', 'set', 'bridge', self._name,
                        'other-config:hwaddr={0}'.format(hwaddr)])

    def defer(self, enable=True):
        if not enable and self._deferred_flows:
            self.push_flows()

        self._defer = enable

    def add_flow(self, match, action, table=0, priority=1000, cookie=None):
        flow = self._format_flow(match, action, table, priority, cookie)

        if self._defer:
            self._deferred_flows.append(flow)
        else:
            self.run_in_ns(["ovs-ofctl", "add-flow", "-OOpenFlow13",
                            self._name, flow])

    def push_flows(self):
        fd, flowfile = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as f:
            f.write('\n'.join(self._deferred_flows))
        self.run_in_ns(["ovs-ofctl", "add-flows" , "-OOpenFlow13",
                        self._name, flowfile])
        self._deferred_flows = []

    def del_flows(self, match=None, action=None, table=None, priority=None, cookie=None):
        flow = self._format_flow(match, action, table, priority, cookie)

        self.run_in_ns(["ovs-ofctl", "del-flows",  "-OOpenFlow13", self._name, flow])

    def create_group(self, group_id):
        self.run_in_ns(["ovs-ofctl", "add-group", "-OOpenFlow13",
                  self._name,
                  'group_id={0},type=all'.format(group_id)])

    def set_group_members(self, group_id, members):
        bucket=''
        for m in members:
            bucket += ',bucket=output:{0}'.format(m)

        self.run_in_ns(["ovs-ofctl", "mod-group", "-OOpenFlow13",
                  self._name,
                  'group_id={0},type=all'.format(group_id) + bucket])

    def add_port(self, dev_name):
        self.run_in_ns(["ovs-vsctl", "--may-exist", "add-port",
                        self._name, dev_name])
        return self.get_port_id(dev_name)

    def del_port(self, dev_name):
        self.run_in_ns(["ovs-vsctl", "del-port", self._name, dev_name])

    def get_port_id(self, dev_name):
        match = re.search(r'(\d+)\({0}\)'.format(dev_name),
                          self.run_output_in_ns(["ovs-ofctl", "show",
                                                 self._name]))
        if match:
            return int(match.group(1))
        else:
            raise KeyError('{0} not found on {1}'.format(dev_name, self._name))

    def add_tunnel(self, tun_name, tun_type, host, tun_id):
        self.run(["ovs-vsctl", "add-port", self._name,
                  tun_name, "--", "set", "interface", tun_name,
                  "type={0}".format(tun_type),
                  "options:remote_ip={0}".format(resolve_host(host)),
                  "options:key={0}".format(tun_id)])

        return self.get_port_id(tun_name)

    def delete(self):
        self.run_in_ns(['ovs-vsctl', '--if-exist', 'del-br', self._name])

    @staticmethod
    def _format_flow(match,action,table, priority, cookie):
        flow = '{table}{priority}{cookie}{match}{action}'.format(
            table='table={0},'.format(table) if table else '',
            priority='priority={0},'.format(priority) if priority is not None else '',
            match='{0},'.format(match) if match else '',
            cookie='cookie={0},'.format(cookie) if cookie is not None else '',
            action='actions={0}'.format(action) if action else '')

        if flow.endswith(','):
            flow=flow[:-1]

        return flow

class VEth(NetDev):
    def __init__(self, name, peername=None, netns=None):
        super(VEth, self).__init__(name, netns)

        if not peername:
            peername = name+'b'
        self._peername = peername

    def create(self):
        self._log_create()
        self.run_in_ns(['ip', 'link', 'add', self._name,
                        'type', 'veth', 'peer', 'name', self._peername])

        return self, self.__class__(self._peername, self._name, self._netns)


class TAP(NetDev):
    def __init__(self, name, netns=None):
        super(TAP, self).__init__(name, netns)

    def create(self):
        self._log_create()
        self.run_in_ns(['ip', 'tuntap', 'add', self._name, 'mode',
                        'tap'])

        return self

    def connect(self, bridge_name):
        subprocess.check_call(["ip", "link", "set", self._name, "master",
                               bridge_name])


class IBVFType(object):
    MLX4 = 1
    MLX5 = 2

def make_mask(num_bits):
    "return a mask of num_bits as a long integer"
    return ((2<<num_bits-1) - 1) << (32 - num_bits)

def dotted_quad_to_num(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('!L', socket.inet_aton(ip))[0]

def num_to_dotted_quad(addr):
    "convert long int to dotted quad string"
    return socket.inet_ntoa(struct.pack('!L', addr))

def get_ip_on_network(netaddr, offset):
    return num_to_dotted_quad(dotted_quad_to_num(netaddr) + offset)

def resolve_host(host):
    data = socket.gethostbyname_ex(host)
    return data[2][0]

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
    suffix = ("{0:x}".format(num)).zfill(mac_suffix_len(prefix))
    suffix = ':'.join(
        suffix[i:i+2] for i in xrange(0, len(suffix), 2))
    return prefix + ':' + suffix

def bridge_exists(brname):
    """ returns whether brname is a bridge (linux or ovs) """
    return (os.path.exists('/sys/devices/virtual/net/{0}/bridge/'.format(brname)) or
           ovs_bridge_exists(brname))

def ovs_bridge_exists(brname):
    match = re.search(r'Bridge {0}'.format(brname),
                  subprocess.check_output(["ovs-vsctl", "show"]))
    if match:
        return True
    else:
        return False

def pci_enable_driver(dev_addr, driver_name):
    device_path = os.path.join("/sys/bus/pci/devices/", dev_addr)
    driver_path = os.path.join("/sys/bus/pci/drivers", driver_name, 'new_id')

    with open(os.path.join(device_path, 'vendor'), 'r') as f:
        vendor_id=f.read()

    with open(os.path.join(device_path, 'device'), 'r') as f:
        device_id=f.read()

    with open(driver_path, 'w') as f:
        f.write('{0} {1}'.format(vendor_id, device_id))

def ibdev_enable_vf_driver(ibdev_name, driver_name):
    device_path = "/sys/class/infiniband/%s/device/virtfn0" % (ibdev_name)
    dev_addr = os.path.basename(os.readlink(device_path))
    pci_enable_driver(dev_addr, driver_name)

def ibdev_find_pkey_idx(device_name, pkey_value):
    pkey_idx_path = "/sys/class/infiniband/%s/ports/1/pkeys" % (
        device_name)

    for pkey_idx in os.listdir(pkey_idx_path):
        this_pkey_idx_path = os.path.join(pkey_idx_path, pkey_idx)
        with open(this_pkey_idx_path) as f:
            try:
                this_pkey_value = int(f.read().strip(), 0)
            except ValueError:
                continue

            if this_pkey_value & 0x7fff == pkey_value & 0x7fff:
                return pkey_idx

    raise NetworkSetupError('pkey %s not found on device %s' % (
        hex(pkey_value), device_name))

def ibdev_get_guid(ibdev_name):
    return subprocess.check_output(['ibstat', '-p',
                                    ibdev_name]).splitlines()[0]


def guid_hex_to_col(guid):
    res = ':'.join(guid[c:c+2] for c in xrange(2, len(guid), 2))
    return res
