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

import socket, struct, atexit, signal
import os, re, shelve, json, logging, subprocess
from abc import ABCMeta, abstractmethod

class Tracker(object):
    _trackable = {}
    @classmethod
    def register_trackable(cls, name, trackable_class):
        cls._trackable[name] = trackable_class

    def __init__(self, store_file):
        self._tracked_objs = shelve.open(store_file)
        for track_key, _ in self.list_objs():
            logging.info('Tracker loaded obj {0} from {1}'.format(
                    track_key, store_file))

        logging.info('Tracker index is at {0}'.format(
                self._track_index))

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
                    logging.info('Deleted {0}'.format(obj))
                else:
                    logging.warning('Deleted leftover {0}'.format(obj))
            except Exception as e:
                logging.warning('Failed to delete {0}: {1} '.format(obj, e))
                pass

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

    def __init__(self):
        pass

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
        logging.info('Created {0}'.format(self))

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

class NetNameSpace(TrackableObject):
    def __init__(self, name):
        self._name = name

    def __repr__(self):
        return '{cls}(name={name})'.format(cls=self.__class__.__name__,
                                           name=self._name)

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
        return '{cls}(number={number})'.format(cls=self.__class__.__name__,
                                               number=self._number)

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
    def __init__(self, rule, chain, table=None, mode='A'):
        self._rule = rule
        self._chain = chain
        self._table = table
        self._mode = mode

    def __repr__(self):
        return '{cls}(rule={rule}, chain={chain}, table={table})'.format(
            cls=self.__class__.__name__,
            rule=self._rule,
            chain=self._chain,
            table=self._table
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
                     ["-{0}".format(self._mode), self._chain] +
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

    @classmethod
    def rule_exist(cls, rule, chain, table = None):
        if table:
            table_args = ["-t", table]
        else:
            table_args = []

        try:
            cls.run(["iptables"] +
                    cls._table_arg(table) +
                    ["-C", chain] +
                    rule.split(), True, True)

            return True
        except subprocess.CalledProcessError as err:
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
        OVSBridge(self._bridge, self._netns).del_flows(cookie='{0}/-1'.format(self._value))

class PidDaemon(TrackableObject):
    def __init__(self, pid_file):
        self._pid_file = pid_file

    def __repr__(self):
        return '{cls}(pid_file={pid_file})'.format(cls=self.__class__.__name__,
                                           pid_file=self._pid_file)

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
    def prefix_cleanup(cls, prefix):
        count = 0

        for dev_id in cls._find_used_dev_ids(prefix):
            cls(cls._dev_name_from_id(prefix,
                                        dev_id)).delete()
            count+=1

        return count

    @classmethod
    def prefix_find_free(cls, prefix, **kwargs):
        return cls(cls._find_free_dev_name(prefix),
                   kwargs)

    def __repr__(self):
        return '{cls}(name={name}, netns={netns})'.format(cls=self.__class__.__name__,
                                                          name=self._name,
                                                          netns=str(self._netns))

    def __init__(self, name, netns):
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
        super(self.__class__, self).__init__(name, netns)

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

    def add_flow(self, match, action, table=0, priority=1000, cookie=None):
        flow = self._format_flow(match, action, table, priority, cookie)

        self.run_in_ns(["ovs-ofctl", "add-flow", "-OOpenFlow13", self._name, flow])

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
        super(self.__class__, self).__init__(name, netns)

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
        super(self.__class__, self).__init__(name, netns)

    def create(self):
        self._log_create()
        self.run_in_ns(['ip', 'tuntap', 'add', self._name, 'mode',
                        'tap'])

        return self

def make_mask(num_bits):
    "return a mask of num_bits as a long integer"
    return ((2L<<num_bits-1) - 1) << (32 - num_bits)

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
