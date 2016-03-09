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

import os
import time
import socket
import sys
import json
import select
import re
import subprocess
import shlex
import atexit
import threading
import errno
import base64
import tempfile
import shutil
import yaml
import logging

from pcocc.scripts import click
from ClusterShell.NodeSet  import RangeSet
from Backports import subprocess_check_output
from Error import PcoccError
from Config import Config

lock = threading.Lock()

def try_kill(sproc):
    try:
        sproc.kill()
    except OSError:
        pass

class InvalidImageError(PcoccError):
    """Exception raised when the image file cannot be handled
    """
    def __init__(self, error):
        super(InvalidImageError, self).__init__('Unable to handle image: '
                                                + error)

class ImageSaveError(PcoccError):
    """Exception raised when the image file cannot be saved
    """
    def __init__(self, error):
        super(ImageSaveError, self).__init__('Unable to save image: '
                                                + error)

class CheckpointError(PcoccError):
    """Exception raised when the VM cannot be checkpointed
    """
    def __init__(self, error):
        super(CheckpointError, self).__init__('Unable to complete VM checkpoint: '
                                                + error)

class HypervisorError(PcoccError):
    """Exception raised when the hypervisor reports an error
    """
    def __init__(self, error):
        super(HypervisorError, self).__init__('VM execution error: '
                                              + error)

class AgentError(PcoccError):
    """Exception raised when the agent reports an error
    """
    def __init__(self, error):
        super(AgentError, self).__init__('Guest agent failure: '
                                              + error)

MAX_QMP_JSON_SIZE=32768

class RemoteMonitor(object):
    def __init__(self, vm):
        self.s_mon = Config().hyp.socket_connect(vm, 'monitor_socket')

        data = self.read_raw(MAX_QMP_JSON_SIZE)
        self.send_raw('{ "execute": "qmp_capabilities" }')
        data = self.read_raw(MAX_QMP_JSON_SIZE)

    def send_raw(self, data):
        return os.write(self.s_mon.stdin.fileno(), data)

    def read_raw(self, size):
        return os.read(self.s_mon.stdout.fileno(), size)

    def quit(self):
        mon_quit_cmd = ('{"execute": "quit", "arguments":{'
                        '} }\n\n')
        self.send_raw(mon_quit_cmd)
        data = self.read_raw(MAX_QMP_JSON_SIZE)

    def stop(self):
        mon_stop_cmd = ('{"execute": "stop", "arguments":{'
                        '} }\n\n')
        self.send_raw(mon_stop_cmd)
        self.read_raw(MAX_QMP_JSON_SIZE)

    def resume(self):
        mon_resume_cmd = ('{"execute": "cont", "arguments":{'
                        '} }\n\n')
        self.send_raw(mon_resume_cmd)
        self.read_raw(MAX_QMP_JSON_SIZE)

    def dump(self, dump_file):
        mon_dump_cmd = ('{"execute": "dump-guest-memory", "arguments":{ '
                        '"paging": true, '
                        '"protocol": "file:%s"'
                        '} }\n\n'  % dump_file)
        self.send_raw(mon_dump_cmd)

        while True:
            data = self.read_raw(MAX_QMP_JSON_SIZE)
            for line in data.splitlines():
                ret = json.loads(line)
                if "error" in ret:
                    raise ImageSaveError(ret["error"]["desc"])
                elif "event" in ret:
                    continue
                elif "return" in ret:
                    return
                else:
                    raise ImageSaveError('unexpected output from qemu: '
                                         '%s , %s' % (line, r))
            time.sleep(2)

    def system_reset(self):
        mon_reset_cmd = ('{"execute": "system_reset", "arguments":{'
                        '} }\n\n')
        self.send_raw(mon_reset_cmd)
        self.read_raw(MAX_QMP_JSON_SIZE)

    def human_monitor_cmd(self, human_cmd):
        mon_human_cmd = ('{"execute": "human-monitor-command", "arguments":{'
                         '"command-line": "%s"} }\n\n' % human_cmd)
        self.send_raw(mon_human_cmd)
        raw_data = self.read_raw(16384)
        try:
            data = json.loads(raw_data)
        except:
            raise PcoccError("Unable to parse output from qemu: " + raw_data)

        try:
            return data["return"]
        except KeyError:
            pass

        try:
            raise PcoccError("Qemu monitor error: " + data["error"]["desc"])
        except KeyError:
            raise PcoccError("Unable to parse output from qemu: " + raw_data)

    def start_migration(self, dest_mem_file):
        mon_speed_cmd = ('{"execute": "migrate_set_speed", "arguments":{'
                         '"value": 4294967296'
                         '} }\n\n')
        self.send_raw(mon_speed_cmd)
        self.read_raw(MAX_QMP_JSON_SIZE)

        mon_save_cmd = ('{"execute": "migrate", "arguments":{'
                        '"uri": "exec:lzop > %s"'
                        '} }\n\n'%(dest_mem_file))
        self.send_raw(mon_save_cmd)
        self.read_raw(MAX_QMP_JSON_SIZE)

    def snapshot_image(self, dest_image_file):
        #TODO
        pass

    def query_migration(self):
        mon_query_cmd = ('{"execute": "query-migrate" }\n\n')
        self.send_raw(mon_query_cmd)
        return self.read_raw(MAX_QMP_JSON_SIZE)

    def close_monitor(self):
        self.s_mon.terminate()
        self.s_mon.wait()

class Qemu(object):
    def __init__(self):
        self.qemu_bin = 'qemu-system-x86_64'

    def _do_lock_image(self, drive, key):
        batch = Config().batch

        # Not yet allocated
        if key is None:
            return yaml.dump(
                {'batchid': batch.batchid, 'count': 1}), True

        key = yaml.safe_load(key)
        if key['batchid'] == batch.batchid:
            key['count'] += 1
            if drive['mmp'] == 'cluster':
                return yaml.dump(key), True
            else:
                raise HypervisorError('drive file is already used in this cluster')

        joblist = batch.list_all_jobs()
        if not key['batchid'] in joblist:
            # Expired job, allocate anyways
            return yaml.dump(
                {'batchid': batch.batchid, 'count': 1}), True
        else:
            raise HypervisorError('drive file is already used in '
                                  'cluster {0}'.format(key['batchid']))

    def _do_unlock_image(self, key):
        batch = Config().batch
        # Not yet allocated
        if key is None:
            logging.warning('Lock file unexpectdly removed')
            return None, False

        key = yaml.safe_load(key)

        if key['batchid'] != batch.batchid:
            logging.warning('Lock file unexpectedly acquired by'
                            'another cluster')
            return yaml.dump(key), False

        key['count'] -= 1
        if key['count'] == 0:
            return yaml.dump(key), True
        else:
            return yaml.dump(key), False

    def _unlock_image(self, path):
        batch = Config().batch

        ret = batch.atom_update_key('global/user',
                                    'mmp/' + path,
                                    self._do_unlock_image)
        if ret:
            batch.delete_key('global/user',
                             'mmp/' + path)


    def run(self, vm, ckpt_dir=None):
        batch = Config().batch

        self._set_vm_state('topology',
                           'gathering topological information',
                           None, vm.rank)

        # VM may use all cores allocated for the job
        # Disable batch manager affinity
        if vm.full_node:
            with open(os.devnull, 'w') as devnull:
                subprocess.check_call(["taskset", "-p",
                                       "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                                       str(os.getpid())],
                                      stdout=devnull, stderr=devnull)

        num_cores = batch.num_cores
        mem_per_core = batch.mem_per_core
        coreset = batch.coreset
        total_mem = mem_per_core * num_cores

        # Recompute num_cores which is more than what
        # was allocated for our task
        if vm.full_node:
            num_cores = len(batch.coreset)


        cores_on_numa = {}

        # Find out hwloc version
        # Python hwloc bindings would be nice
        try:
            version_string = subprocess_check_output(['lstopo-no-graphics', '--version'])
        except (OSError, subprocess.CalledProcessError) as err:
            raise HypervisorError('hwloc (lstopo-no-graphics) is not available')

        match = re.search(r'lstopo-no-graphics (\d+)\.(\d+)', version_string)
        hwloc_version = (int(match.group(1)), int(match.group(2)))
        if hwloc_version[0] == 1 and hwloc_version[1] < 9:
            hwloc_force_flags = ''
        else:
            hwloc_force_flags = '-f '

        if len(coreset) > 1:
            (_, topology_cache_file) = tempfile.mkstemp()
            subprocess.check_call(shlex.split(
                    'lstopo-no-graphics --of xml --no-io ' +
                    hwloc_force_flags +
                    topology_cache_file))
            topology_cache_args = ['--input', topology_cache_file]
        else:
            topology_cache_args = []

        if vm.emulator_cores >= num_cores:
            logging.warning('VM {0} was only given {1} cores, '
                            'but its template requires {2} for the emulator. '
                            'Reducing emulator cores to {3}'.format(
                    vm.rank, num_cores, vm.emulator_cores,
                    num_cores - 1))
            emulator_cores = num_cores - 1
        else:
            emulator_cores = vm.emulator_cores

        emulator_coreset  = coreset[:emulator_cores]
        coreset = coreset[emulator_cores:]

        # Recompute num_cores to exclude emulator_cores
        num_cores = len(coreset)

        for core_id in coreset:
            numa_node = int(subprocess_check_output(['hwloc-calc',
                                                     'Core:%d' % (int(core_id)),
                                                     '-I', 'NUMANode'] +
                                                    topology_cache_args))
            cores_on_numa.setdefault(numa_node,
                                     RangeSet()).update(RangeSet(str(core_id)))
        if vm.qemu_bin:
            cmdline = [ vm.qemu_bin ]
        else:
            cmdline = [ self.qemu_bin ]

        version_string = subprocess_check_output(cmdline + ['--version'])
        match = re.search(r'version (\d+\.\d+)', version_string)
        qemu_version = float(match.group(1))

        if ckpt_dir:
            dest_mem_file = self.checkpoint_mem_file(vm, ckpt_dir)

            cmdline += ['-incoming',
                        "exec: lzop -dc %s" % (dest_mem_file)]

        # Basic machine definition
        cmdline += ['-machine', 'type=pc,accel=kvm']
        cmdline += ['-nographic']
        cmdline += ['-rtc', 'base=utc']
        cmdline += ['-cpu', 'host']

        self._set_vm_state('temporary-disk',
                           'creating disk file',
                           None, vm.rank)

        # Image
        # Emulate -snapshot with qemu-img so that we
        # may save the image later if needed
        snapshot_path = batch.get_vm_state_path(vm.rank, 'image_snapshot')

        if not vm.image_dir is None:
            if ckpt_dir:
                image_path = self.checkpoint_img_file(vm, ckpt_dir)
            else:
                image_path = vm.image_path

            with open(os.devnull, 'w') as devnull:
                try:
                    subprocess.check_call(['qemu-img', 'create',
                                           '-f', 'qcow2',
                                        '-b', image_path, snapshot_path],
                                          stdout=devnull)
                except (OSError, subprocess.CalledProcessError) as err:
                    raise InvalidImageError('failed to create temporary disk')


            atexit.register(os.remove, snapshot_path)

            cmdline += ['-device', 'virtio-blk-pci,'
                        'drive=bootdisk,addr=06.0']

            cmdline += ['-drive', 'id=bootdisk,'
                        'file=%s,index=0,if=none,'
                        'format=qcow2,cache=%s,aio=threads' %
                        (snapshot_path, vm.disk_cache)]

        for i, drive in enumerate(vm.persistent_drives):
            path =  Config().resolve_path(drive, vm)
            if vm.persistent_drives[drive]['mmp']:
                spath = os.path.realpath(path)
                spath = spath[1:]
                spath = spath.replace('_', '__')
                spath = spath.replace('/', '_')
                batch.atom_update_key('global/user',
                                      'mmp/' + spath,
                                      self._do_lock_image,
                                      vm.persistent_drives[drive])
                atexit.register(self._unlock_image, spath)

            cmdline += ['-object',
                        'iothread,id=ioth-datadisk{0}'.format(i)]
            cmdline += ['-device',
                        'virtio-blk-pci,id=ioth-datadisk{0},multifunction=on,'
                        'drive=datadisk{0},addr={1:02d}.{2}'.format(
                            i, i/3+7, i%3)]
            cmdline += ['-drive',
                        'file={0},cache={1},id=datadisk{2},format=raw,'
                        'if=none'.format(
                        path,
                        vm.persistent_drives[drive]['cache'],
                        i)]

        if not '-boot' in vm.custom_args:
            cmdline += ['-boot', 'c']

        # Memory
        total_mem = total_mem - (total_mem % len(cores_on_numa))
        cmdline += ['-m', str(total_mem)]

        # CPU topology
        #
        if qemu_version > 2:
            cmdline += ['-smp', 'threads=1,cores=1,sockets=%d' %
                        (num_cores)]
        else:
            cmdline += ['-smp', '%d,sockets=%d' %
                        (num_cores, len(cores_on_numa))]

        start_cpu = 0
        virt_to_phys_coreid = []
        for i, numa_node in enumerate(sorted(cores_on_numa)):
            numa_coreset = cores_on_numa[numa_node]
            virt_to_phys_coreid += numa_coreset
            ncores_on_node = len(numa_coreset)
            # TODO: adjust the memory for irregular NUMA nodes
            if qemu_version > 2:
                cmdline += ['-numa', 'node,memdev=ram-%d,cpus=%d-%d,nodeid=%d' % (
                        i,
                        start_cpu,
                        start_cpu + ncores_on_node - 1,
                        i)]

                cmdline += ['-object', 'memory-backend-ram,size=%dM,policy=preferred,prealloc=yes,'
                            'host-nodes=%d,id=ram-%d' % (
                                total_mem / len(cores_on_numa),
                                numa_node, i)]

            else:
                cmdline += ['-numa', 'node,cpus=%d-%d,nodeid=%d' % (
                        start_cpu,
                        start_cpu + ncores_on_node - 1,
                        i)]
            start_cpu += ncores_on_node

        # Ethernet interfaces
        try:
            # Check if the vhost device is usable
            f =  open('/dev/vhost-net', 'r+')
        except:
            vhost_string = ''
        else:
            f.close()
            vhost_string = ',vhost=on'

        for i, net in enumerate(sorted(vm.eth_ifs.iterkeys(),
                                      key=vm.networks.index)):
            tap_name = vm.eth_ifs[net]['tap']
            hwaddr = vm.eth_ifs[net]['hwaddr']

            if vm.nic_model:
                model = vm.nic_model
            else:
                model = 'virtio-net'

            cmdline += ['-netdev',
                        'tap,ifname=%s,script=no,downscript=no,id=tap_%s%s' % (
                            tap_name, net , vhost_string),
                        '-device',
                        '%s,netdev=tap_%s,id=%s,'
                        'mac=%s'%(model,net,net,hwaddr)]

        # VFIO interfaces
        for i, net in enumerate(sorted(vm.vfio_ifs.iterkeys(),
                                      key=vm.networks.index)):
            vfio_name = vm.vfio_ifs[net]['vf_name']

            cmdline += ['-device',
                        'vfio-pci,host=%s' % (vfio_name)]

        # Mount points
        for mount in vm.mount_points:
            host_path = vm.mount_points[mount]['path']
            host_path = Config().resolve_path(host_path, vm)

            readonly = vm.mount_points[mount].get('readonly', False)
            if readonly:
                readonly_string=',readonly'
            else:
                readonly_string=''

            cmdline += ['-fsdev', 'local,id=%s,path=%s,security_model=none%s'%
                        (mount, host_path, readonly_string)]

            cmdline += ['-device', 'virtio-9p-pci,fsdev=%s,mount_tag=%s'%
                        (mount, mount)]

        # Monitor
        socket_path = batch.get_vm_state_path(vm.rank, 'monitor_socket')
        cmdline += ['-qmp', 'unix:%s,server,nowait' % (socket_path)]

        # Serial Console
        socket_path = batch.get_vm_state_path(vm.rank, 'qemu_console_socket')
        cmdline += ['-chardev',
                    'socket,id=charserial0,'
                    'path=%s,server,nowait' % (socket_path),
                    '-device', 'isa-serial,chardev=charserial0,id=serial0']

        # Custom serial ports
        if len(vm.serial_ports) > 0:
            nserials = len(vm.serial_ports)
            cmdline += [ '-device',
                        'virtio-serial,id=ser0,max_ports=%d' % (nserials+1) ]
            for i, serial in enumerate(vm.serial_ports):
                serialid = i + 1
                socket_path = batch.get_vm_state_path(vm.rank,
                                                      'serial_%s_socket'%
                                                      serial)
                cmdline += [ '-chardev', 'socket,id=charserial%d,'
                            'path=%s,server,nowait' % (serialid, socket_path)]
                cmdline += [ '-device',
                            'virtserialport,chardev=charserial%d,'
                            'id=ioserial%d,name=%s' %
                            (serialid, serialid, serial)]

        try:
            user_data_file = batch.get_vm_state_path(vm.rank, 'user-data')
            meta_data_file = batch.get_vm_state_path(vm.rank, 'meta-data')
            iso_file = batch.get_vm_state_path(vm.rank, 'cloud_seed')

            f = open(meta_data_file, 'w')
            f.write('instance-id: pcocc-deploy\n')
            f.write('local-hostname: vm%d\n' % (vm.rank))
            f.close()

            if vm.user_data:
                shutil.copyfile(Config().resolve_path(vm.user_data, vm),
                                user_data_file)
            else:
                shutil.copyfile('/dev/null', user_data_file)

            with open(os.devnull, 'w') as devnull:
                subprocess.check_call(['genisoimage',
                                       '-output', iso_file, '-volid', 'cidata', '-joliet',
                                       '-rock', user_data_file,
                                       meta_data_file], stdout=devnull, stderr=devnull)

            cmdline += [ '-drive',
                         'file={0},index=3,media=cdrom'.format(iso_file)]

        except (OSError, IOError, subprocess.CalledProcessError) as err:
            raise HypervisorError('unable to generate cloud-init iso: '
                                  + str(err))

        self._set_vm_state('qemu-start',
                           'starting qemu',
                           None, vm.rank)

        if vm.custom_args:
            cmdline += vm.custom_args


        if emulator_coreset:
            emulator_phys_coreset = [ subprocess_check_output(
                    ['hwloc-calc', '--po', '-I', 'PU', 'Core:%s' % core]).strip()
                                      for core in emulator_coreset ]
            cmdline = ['taskset',
                       '-c', ','.join(emulator_phys_coreset)] + cmdline

        qemu_pid = os.fork()
        if qemu_pid == 0:
            os.execvp(cmdline[0], cmdline)

        while True:
            try:
                # Init qemu monitor
                s_mon = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s_mon.connect(batch.get_vm_state_path(vm.rank, 'monitor_socket'))
                break

            except socket.error as err:
                if err.errno == errno.ENOENT:
                    pid, status = os.waitpid(qemu_pid, os.WNOHANG)
                    if pid:
                        ret = status >> 8
                        raise HypervisorError("qemu exited during init with"
                                              " status %d" % (ret))
                    time.sleep(1)


        data = s_mon.recv(MAX_QMP_JSON_SIZE)
        s_mon.sendall('{ "execute": "qmp_capabilities" }')
        data = s_mon.recv(MAX_QMP_JSON_SIZE)

        # Ask for vcpu thread info
        s_mon.sendall('{ "execute": "query-cpus" }')
        data = s_mon.recv(8192)
        ret = json.loads(data)

        # Bind each vcpu thread on its physical cpu
        for cpu_info in ret["return"]:
            cpu_id = cpu_info["CPU"]
            cpu_thread_id = cpu_info["thread_id"]
            phys_coreid = subprocess_check_output(
                ['hwloc-calc' , '--po', '-I', 'PU',
                 'core:%s'%(virt_to_phys_coreid[cpu_id])]  +
                topology_cache_args).strip()
            subprocess_check_output(['taskset', '-p', '-c',
                                     phys_coreid, str(cpu_thread_id)])

        s_mon.close()

        qemu_socket_path = batch.get_vm_state_path(vm.rank,
                                                   'qemu_console_socket')
        pcocc_socket_path = batch.get_vm_state_path(vm.rank,
                                                   'pcocc_console_socket')

        logging.debug('Connecting to qemu console {0}'.format(
                qemu_socket_path))
        qemu_console_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            qemu_console_sock.settimeout(30)
            qemu_console_sock.connect(qemu_socket_path)
            qemu_console_sock.settimeout(None)
        except socket.error:
            logging.error('Failed to connect to qemu console')
            qemu_console_sock = None

        pcocc_console_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        pcocc_console_sock.bind(pcocc_socket_path)
        pcocc_console_sock.listen(0)

        # Signal VM started
        self._set_vm_state('complete',
                           'started',
                           None, vm.rank)

        # Proxy the VM console until Qemu closes it
        client_sock = None

        console_log_file = open(batch.get_vm_state_path(vm.rank,
                                                   'qemu_console_log'), 'w+',
                                1)

        while qemu_console_sock:
            # Only accept one client at a time
            if client_sock:
                sock_list = [client_sock, qemu_console_sock]
            else:
                sock_list = [pcocc_console_sock, qemu_console_sock]

            rdy, _ , _  = select.select(sock_list, [], [])

            for s in rdy:
                if s is pcocc_console_sock:
                    client_sock, _ = pcocc_console_sock.accept()
                    logging.debug('New client connexion to console')

                elif s is qemu_console_sock:
                    data = qemu_console_sock.recv(4096)
                    if not data:
                        # 0 bytes read means qemu disconnected
                        # Disconnect client if needed and stop console proxy
                        if client_sock:
                            try:
                                client_sock.shutdown(socket.SHUT_RDWR)
                                client_sock.close()
                            except:
                                pass
                        try:
                            qemu_console_sock.shutdown(socket.SHUT_RDWR)
                            qemu_console_sock.close()
                        except:
                            pass

                        # Leave all loops
                        qemu_console_sock = None
                        break

                    if client_sock:
                        try:
                            client_sock.sendall(data)
                        except:
                            pass

                    console_log_file.write(data)

                elif s is client_sock:
                    try:
                        data = client_sock.recv(4096)
                    except:
                        data = None

                    if data:
                        try:
                            qemu_console_sock.sendall(data)
                        except:
                            pass
                    else:
                        # 0 byte read means client disconnected
                        logging.debug('Client disconnected from console')
                        try:
                            client_sock.shutdown(socket.SHUT_RDWR)
                            client_sock.close()
                        except:
                            pass
                        client_sock = None

        pid, status = os.waitpid(qemu_pid, 0)
        ret = status >> 8
        if ret != 0:
            raise HypervisorError("qemu exited with status %d" % ret)

        return ret

    def dump(self, vm, dumpfile):
        mon = RemoteMonitor(vm)
        mon.dump(dumpfile)
        mon.close_monitor()

    def reset(self, vm):
        mon = RemoteMonitor(vm)
        mon.system_reset()
        mon.close_monitor()

    def human_monitor_cmd(self, vm, cmd):
        mon = RemoteMonitor(vm)
        res = mon.human_monitor_cmd(cmd)
        mon.close_monitor()
        return res

    def checkpoint(self, vm, ckpt_dir):
        dest_mem_file = self.checkpoint_mem_file(vm, ckpt_dir)

        mon = RemoteMonitor(vm)
        mon.stop()
        mon.start_migration(dest_mem_file)

        retry_count = 0
        status = 'failed'
        try:
            while True:
                time.sleep(1)
                data = mon.query_migration()

                ret =  json.loads(data)
                # If we are too fast, it seems qemu doesn't return the status
                if not 'status' in ret["return"]:
                    continue

                status = ret["return"]["status"]
                if status == "active":
                    remain_mb = (int(ret["return"]["ram"]["remaining"])
                                 / (1024 * 1024))
                    tot_mb = (int(ret["return"]["ram"]["total"])
                              / (1024 * 1024))
                    remain_pct = 100. * remain_mb / tot_mb

                    if remain_mb > 0:
                        print ("checkpointing vm%d memory: "
                               "%d MB remaining (%d %%)" )% (
                            vm.rank,
                            remain_mb,
                            remain_pct)
                elif status == 'completed':
                    break
                elif status == 'failed':
                    sys.stderr.write('Memory save error for VM %d, '
                    'output was %s \n' % (vm.rank, data))
                    if retry_count < Config().ckpt_retry_count:
                        retry_count += 1
                        sys.stderr.write('Retrying...\n')
                        mon.start_migration(dest_mem_file)
                        continue
                    else:
                        break
                elif status == 'setup':
                    continue
                else:
                    break

        except (KeyError , ValueError)  as err:
            raise CheckpointError(str(err) + ' Monitor sent: ' + data)

        if status != 'completed':
            raise CheckpointError('status is %s. Monitor sent: ' + data)

        mon.close_monitor()



    def quit(self, vm):
        s_mon = RemoteMonitor(vm)
        s_mon.quit()
        s_mon.close_monitor()

    def save(self, vm, dest_img_file, full=False):
        # FIXME: Use blockdev-snapshot-sync
        # FIXME: Could use block stream to prevent long snapshot chains
        # but this could be problematic with old QEMUs
        batch = Config().batch
        snapshot_path = batch.get_vm_state_path(vm.rank, 'image_snapshot')

        remote_host = vm.get_host()
        vm_image_path = vm.image_path

        try:
            subprocess.check_call(['ssh', remote_host,
                                   'cp', snapshot_path, dest_img_file])
        except (OSError, subprocess.CalledProcessError) as err:
            raise ImageSaveError('unable to copy image')

        need_rebase = False
        if full:
            need_rebase = True
            new_backing_file = '""'
            print 'Merging snapshot with backing file to make it standalone...'
        else:
            try:
                img_info_output =  subprocess_check_output(['ssh', remote_host,
                                                            'qemu-img', 'info',
                                                            dest_img_file])
            except (OSError, subprocess.CalledProcessError) as err:
                raise ImageSaveError('unable to determine backing file')

            match = re.search(r'backing file: (.+)\n', img_info_output)
            if not match:
                raise ImageSaveError('unable to determine backing file. Qemu-img '
                                     'output was ' + img_info_output)

            backing_file = match.group(1)

            if not os.path.samefile(backing_file, vm_image_path):
                need_rebase = True
                new_backing_file = vm_image_path
                print 'Current snapshot backing file is %s' % backing_file
                print 'Rebasing snapshot on %s to preserve chaining...' % vm_image_path

        if need_rebase:
            try:
                subprocess.check_call(['ssh', remote_host,
                                       'qemu-img', 'rebase',
                                       '-b', new_backing_file,
                                       dest_img_file])
            except (OSError, subprocess.CalledProcessError):
                raise ImageSaveError('Unable to rebase disk')

    def _get_agent_ctl_safe(self,vm):
        batch = Config().batch
        qga_cmd = '{"execute":"guest-ping"}\n\n'

        remote_host = vm.get_host()

        # We need to make several tries because nc and qemu may drop or
        # input silently if we race with them
        # We assume that a broken pipe means nc/qemu was not ready and
        # everything we sent was lost, unless we already received data from
        # it which means something went wrong and we stop retrying
        retry_connect = True
        while 1:
            s_ctl = self.socket_connect(vm, 'serial_taskcontrolport_socket')

            atexit.register(try_kill, s_ctl)
            # TODO: Remove this wait. For now, without it, some of the data we
            # send is lost
            time.sleep(1)

            retry_send = True
            while 1:
                if retry_send:
                    rdy = select.select([s_ctl.stdout],
                                        [s_ctl.stdin], [])
                else:
                    rdy = select.select([s_ctl.stdout], [], [])

                if s_ctl.stdout in rdy[0]:
                    data = os.read(s_ctl.stdout.fileno(), MAX_QMP_JSON_SIZE)
                    try:
                        retval = json.loads(data)["return"]
                        if retval:
                            raise AgentError("unexpected answer when "
                                             "pinging VM agent  "
                                             "%s\n" % data)
                        else:
                            return s_ctl
                    except (ValueError, KeyError)  as err:
                        if not data:
                            # Pipe closed, retry
                            break
                        else:
                            raise AgentError("unexpected answer when "
                                             "pinging VM agent  "
                                             "%s\n" % data)

                if retry_send and s_ctl.stdin in rdy[1]:
                    try:
                        s_ctl.stdin.write(qga_cmd)
                        retry_send = False
                    except IOError as err:
                        # Qemu wasn't ready, retry
                        if err.errno == errno.EPIPE:
                            break
                        else:
                            raise
            s_ctl.wait()
            # wait before trying a reconnection
            time.sleep(5)

    def put_file(self, vm, source_file, dest_file):
        batch = Config().batch
        s_ctl = self._get_agent_ctl_safe(vm)

        try:
            with open(source_file) as f:
                encoded_source = base64.b64encode(f.read())
        except IOError as err:
            raise AgentError("unable to read source file "
                             "for copy: %s" % str(err))

        try:
            s_ctl.stdin.write('{"execute":"guest-file-open",'
                              '"arguments":{"path":"%s",'
                              '"mode":"w+"}}\n\n'%(dest_file))
            data = os.read(s_ctl.stdout.fileno(), MAX_QMP_JSON_SIZE)
            handle = json.loads(data)["return"]


            s_ctl.stdin.write('{"execute":"guest-file-write",'
                              '"arguments":{"handle":%d,'
                              '"buf-b64":"%s"}}' %
                              (handle, encoded_source))
            data = os.read(s_ctl.stdout.fileno(), MAX_QMP_JSON_SIZE)
            count = json.loads(data)["return"]["count"]
            eof = json.loads(data)["return"]["eof"]

            s_ctl.stdin.write('{"execute":"guest-file-close",'
                              '"arguments":{"handle":%d}}' %
                              handle)

            data = os.read(s_ctl.stdout.fileno(), MAX_QMP_JSON_SIZE)
            ret = json.loads(data)["return"]
            if ret:
                raise ValueError

        except IOError as err:
            raise AgentError("failed to communicate:  %s" % err)
        except (KeyError, ValueError)  as err:
            raise AgentError("unexpected answer when "
                             "receiving exec output "
                             "%s\n" % data)

        s_ctl.terminate()



    def exec_cmd(self, vm, cmd, user):
        batch = Config().batch


        if cmd:
            s_ctl = self._get_agent_ctl_safe(vm)
        else:
            # FIXME: When resuming the agent might already be busy
            # so we cannot go through the safe connection which pings...
            s_ctl = self.socket_connect(vm,
                                         'serial_taskcontrolport_socket')

        # Create a ssh tunnel to the io pipe
        # TODO: integrate this to the agent
        s_io = self.socket_connect(vm,
                                    'serial_taskioport_socket')

        # Send a command if we need to
        if cmd:
            arglist = "".join("{\"argument\": \"%s\"},"%arg for arg in cmd[1:])
            arglist = arglist[:-1]

            envlist = "".join("{\"nameval\": %s},"
                              %(json.dumps(name+'='+val)) for (name, val) in
                              os.environ.iteritems()
                              if not re.search(r'SLURM', name))
            envlist = envlist[:-1]

            qga_cmd = ('{"execute": "guest-cmd-exec", "arguments":{'
                       '"username": "%s",'
                       '"path": "%s",'
                       '"cmd": "%s",'
                       '"arguments": [ %s ],'
                       '"env": [ %s ]'
                       '} }\n\n'%(user,
                                  os.getcwd(),
                                  cmd[0],
                                  arglist,
                                  envlist))
            try:
                s_ctl.stdin.write(qga_cmd)

            except IOError as err:
                raise AgentError("failed to send cmd to guest agent: %s "
                                 % err)

        # Poll the I/O stream as long as the command is runnning
        # Return the command return value when it exits
        while 1:
                rdy = select.select([s_ctl.stdout, s_io.stdout],
                                    [], [])

                if s_io.stdout in rdy[0]:
                    data = os.read(s_io.stdout.fileno(), 4096)

                    if data:
                        print data,

                if s_ctl.stdout in rdy[0]:
                    data = os.read(s_ctl.stdout.fileno(), 4096)

                    try:
                        retval = json.loads(data)["return"]
                        if retval != 0:
                            sys.stderr.write("vm%d: exit %d\n"%(vm.rank,
                                                                retval))

                        # Make sure we read everything from the I/O pipe
                        # before exiting
                        self._flush_outstanding_io(s_io)

                        s_ctl.terminate()
                        s_ctl.wait()
                        s_io.terminate()
                        s_io.wait()

                        return retval

                    except (ValueError, KeyError) as err:
                        if not data:
                            # Flush IO to prevent losing data
                            self._flush_outstanding_io(s_io)

                            s_ctl.poll()
                            if s_ctl.returncode == 0:
                                # If the connexion was closed properly
                                # it means qemu existed. We should do the same
                                # sys.stderr.write("Agent closed\n")
                                s_io.terminate()
                                s_io.wait()
                                return 0

                            elif s_ctl.returncode and not cmd:
                                # FIXME: This can happen when
                                # resuming since we can not go through the
                                # safe connect method because the agent may
                                # already be busy.
                                # We assume that qemu was not ready yet
                                # and just retry
                                # sys.stderr.write("Retrying connection\n")
                                s_io.terminate()
                                s_io.wait()
                                s_ctl = self.socket_connect(vm,
                                               'serial_taskcontrolport_socket')
                                s_io = self.socket_connect(vm,
                                               'serial_taskioport_socket')
                                time.sleep(5)
                                continue
                            else:
                                # Should not happen
                                sys.stderr.write('Connection did not exit\n')

                        raise AgentError("unexpected answer when "
                                         "receiving exec output from VM agent: "
                                         "%s -\n" % data)

    def _flush_outstanding_io(self, subproc):
        # Make sure we read everything from the I/O pipe
        # before exiting
        while True:
            rdy = select.select([subproc.stdout], [], [], 0)
            if subproc.stdout in rdy[0]:
                data = os.read(subproc.stdout.fileno(), 4096)
                if data:
                    print data,
                else:
                    break
            else:
                break

    def checkpoint_mem_file(self, vm, ckpt_dir):
        return os.path.join(ckpt_dir,'memory-vm%d' % (vm.rank))

    def checkpoint_img_file(self, vm, ckpt_dir):
        return os.path.join(ckpt_dir,'disk-vm%d' % (vm.rank))

    def socket_connect(self,vm, name):
        batch = Config().batch
        remote_host = vm.get_host()
        io_file = batch.get_vm_state_path(vm.rank,
                                          name)
        lock.acquire()
        subproc = subprocess.Popen(shlex.split('ssh %s nc -U %s'%(
                    remote_host, io_file)),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             stdin=subprocess.PIPE)
        lock.release()

        atexit.register(try_kill, subproc)
        return subproc

    def _set_vm_state(self, state, desc, value, vm_rank):
        Config().batch.write_key('cluster/user',
                                       self._vm_state_key(vm_rank),
                                       yaml.dump({'state': state,
                                                  'desc': desc,
                                                  'value': value}))

    def _unpack_vm_state(self, value):
        if value:
            return yaml.safe_load(value)
        else:
            return {'state': 'not-started',
                    'desc': 'waiting for batch manager',
                    'value': None}

    def _vm_state_key(self, vm_rank):
        return "state/vms/{0}".format(vm_rank)

    def wait_vm_start(self, vm):
        """Wait for vm to start"""

        batch = Config().batch
        vm_state, index = batch.read_key_index(
            'cluster/user',
            self._vm_state_key(vm.rank))

        vm_state = self._unpack_vm_state(vm_state)
        if vm_state['state'] == 'complete':
            return

        with click.progressbar(
            show_eta = False,
            show_percent = False,
            length = 2,
            label = 'Starting vm...',
            bar_template = '%(label)s (%(info)s)',
            item_show_func = lambda x: x['desc'] if x else '') as bar:

            bar.current_item =  vm_state
            bar.update(0)

            while True:
                vm_state, index = batch.wait_key_index(
                    'cluster/user',
                    self._vm_state_key(vm.rank),
                    index)

                vm_state = self._unpack_vm_state(vm_state.value)
                bar.current_item = vm_state
                bar.update(1)
                if vm_state['state'] == 'complete':
                    break
