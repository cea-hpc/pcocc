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
from __future__ import division

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
import signal
import datetime
import random
import binascii
import uuid
import Queue
import agent_pb2


from ClusterShell.NodeSet  import RangeSet
from .scripts import click
from .Backports import subprocess_check_output, enum
from .Error import PcoccError
from .Config import Config
from .Misc import fake_signalfd, wait_or_term_child
from .Misc import stop_threads, systemd_notify

lock = threading.Lock()

QEMU_GUEST_AGENT_PORT='org.qemu.guest_agent.0'

def try_kill(sproc):
    try:
        sproc.kill()
    except OSError:
        pass

VM_FREEZE_OPT = enum('NO', 'TRY', 'YES')

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

class HostAgentCtx(object):
    """
    This class hosts the HostAgent context.  It keeps track of
    callbacks used for processing agent replies.
    """
    def __init__(self):
        self.cb = {}

    def set_ret_cb(self, tag_id, ret_cb):
        """
        Associate a return callback with a tag
        """
        self.cb[str(tag_id)] = ret_cb

    def get_ret_cb(self, tag_id, keep):
        """
        Get a return callback for
        a given tag
        """

        try:
            ret = self.cb[str(tag_id)]
            if not keep:
                del self.cb[str(tag_id)]
        except KeyError:
            ret = None
        return ret

    def get_all_cbs(self):
        ret = self.cb.values()
        self.cb = {}

        return ret


class HostAgent(object):
    """
    This class is in charge of managing and sending
    commands to the VM agent

    It acts both as a client and server for theses
    requests. It is also providing some state management
    through the hostAgentContext class
    """
    def __init__(self, vm_rank):
        # The rank of the VM this agent works for
        self.rank = vm_rank
        batch = Config().batch

        # Lock for the serial port and tag allocation
        self.wlock = threading.Lock()

        # Tag allocator
        self.current_tag = 1

        # Store partially read serial port data
        self.databuff = ""

        # Pipe to notify the client thread
        self.sp_r, self.sp_w = os.pipe()

        # Manage callbacks for current RPCs to the VM agent
        self.ctx = HostAgentCtx()

        # Connect a socket to the VM agent serial port
        agent_file = batch.get_vm_state_path(vm_rank,
                                             "serial_pcocc_agent_socket")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.sock.connect(agent_file)
        except Exception as e:
            raise PcoccError("Could not connect to pcocc_agent socket:" + str(e))

        # Read the VM agent serial port socket and handle messages
        threading.Thread(target=self._client_thread).start()

        # Signal the client thread to stop when we want to exit
        threading.Thread(target=self._killer_thread).start()

        #Make sure the agent is unfrozen
        self.send_message("thaw", agent_pb2.ThawMessage())


    def stream_init_handler(self, name, init_msg, req_ctx):
        """
        Return functions to be used as callbacks to manage input and
        output for streaming RPCs
        """

        tag = self._alloc_tag()

        ret_iter = self.send_stream_message(name, init_msg,
                                            agent_pb2.AgentMessage.StreamRequest, tag, req_ctx)
        first_reply = next(ret_iter)

        if isinstance(first_reply, agent_pb2.GenericError):
            logging.info("Stream handler: error handling header msg: %s", first_reply)
            return None, None, first_reply

        def input_handler(cmd, msg, req_ctx):
            # FIXME: In some cases we may be interested in the agent answer
            # we should route it to the output_handler
            self.send_message(cmd, msg, None)

        def output_handler(req_ctx):
            for r in ret_iter:
                logging.debug("Stream handler: relaying msg from VM agent: %s", r)
                yield r

        #We should define a more generic way to do this but we only
        #have one case for now. If an attach gets cancelled, force a detach
        #in cas de the client didnt send it
        if name == "attach":
            def detach():
                self.send_message("detach",
                                  agent_pb2.DetachMessage(exec_id=init_msg.exec_id,
                                                          tag=tag),
                                  None)
            req_ctx.add_callback(detach)

        return input_handler, output_handler, first_reply

    def send_message(self, name, args, request_context=None):
        """
        Send a message to the VM agent and return a single result
        """
        tag = self._alloc_tag()

        try:
            return next(self.send_stream_message(name, args, agent_pb2.AgentMessage.Request, tag, request_context))
        except StopIteration:
            # FIXME: Allow empty results for locally sent requests
            if request_context is None:
                return None
            else:
                raise

    def _alloc_tag(self):
        self.wlock.acquire()
        tag = self.current_tag
        self.current_tag = self.current_tag + 1
        self.wlock.release()
        return tag

    def send_stream_message(self, name, args, kind, tag, request_context=None):
        """
        Send a message to the VM agent and return an generator for a
        stream of results

        """
        logging.info("Host agent: sending message {} "
                     "to VM {} agent".format(name, self.rank))

        retq = Queue.Queue()

        if request_context is None:
            # FIXME: For now ignore results for locally sent requests (thaw) as
            # we dont need them
            retq.put(None)
        else:
            def return_cb(result, keep):
                retq.put(result)
                if not keep:
                    retq.put(None)

            def cancel_cb():
                if self.ctx.get_ret_cb(tag, False):
                    logging.info("Cancelled request")
                    # FIXME: for now we let the VM agent finish processing the
                    # request and discard the result but we may have to
                    # cancel the VM agent processing as well

                    # The return value should never reach a client
                    # since it is called when the request is cancelled
                    # but we return something sensible just in case
                    retq.put(agent_pb2.GenericError(
                            kind = agent_pb2.GenericError.Cancelled,
                            description = "VM agent processing cancelled due to RPC cancellation"))
                    retq.put(None)

            self.ctx.set_ret_cb(tag, return_cb)
            request_context.add_callback(cancel_cb)


        am =  agent_pb2.AgentMessage(name = name,
                                     kind = kind,
                                     tag = tag)
        am.data.Pack(args)

        self.wlock.acquire()
        try:
            enc=base64.b64encode(am.SerializeToString())
            self.sock.sendall(enc+'\n')
        except IOError as e:
            logging.warning("Failed to %s message to agent due to %s", am.name, str(e))

        self.wlock.release()

        while True:
            data = retq.get()
            if data is None:
                return
            yield data

    def _cancel_all_requests(self):
        for callback in self.ctx.get_all_cbs():
            logging.info("Host agent: cancelling pending request")
            callback(agent_pb2.GenericError(
                    kind = agent_pb2.GenericError.Cancelled,
                    description = "Cancelled by host agent while executing RPC"), False)


    def _handle_incoming_command(self, command_data):
        """
        Run the callback for a given VM agent answer or async notification
        """
        logging.debug("Host agent: received {} from the VM agent".format(command_data))
        try:
            cmd = agent_pb2.AgentMessage()
            cmd.ParseFromString(base64.b64decode(command_data))
            logging.debug("Host agent: decoded protobuf to:\n{}".format(cmd))
        except Exception as e:
            # TODO: We shoudl implement a better recovery strategy
            # from leftover garbage in the serial port
            logging.error("Host agent: cannot decode protobuf from VM agent: {}".format(e))
            return

        if cmd.kind in (agent_pb2.AgentMessage.Reply,
                        agent_pb2.AgentMessage.Async,
                        agent_pb2.AgentMessage.StreamReply):

            if cmd.kind == agent_pb2.AgentMessage.Reply:
                keep = False
            else:
                keep = True

            callback = self.ctx.get_ret_cb(cmd.tag, keep)

            data = getattr(agent_pb2, cmd.data.TypeName())()
            cmd.data.Unpack(data)

            if callback:
                callback(data, keep)
                return
            else:
                # This can happen for some requests where we dont care
                # about the result or that were cancelled
                logging.debug("Host agent: got answer for {} with tag {} "
                              "which has no callback registered".format(cmd.name, cmd.tag))
        else:
            logging.error("Host agent: received unsupported message kind from VM agent: {}".format(cmd.kind))

    def _killer_thread(self):
        """Waits for a stop_threads event and signal the client thread to stop blocking"""
        stop_threads.wait()
        logging.info("Host agent: signaling serial port reader thread to exit")
        os.write(self.sp_w, "x")

    def _client_thread(self):
        """Read data from the VM agent answers over the dedicated serial port
        and run the registered callbacks
        """
        logging.info("Host agent: listening to VM {} agent over serial port".format(self.rank))
        while True:
            sdata = self._read_a_command()
            if sdata == None:
                logging.info("Host agent: disconnected from VM {} serial port".format(self.rank))
                break

            if len(sdata.replace("\n","")) == 0:
                continue
            self._handle_incoming_command(sdata)

        # If we disconnect, cancel all pending requests to the host
        # agent
        self._cancel_all_requests()

    def _read_a_command(self):
        """
        Read data from the VM until a complete command is read
        """
        while not '\n' in self.databuff:
            rdr, _, _ = select.select([self.sp_r, self.sock], [], [])
            if self.sp_r in rdr:
                # The host agent is shutting down
                # so we interrupt our read
                return None
            elif rdr:
                try:
                    tdata = self.sock.recv(32768)
                except socket.error:
                    tdata = None

                if not tdata:
                    return None
                else:
                    self.databuff = self.databuff + tdata

        sret = self.databuff.split("\n")
        self.databuff = "\n".join(sret[1:])
        ret = sret[0]
        return ret


QMP_READ_SIZE=32768

class RemoteMonitor(object):
    def __init__(self, vm):
        self.s_mon = Config().hyp.socket_connect(vm, 'monitor_socket')

        self.flush_output()
        self.send_raw('{ "execute": "qmp_capabilities" }')
        self.flush_output()

    def send_raw(self, data):
        return os.write(self.s_mon.stdin.fileno(), data)

    def flush_output(self):
        """Read everything from the monitor to start fresh
        """
        _ = os.read(self.s_mon.stdout.fileno(), 1)
        while select.select([self.s_mon.stdout.fileno()],[],[],0.0)[0]:
            _ = os.read(self.s_mon.stdout.fileno(), QMP_READ_SIZE)

    def read_filtered(self, event_list=None):
        """Read from the monitor socket and discard all events not in the event_list array
        """
        if event_list is None:
            event_list = []

        while True:
            data = self.s_mon.stdout.readline()
            try:
                ret = json.loads(data)
                if 'event' in ret and ret['event'] not in event_list:
                    continue
            except Exception:
                pass

            return data


    def quit(self):
        mon_quit_cmd = ('{"execute": "quit", "arguments":{'
                        '} }\n\n')
        self.send_raw(mon_quit_cmd)
        self.read_filtered()

    def stop(self):
        mon_stop_cmd = ('{"execute": "stop", "arguments":{'
                        '} }\n\n')
        self.send_raw(mon_stop_cmd)
        self.read_filtered()

    def query_status(self):
        mon_query_cmd = ('{"execute": "query-status", "arguments":{'
                        '} }\n\n')
        self.send_raw(mon_query_cmd)
        data = self.read_filtered()
        try:
            ret = json.loads(data)
        except:
            raise PcoccError("Could not parse query-status return: " + data)

        try:
            return ret["return"]["status"]
        except:
            raise PcoccError("Could not parse query-status return: " + data)


    def cont(self):
        mon_cont_cmd = ('{"execute": "cont", "arguments":{'
                        '} }\n\n')
        self.send_raw(mon_cont_cmd)
        self.read_filtered()

    def drive_backup(self, device, dest):
        mon_backup_cmd = ('{"execute": "drive-backup",'
                        '"arguments": { "device": "%s",'
                        '"target": "%s", "sync": "top"'
                        '} }\n\n' % (device, dest))
        self.send_raw(mon_backup_cmd)
        ret = self.read_filtered()

        try:
            ret = json.loads(ret)
        except:
            raise PcoccError("Could not parse drive-backup return: " + ret)

        if "error" in ret:
            raise ImageSaveError(ret["error"]["desc"])

        ret = self.read_filtered(["BLOCK_JOB_COMPLETED"])
        try:
            ret = json.loads(ret)
            event = ret["event"]
        except:
            raise PcoccError("Could not parse drive-backup event: " + ret)


        if event != "BLOCK_JOB_COMPLETED":
            raise ImageSaveError("Qemu returned event {0}, "
                                 "expected BLOCK_JOB_COMPLETED".format(event))

        if "error" in ret["data"]:
            raise ImageSaveError(ret["data"]["error"])

    def dump(self, dump_file):
        mon_dump_cmd = ('{"execute": "dump-guest-memory", "arguments":{ '
                        '"paging": true, '
                        '"protocol": "file:%s"'
                        '} }\n\n'  % dump_file)
        self.send_raw(mon_dump_cmd)

        while True:
            data = self.read_filtered()
            for line in data.splitlines():
                ret = json.loads(line)
                if "error" in ret:
                    raise ImageSaveError(ret["error"]["desc"])
                elif "event" in ret:
                    continue
                elif "return" in ret:
                    return
                else:
                    raise ImageSaveError('unexpected output from qemu: ' + line)
            time.sleep(2)

    def system_reset(self):
        mon_reset_cmd = ('{"execute": "system_reset", "arguments":{'
                        '} }\n\n')
        self.send_raw(mon_reset_cmd)
        self.read_filtered()

    def system_powerdown(self):
        mon_reset_cmd = ('{"execute": "system_powerdown", "arguments":{'
                        '} }\n\n')
        self.send_raw(mon_reset_cmd)
        self.read_filtered()

    def human_monitor_cmd(self, human_cmd):
        mon_human_cmd = ('{"execute": "human-monitor-command", "arguments":{'
                         '"command-line": "%s"} }\n\n' % human_cmd)
        self.send_raw(mon_human_cmd)
        raw_data = self.read_filtered()
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
        self.read_filtered()

        mon_save_cmd = ('{"execute": "migrate", "arguments":{'
                        '"uri": "exec:lzop > %s"'
                        '} }\n\n'%(dest_mem_file))
        self.send_raw(mon_save_cmd)
        data = self.read_filtered()
        try:
            ret = json.loads(data)
            if 'error' in ret:
                raise PcoccError('Failed to start memory transfer: ' +
                                 ret['error']['desc'])
        except:
            raise
#            raise PcoccError("Unable to parse output from qemu: " + data)

    def snapshot_image(self, dest_image_file):
        #TODO
        pass

    def query_migration(self):
        mon_query_cmd = ('{"execute": "query-migrate" }\n\n')
        self.send_raw(mon_query_cmd)
        return self.read_filtered()

    def close_monitor(self):
        self.s_mon.terminate()
        self.s_mon.communicate()

class Qemu(object):
    def __init__(self):
        self.qemu_bin = 'qemu-system-x86_64'
        self.host_agent = None
        self.state_ready = 0


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


    def _setup_spice(self, vm):
        batch = Config().batch
        # TODO: Add TLS support for untrusted networks
        spice_path = os.path.join(batch.cluster_state_dir,
                                  'spice_vm{0}'.format(vm.rank))
        sasldb_path = os.path.join(spice_path, 'saslpasswd.db')
        os.environ['SASL_CONF_PATH'] = spice_path
        os.mkdir(spice_path, 0o700)

        spice_password = binascii.b2a_hex(os.urandom(16))
        s_exec = subprocess.Popen(['saslpasswd2', '-f',
                                   sasldb_path, '-p',
                                   '-c',  '-u', 'pcocc',
                                   batch.batchuser],
                                  stdin=subprocess.PIPE)
        s_exec.communicate(input=spice_password + '\n')
        if s_exec.returncode:
            raise PcoccError('Failed to setup SASL password')

        qemu_conf="""
mech_list: digest-md5
sasldb_path: {0}
auxprop_plugin: sasldb
""".format(sasldb_path)
        with open(os.path.join(spice_path, 'qemu.conf'), 'w') as f:
            f.write(qemu_conf)


        randrange = range(5900,6100, 2)
        random.shuffle(randrange)
        # TODO: find a better way to allocate port numbers since qemu
        # requires a fixed port. For now use odd port numbers as locks
        # guarding even port numbers and hope we don't race with some
        # non-pcocc app.
        locksocket = socket.socket(socket.AF_INET,
                                   socket.SOCK_STREAM)
        testsocket = socket.socket(socket.AF_INET,
                                   socket.SOCK_STREAM)

        spice_port = 0
        for spice_port in randrange:
            try:
                locksocket.bind(('', spice_port + 1))
            except Exception:
                continue

            try:
                testsocket.bind(('', spice_port))
            except Exception:
                locksocket.close()
                locksocket = socket.socket(socket.AF_INET,
                                               socket.SOCK_STREAM)
                continue

            testsocket.close()
            atexit.register(locksocket.close)
            break
        else:
            raise HypervisorError('Unable to find a free port for remote display')

        with open(os.path.join(spice_path, 'console.vv'),
                  'w') as f:
            f.write("""[virt-viewer]
type=spice
host={0}
port={1}
password={2}
username={3}@pcocc
""".format(vm.get_host(), spice_port,
           spice_password, batch.batchuser))

        return ['-spice','port={0},sasl'.format(spice_port),
                '-device', 'virtserialport,chardev=spicechannel0,name=com.redhat.spice.0',
                '-chardev', 'spicevmc,id=spicechannel0,name=vdagent']

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
            logging.warning('VM %s was only given %s cores, '
                            'but its template requires %s for the emulator. '
                            'Reducing emulator cores to %s',
                            vm.rank, num_cores, vm.emulator_cores,
                            num_cores - 1)
            emulator_cores = num_cores - 1
        else:
            emulator_cores = vm.emulator_cores

        emulator_coreset  = coreset[:emulator_cores]
        coreset = coreset[emulator_cores:]

        # Recompute num_cores to exclude emulator_cores
        num_cores -= emulator_cores

        if num_cores == len(coreset):
            logging.info('Physical resources match VM definition, activating autobinding')
            autobind_cpumem = True
            for core_id in coreset:
                try:
                    with open(os.devnull, 'w') as devnull:
                        numa_node = int(subprocess_check_output(['hwloc-calc',
                                                                 'Core:%d' %
                                                                 (int(core_id)),
                                                                 '-I', 'NUMANode'] +
                                                                topology_cache_args,
                                        stderr=devnull))
                except ValueError:
                    # Use NUMA node 0 if the CPU doesnt intersect any NUMANode
                    # Usually this means that we have a UMA machine
                    numa_node = 0

                except Exception as err:
                    raise HypervisorError('unable to compute NUMA node: '
                                          + str(err))

                cores_on_numa.setdefault(numa_node,
                                         RangeSet()).update(RangeSet(str(core_id)))
        else:
            logging.info('Physical resources don\'t match VM definition. Autobind deactivated.')
            autobind_cpumem = False
            cores_on_numa[0] = coreset

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
        try:
            # Check if the kvm is usable
            f =  open('/dev/kvm', 'w+')
            cmdline += ['-machine', 'type={0},accel=kvm'.format(vm.machine_type)]
            cmdline += ['-cpu', 'host']
        except:
            cmdline += ['-machine', 'type={0}'.format(vm.machine_type)]
        else:
            f.close()

        cmdline += ['-rtc', 'base=utc']
        cmdline += ['-device', 'qxl-vga,id=video0,ram_size=67108864,'
                   'vram_size=67108864,vgamem_mb=16']

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

            if vm.disk_model == 'virtio':
                cmdline += ['-object',
                            'iothread,id=ioth-bootdisk']
                cmdline += ['-device',
                            'virtio-blk-pci,id=ioth-bootdisk,multifunction=on,'
                            'drive=bootdisk,addr=06.0']
            elif vm.disk_model == 'ide':
                cmdline += ['-device', 'ich9-ahci,id=ahci,addr=06.0']
                cmdline += ['-device', 'ide-hd,'
                            'drive=bootdisk,bus=ahci.0']
            else:
                raise HypervisorError('Unsupported disk model: '
                                      + str(vm.disk_model))

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
                            i, i//3+7, i%3)]
            cmdline += ['-drive',
                        'file={0},cache={1},id=datadisk{2},'
                        'if=none'.format(
                        path,
                        vm.persistent_drives[drive]['cache'],
                        i)]

        if not '-boot' in vm.custom_args:
            cmdline += ['-boot', 'order=cd']

        # Memory
        # FIXME: Reserve 15% if total_memory for qemu
        total_mem = int(total_mem * 0.85)
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

        if autobind_cpumem:
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

                    cmdline += ['-object',
                                'memory-backend-ram,size=%dM,policy=preferred,prealloc=yes,'
                                'host-nodes=%d,id=ram-%d' % (
                            total_mem // len(cores_on_numa),
                            numa_node, i)]

                else:
                    cmdline += ['-numa', 'node,cpus=%d-%d,nodeid=%d' % (
                            start_cpu,
                            start_cpu + ncores_on_node - 1,
                            i)]

                start_cpu += ncores_on_node
        else:
            cmdline += ['-m', str(total_mem)]

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

            # Fail early if the mount point is not accessible as Qemu will
            # refuse to start anyway
            if ( not os.path.isdir(host_path) or
                 not os.access(host_path, os.R_OK|os.X_OK)):
                raise HypervisorError('unable to access mount '
                                      'point {0}'.format(host_path))

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
                         'virtio-serial,id=ser0,max_ports=%d' % (nserials+2) ]
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

        # Virtio RNG
        cmdline += [ '-device', 'virtio-rng-pci']

        #Display
        if vm.remote_display == 'spice':
            cmdline += self._setup_spice(vm)
        elif not vm.remote_display:
            cmdline += ['-display', 'none']
        else:
            raise HypervisorError('Unsupported remote display type: '
                                  + str(vm.remote_display))

        try:
            user_data_file = batch.get_vm_state_path(vm.rank, 'user-data')
            meta_data_file = batch.get_vm_state_path(vm.rank, 'meta-data')
            iso_file = batch.get_vm_state_path(vm.rank, 'cloud_seed')

            f = open(meta_data_file, 'w')
            instance_id = vm.instance_id
            if instance_id is None:
                instance_id = uuid.uuid4()
            f.write('instance-id: {0}\n'.format(instance_id))

            if hasattr(vm, 'domain_name'):
                # Setting the fqdn as a hostname is not standard but
                # its what cloud-init wants and its difficult to work
                # around it.  Ideally we'd set the short hostname for
                # and cloud-init would use it as a hostname without
                # appending .localdomain. The fqdn should be
                # determined by the resolver configuration (dns or
                # host file).
                f.write('local-hostname: vm{0}.{1}\n'.format(vm.rank, vm.domain_name))
            else:
                # For networks without managed DHCP/DNS set a hostname by default
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


            cmdline += [ '-drive', 'id=cdrom0,if=none,format=raw,readonly=on,file={0}'.format(iso_file)]
            cmdline += [ '-device', 'virtio-scsi-pci,id=scsi0']
            cmdline += [ '-device', 'scsi-cd,bus=scsi0.0,drive=cdrom0']

        except (OSError, IOError, subprocess.CalledProcessError) as err:
            raise HypervisorError('unable to generate cloud-init iso: '
                                  + str(err))

        self._set_vm_state('qemu-start',
                           'starting qemu',
                           None, vm.rank)

        if vm.custom_args:
            cmdline += vm.custom_args


        if emulator_coreset and autobind_cpumem:
            emulator_phys_coreset = [ subprocess_check_output(
                ['hwloc-calc', '--po', '-I', 'PU', 'Core:%s' % core] +
                topology_cache_args).strip()
                                      for core in emulator_coreset ]
            cmdline = ['taskset',
                       '-c', ','.join(emulator_phys_coreset)] + cmdline

        qemu_pid = os.fork()
        if qemu_pid == 0:
            # Silence Qemu unless in verbose mode
            if not Config().verbose:
                fd = os.open(os.devnull, os.O_WRONLY)
                os.dup2(fd, 2)
                os.dup2(fd, 1)
            # Run in a new process group to not get SIGINTs if launched from
            # a terminal
            os.setpgid(0, 0)
            os.execvp(cmdline[0], cmdline)

        while True:
            try:
                # Init qemu monitor
                s_mon = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s_mon.connect(batch.get_vm_state_path(vm.rank, 'monitor_socket'))
                break

            except socket.error as err:
                pid, status = os.waitpid(qemu_pid, os.WNOHANG)
                if pid:
                    ret = status >> 8
                    raise HypervisorError("qemu exited during init with"
                                          " status %d" % (ret))
                time.sleep(1)


        data = s_mon.recv(QMP_READ_SIZE)
        s_mon.sendall('{ "execute": "qmp_capabilities" }')
        data = s_mon.recv(QMP_READ_SIZE)

        self._set_vm_state('qemu-start',
                           'binding vcpus',
                           None, vm.rank)

        if autobind_cpumem:
            # Ask for vcpu thread info
            s_mon.sendall('{ "execute": "query-cpus" }')
            data = s_mon.recv(QMP_READ_SIZE)
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

        logging.debug('Connecting to qemu console %s',
                      qemu_socket_path)
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


        if ckpt_dir:
            # Signal VM restore
            self._set_vm_state('qemu-start',
                           'restoring',
                           None, vm.rank)

            mon = RemoteMonitor(vm)
            while mon.query_status() == 'inmigrate':
                time.sleep(1)
            mon.cont()
            mon.close_monitor()

        # Signal VM started
        self._set_vm_state('running',
                           'The vm has started',
                           None, vm.rank)

        # If we need to properly shutdown the guest, catch SIGTERMs
        # and SIGINTS
        if vm.wait_for_poweroff:
            term_sigfd = fake_signalfd([signal.SIGTERM, signal.SIGINT])
        else:
            term_sigfd = None

        # Proxy the VM console until Qemu closes it
        client_sock = None

        console_log_file = open(batch.get_vm_state_path(vm.rank,
                                                   'qemu_console_log'), 'w+',
                                1)

        t = None
        shutdown_attempts = 0
        if term_sigfd is None:
            base_list = [qemu_console_sock]
        else:
            base_list = [term_sigfd, qemu_console_sock]


        if systemd_notify('VM is booting...', ready=True):
            watchdog = threading.Thread(None, self.watchdog, args=[vm])
            watchdog.start()


        vm.enable_agent_server(HostAgent(vm.rank))

        while qemu_console_sock:
            # Only accept one client at a time
            if client_sock:
                listen_list = base_list + [client_sock]
            else:
                listen_list = base_list + [pcocc_console_sock]

            try:
                rdy, _ , _  = select.select(listen_list, [], [])
            except select.error as e:
                if e.args[0] == errno.EINTR:
                    continue
                else:
                    raise

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
                elif s is term_sigfd:
                    os.read(term_sigfd, 1024)
                    if shutdown_attempts >= 5:
                        logging.info('Timed out waiting for VM to poweroff')
                        # Exit loops
                        qemu_console_sock = None
                        break

                    mon = RemoteMonitor(vm)
                    mon.system_powerdown()
                    mon.close_monitor()
                    logging.debug('Waiting for VM to poweroff')
                    # Wait 10s for Qemu to exit and resend signal
                    if t:
                        t.cancel()
                        t.join(0)
                    t = threading.Timer(10, os.kill,
                                        [os.getpid(), signal.SIGTERM])
                    t.start()
                    shutdown_attempts+=1

        logging.debug('Cleaning up Qemu')
        # Qemu should have exited, send it a SIGTERM and a SIGKILL 5s later
        if t:
            t.cancel()
            t.join(0)

        stop_threads.set()
        os.kill(os.getpid(), signal.SIGTERM)
        status, pid, _ = wait_or_term_child(qemu_pid, signal.SIGTERM,
                                            term_sigfd, 5)
        ret = status >> 8
        if ret != 0:
            raise HypervisorError("qemu exited with status %d" % ret)

        return ret

    def watchdog(self, vm):
        while not stop_threads.wait(30):
            try:
                s_ctl = self._get_agent_ctl_safe(vm, QEMU_GUEST_AGENT_PORT, 5,
                                                 False)
                systemd_notify('Watchdog successful at {0}'.format(
                    datetime.datetime.now()), watchdog=True)

            except Exception:
                systemd_notify('Watchdog could not query guest at {0}'.format(
                    datetime.datetime.now()))

            try:
                s_ctl.terminate()
                s_ctl.communicate()
            except Exception:
                pass

        logging.info('Got thread termination event')

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

        try:
            mon.start_migration(dest_mem_file)
            retry_count = 0
            status = 'failed'

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
                                 // (1024 * 1024))
                    tot_mb = (int(ret["return"]["ram"]["total"])
                              // (1024 * 1024))
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
        except PcoccError as err:
            try:
                mon.cont()
            except:
                pass
            raise CheckpointError(str(err))

        except (KeyError , ValueError)  as err:
            try:
                mon.cont()
            except:
                pass
            raise CheckpointError(str(err) + ' Monitor sent: ' + data)


        if status != 'completed':
            raise CheckpointError('status is %s. Monitor sent: ' + data)

        mon.close_monitor()



    def quit(self, vm):
        s_mon = RemoteMonitor(vm)
        s_mon.quit()
        s_mon.close_monitor()

    def save(self, vm, dest_img_file, full=False, freeze=VM_FREEZE_OPT.TRY):
        remote_host = vm.get_host()
        vm_image_path = vm.image_path
        use_fsfreeze = False

        if freeze != VM_FREEZE_OPT.NO:
            if freeze == VM_FREEZE_OPT.YES:
                timeout = 0
            else:
                timeout = 2

            try:
                self.fsthaw(vm, timeout=timeout)
                use_fsfreeze = True
            except AgentError:
                if freeze == VM_FREEZE_OPT.YES:
                    raise ImageSaveError('Unable to freeze filesystems')

                print ('No answer from Qemu agent when trying to freeze filesystem: '
                       'saved image could be corrupted if the filesystem '
                       'is accessed')

        if use_fsfreeze:
            self.fsfreeze(vm)

        try:
            mon = RemoteMonitor(vm)
            mon.drive_backup('bootdisk', dest_img_file)
            mon.close_monitor()
        except:
            if use_fsfreeze:
                self.fsthaw(vm)
            raise

        if use_fsfreeze:
            self.fsthaw(vm)

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
            except (OSError, subprocess.CalledProcessError):
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

    def _get_agent_ctl_safe(self, vm, port='taskcontrolport', timeout=0, kill_atexit=True):
        # We need to make several tries because nc and qemu may drop or
        # input silently if we race with them
        # We assume that a broken pipe means nc/qemu was not ready and
        # everything we sent was lost, unless we already received data from
        # it which means something went wrong and we stop retrying
        while 1:
            s_ctl = self.socket_connect(vm, 'serial_{0}_socket'.format(port), kill_atexit)
            syn_id = random.randint(100000000,999999999)
            qga_cmd = '{"execute":"guest-sync", "arguments": { "id": %d }}\n\n' % syn_id
            logging.debug("Sending agent sync %s", qga_cmd)

            # TODO: Remove this wait. For now, without it, some of the data we
            # send is lost
            time.sleep(1)

            retry_send = True
            while 1:
                if retry_send:
                    rdy = select.select([s_ctl.stdout],
                                        [s_ctl.stdin], [])
                else:
                    rdy = select.select([s_ctl.stdout], [], [], timeout)

                if timeout and rdy == ([], [], []):
                    self._cleanup_and_raise(s_ctl, AgentError("Timeout pinging agent"))

                if s_ctl.stdout in rdy[0]:
                    data = os.read(s_ctl.stdout.fileno(), QMP_READ_SIZE)
                    if not data:
                        # Pipe closed, retry
                        break

                    if data.find(str(syn_id)) == -1:
                        self._cleanup_and_raise(s_ctl, AgentError("unexpected answer when "
                                                                  "pinging VM agent  "
                                                                  "%s\n" % data))
                    return s_ctl

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

            try:
                if s_ctl.poll() is None:
                    s_ctl.terminate()
            except Exception:
                pass

            s_ctl.communicate()

            if timeout:
                # Shave 5 seconds off of the timeout as we are
                # going to sleep for that much before retry our select
                timeout -= 5
                if timeout <= 0:
                    self._cleanup_and_raise(s_ctl, AgentError("Timeout pinging agent"))

            # wait before trying a reconnection
            time.sleep(5)

    def _cleanup_and_raise(self, sproc, error):
        try:
            if not sproc.poll():
                sproc.terminate()
        except Exception:
            pass

        try:
            sproc.communicate()
        except Exception:
            pass

        raise error


    def put_file(self, vm, source_file, dest_file):
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
            data = os.read(s_ctl.stdout.fileno(), QMP_READ_SIZE)
            handle = json.loads(data)["return"]


            s_ctl.stdin.write('{"execute":"guest-file-write",'
                              '"arguments":{"handle":%d,'
                              '"buf-b64":"%s"}}' %
                              (handle, encoded_source))
            data = os.read(s_ctl.stdout.fileno(), QMP_READ_SIZE)
            count = json.loads(data)["return"]["count"]
            eof = json.loads(data)["return"]["eof"]

            fsize = os.stat(source_file).st_size
            if count < fsize:
                raise AgentError("Wrote only {0} out of {1} bytes of {2}".format(
                    count, fsize, source_file))

            if eof:
                raise AgentError("Unexepected EOF writing {0}".format(source_file))

            s_ctl.stdin.write('{"execute":"guest-file-close",'
                              '"arguments":{"handle":%d}}' %
                              handle)

            data = os.read(s_ctl.stdout.fileno(), QMP_READ_SIZE)
            ret = json.loads(data)["return"]
            if ret:
                raise ValueError

            logging.debug('Agent wrote %s to %s (%s bytes)',
                          source_file, dest_file, count)

        except IOError as err:
            raise AgentError("failed to communicate:  %s" % err)
        except (KeyError, ValueError)  as err:
            raise AgentError("unexpected answer when "
                             "receiving exec output "
                             "%s\n" % data)

        s_ctl.terminate()


    def fsfreeze(self, vm, port=QEMU_GUEST_AGENT_PORT, timeout=0):
        s_ctl = self._get_agent_ctl_safe(vm, port, timeout)
        s_ctl.stdin.write('{"execute":"guest-fsfreeze-freeze"}')
        data = os.read(s_ctl.stdout.fileno(), QMP_READ_SIZE)
        try:
            ret = json.loads(data)
        except:
            raise AgentError("Failed to parse agent output")

        if "error" in ret:
            raise AgentError("Error while freezing VM: " + ret["error"]["desc"])

        ret = json.loads(data)["return"]
        if  ret <= 0:
            raise AgentError("No filesystem frozen")

        print 'vm{0} frozen'.format(vm.rank)
        s_ctl.terminate()

    def fsthaw(self, vm, port=QEMU_GUEST_AGENT_PORT, timeout=0):
        s_ctl = self._get_agent_ctl_safe(vm, port, timeout)
        s_ctl.stdin.write('{"execute":"guest-fsfreeze-thaw"}')
        data = os.read(s_ctl.stdout.fileno(), QMP_READ_SIZE)
        try:
            ret = json.loads(data)
        except:
            raise AgentError("Failed to parse agent output")

        if "error" in ret:
            raise AgentError("Error while thawing VM: " + ret["error"]["desc"])

        ret = json.loads(data)["return"]

        if ret > 0:
            print 'vm{0} thawed'.format(vm.rank)

        s_ctl.terminate()

    def exec_cmd(self, vm, cmd, user):
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
                    s_ctl.communicate()
                    s_io.terminate()
                    s_io.communicate()

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
                            s_io.communicate()
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
                            s_io.communicate()
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

    def socket_connect(self,vm, name, kill_atexit=True):
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
        if kill_atexit:
            atexit.register(try_kill, subproc)

        lock.release()

        return subproc

    def _set_vm_state(self, state, desc, value, vm_rank):
        Config().batch.write_key('cluster/user',
                                       self._vm_state_key(vm_rank),
                                       yaml.dump({'state': state,
                                                  'desc': desc,
                                                  'hostname' : socket.gethostname(),
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

    def get_vm_state(self, vm_rank):
        batch = Config().batch
        vm_state, index = batch.read_key_index(
            'cluster/user',
            self._vm_state_key(vm_rank))

        return self._unpack_vm_state(vm_state), index

    def wait_vm_start(self, vm_rank):
        """Wait for vm to start"""
        vm_state, index = self.get_vm_state(vm_rank)
        if vm_state['state'] == 'running':
            return

        batch = Config().batch
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
                    self._vm_state_key(vm_rank),
                    index)

                vm_state = self._unpack_vm_state(vm_state.value)
                bar.current_item = vm_state
                bar.update(1)
                if vm_state['state'] == 'running':
                    break
