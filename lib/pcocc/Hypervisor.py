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
import random
import binascii
import uuid
import Queue
import agent_pb2
import Docker

from abc import ABCMeta
from ClusterShell.NodeSet  import RangeSet
from .scripts import click
from .Backports import subprocess_check_output, enum
from .Error import PcoccError
from .Config import Config
from .Misc import fake_signalfd, wait_or_term_child
from .Misc import stop_threads, systemd_notify
from .Templates import DRIVE_IMAGE_TYPE


lock = threading.Lock()

QEMU_GUEST_AGENT_PORT='org.qemu.guest_agent.0'

def try_kill(sproc):
    try:
        sproc.kill()
    except OSError:
        pass

VM_FREEZE_OPT = enum('NO', 'TRY', 'YES')

DRIVE_SAVE_MODE = enum('FULL', 'TOP', 'INCR')

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
    This class is in charge of proxying commands to the VM agent and the Qemu
    Monitor
    """
    _stream_req_handlers = {}
    _req_handlers = {}

    @classmethod
    def register_handler(cls, name, rq_class):
        cls._req_handlers[name] = rq_class.handle

    @classmethod
    def register_stream_handler(cls, name, rq_class):
        cls._stream_req_handlers[name] = rq_class.handle

    def __init__(self, vm):
        self.vm = vm

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
        agent_file = batch.get_vm_state_path(vm.rank,
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

        # If the message is to be handled on the host, a handler will be
        # registered
        if name in self._stream_req_handlers:
            ret_iter = self._stream_req_handlers[name](self, init_msg,
                                                       agent_pb2.AgentMessage.StreamRequest,
                                                       tag, req_ctx)
            def input_handler(cmd, msg, req_ctx):
                # Currently messages handled by the host accept no subsequent input
                pass
        else:
            # If no local handler was registered, passthrough the message to the VM
            # agent
            ret_iter = self.send_stream_message(name, init_msg,
                                                agent_pb2.AgentMessage.StreamRequest,
                                                tag, req_ctx)
            def input_handler(cmd, msg, req_ctx):
                # In some cases we may be interested in the agent answer
                # we should route it to the output_handler. For now the only case
                # is attach where we don't really care.
                self.send_message(cmd, msg, None)

        first_reply = next(ret_iter)

        if isinstance(first_reply, agent_pb2.GenericError):
            logging.info("Stream handler: error handling header msg: %s", first_reply)
            return None, None, first_reply

        def output_handler(req_ctx):
            for r in ret_iter:
                logging.debug("Stream handler: relaying stream msg from VM agent: %s", r)
                yield r

        # We should define a more generic way to do this but we only
        # have one case for now. If an attach gets cancelled, force a detach
        # in case the client didnt send it
        if name == "attach":
            def detach():
                self.send_message("detach",
                                  agent_pb2.DetachMessage(exec_id=init_msg.exec_id,
                                                          tag=tag),
                                  None)
            req_ctx.add_callback(detach)

        return input_handler, output_handler, first_reply

    def message_handler(self, name, args, request_context=None):
        """
        Handle a message sent to the host agent
        """

        # If the message is to be handled on the host, a handler will be
        # registered
        if name in self._req_handlers:
            return self._req_handlers[name](self, args, request_context)

        # If no local handler was registered, passthrough the message to the VM
        # agent
        return self.send_message(name, args, request_context)

    def send_message(self, name, args, request_context=None):
        """
        Send a message to the VM agent and return a single result
        """
        tag = self._alloc_tag()

        try:
            return next(self.send_stream_message(name, args,
                                                 agent_pb2.AgentMessage.Request,
                                                 tag, request_context))
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
        logging.info("Host agent: sending message %s "
                     "to VM %d agent", name, self.vm.rank)

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
            logging.warning("Failed to send %s message to agent due to %s", am.name, str(e))

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
        logging.debug("Host agent: received %s from the VM agent", str(command_data))
        try:
            cmd = agent_pb2.AgentMessage()
            cmd.ParseFromString(base64.b64decode(command_data))
            logging.debug("Host agent: decoded protobuf to:\n%s", str(cmd))
        except Exception as e:
            # TODO: We should implement a better recovery strategy
            # from leftover garbage in the serial port
            logging.error("Host agent: cannot decode protobuf from VM agent: %s",
                          str(e))
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
                logging.debug("Host agent: got answer for %s with tag %d "
                              "which has no callback registered", cmd.name,
                              cmd.tag)
        else:
            logging.error("Host agent: received unsupported message kind "
                          "from VM agent: %s", cmd.kind)

    def _killer_thread(self):
        """Waits for a stop_threads event and signal the client thread to stop blocking"""
        stop_threads.wait()
        logging.info("Host agent: signaling serial port reader thread to exit")
        os.write(self.sp_w, "x")

    def _client_thread(self):
        """Read data from the VM agent answers over the dedicated serial port
        and run the registered callbacks
        """
        logging.info("Host agent: listening to VM %d agent over serial port",
                     self.vm.rank)
        while True:
            sdata = self._read_a_command()
            if sdata == None:
                logging.info("Host agent: disconnected from VM %d "
                             "serial port", self.vm.rank)
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


class HAStreamReqClass(ABCMeta):
    def __init__(cls, name, bases, dct):
        if '_name' in dct:
            HostAgent.register_stream_handler(dct['_name'], cls)

        super(HAStreamReqClass, cls).__init__(name, bases, dct)

class HAReqClass(ABCMeta):
    def __init__(cls, name, bases, dct):
        if '_name' in dct:
            HostAgent.register_handler(dct['_name'], cls)
        super(HAReqClass, cls).__init__(name, bases, dct)

class HADumpReq(object):
    _name = "dump"
    __metaclass__ = HAStreamReqClass

    def __init__(self):
        pass

    @staticmethod
    def handle(agent, args, kind, tag, request_context):
        retq = Queue.Queue()

        def complete_cb(event):
            if event is None:
                retq.put({'error': 'disconnected'})

            if 'event' in event and event['event'] == 'DUMP_COMPLETED':
                retq.put(event)
                return False
            return True

        try:
            res = agent.vm.qemu_mon.dump(args.path)
        except PcoccError as e:
            yield agent_pb2.GenericError(
                        kind = agent_pb2.GenericError.AgentError,
                        description = str(e))
            return

        agent.vm.qemu_mon.async_cb.append(complete_cb)

        while True:
            try:
                res = retq.get(True, 0.1)
                break
            except Queue.Empty:
                pass

            r = agent.vm.qemu_mon.query_dump()

            if r['status'] == 'active':
                pct=float(r['completed']) / float(r['total'])
                yield agent_pb2.DumpResult(complete=False, pct=pct)

        if 'error' in res:
            yield agent_pb2.GenericError(
                        kind = agent_pb2.GenericError.AgentError,
                        description = res['error'])
        else:
            yield agent_pb2.DumpResult(complete=True, pct=100.)
        return


class HACkptReq(object):
    _name = "checkpoint"
    __metaclass__ = HAStreamReqClass

    @staticmethod
    def handle(agent, args, kind, tag, request_context):
        retq = Queue.Queue()

        complete = False

        if args.vm_suffix_path:
            args.path = args.path + "-vm{}".format(agent.vm.rank)

        def cancel_cb():
            if complete:
                logging.debug('Ignoring cancel of complete migrate job')
                return

            logging.debug('Cancelling migrate job')
            try:
                agent.vm.qemu_mon.cancel_migration()
            except:
                logging.error('Failed to cancel migrate job')

            logging.debug('Resuming VM')
            try:
                agent.vm.qemu_mon.cont()
            except:
                logging.error('Failed to resume VM')

        def complete_cb(event):
            if event is None:
                retq.put({'error': 'disconnected'})
                return

            if ('event' in event and
                event['event'] == 'MIGRATION' and (
                 event['data']['status'] == 'completed' or
                 event['data']['status'] == 'failed' or
                 event['data']['status'] == 'cancelled')):
                logging.debug('Notifying job completion')
                retq.put(event)
                return False

            return True

        agent.vm.qemu_mon.stop()
        agent.vm.qemu_mon.async_cb.append(complete_cb)
        request_context.add_callback(cancel_cb)
        agent.vm.qemu_mon.start_migration(args.path)


        while True:
            try:
                res = retq.get(True, 0.1)
                complete = True
                if res['data']['status'] != 'completed':
                    yield agent_pb2.GenericError(
                        kind = agent_pb2.GenericError.AgentError,
                        description = 'Migration '+ res['data']['error'])
                else:
                    yield agent_pb2.CheckpointResult(status = 'complete')
                    agent.vm.qemu_mon.quit()
                return
            except Queue.Empty:
                pass

            r = agent.vm.qemu_mon.query_migration()
            if not 'status' in r:
                # If we are too fast, Qemu may not return the status
                continue

            if r['status'] == 'active':
                yield agent_pb2.CheckpointResult(
                    status = 'active',
                    remaining = int(r['ram']['remaining']),
                    total     = int(r['ram']['total']))
            elif r['status'] == 'completed':
                complete = True
                yield agent_pb2.CheckpointResult(status = 'complete')
                agent.vm.qemu_mon.quit()
                return


class HASaveDriveReq(object):
    _name = "save"
    __metaclass__ = HAStreamReqClass

    @staticmethod
    def handle(agent, args, kind, tag, request_context):
        retq = Queue.Queue()

        if len(args.drives) != 1:
            yield agent_pb2.GenericError(
                        kind = agent_pb2.GenericError.AgentError,
                        description = 'Only single drive saves are supported')
            return

        if len(args.drives) != len(args.paths):
            yield agent_pb2.GenericError(
                        kind = agent_pb2.GenericError.AgentError,
                        description = 'Mismatch between drives and paths counts')
            return

        use_fsfreeze = False
        if args.freeze != VM_FREEZE_OPT.NO:
            if args.freeze == VM_FREEZE_OPT.YES:
                timeout = 0
            else:
                timeout = 2

            try:
                Config().hyp.fsthaw(agent.vm, timeout=timeout)
                use_fsfreeze = True
            except AgentError:
                if args.freeze == VM_FREEZE_OPT.YES:
                    raise ImageSaveError('Unable to freeze filesystems')

                yield agent_pb2.SaveDriveResult(
                    status = 'freeze-failed')

        if use_fsfreeze:
            Config().hyp.fsfreeze(agent.vm)

            yield agent_pb2.SaveDriveResult(
                status = 'frozen')

        if args.stop_vm:
            agent.vm.qemu_mon.stop()
            yield agent_pb2.CheckpointResult(status = 'vm-stopped')

        complete = False

        if args.vm_suffix_path:
            for i, path in enumerate(args.paths):
                args.paths[i] = path + "-vm{}".format(agent.vm.rank)

        def cancel_cb():
            if complete:
                logging.debug('Ignoring cancel of complete block job')
                return False

            try:
                logging.debug('Cancelling block job')
                agent.vm.qemu_mon.block_job_cancel(
                    args.drives[0])
            except:
                logging.error('Failed to cancel block job')

            try:
                if args.stop_vm:
                    logging.debug('Resuming VM')
                    agent.vm.qemu_mon.cont()
            except:
                logging.error('Failed to resume VM')

            return False


        def complete_cb(event):
            if event is None:
                retq.put({'error': 'disconnected'})
                return

            if ('event' in event and
                (event['event'] == 'BLOCK_JOB_COMPLETED' or
                 event['event'] == 'BLOCK_JOB_ERROR' or
                 event['event'] == 'BLOCK_JOB_CANCELLED') and
                event['data']['device'] == args.drives[0]):
                logging.debug('Notifying job completion')
                retq.put(event)
                return False
            return True

        agent.vm.qemu_mon.async_cb.append(complete_cb)
        request_context.add_callback(cancel_cb)

        try:
            res = agent.vm.qemu_mon.drive_backup(args.drives,
                                                args.paths,
                                                args.mode)
        except PcoccError as e:
            if use_fsfreeze:
                Config().hyp.fsthaw(agent.vm)

            yield agent_pb2.GenericError(
                        kind = agent_pb2.GenericError.AgentError,
                        description = str(e))
            return

        if use_fsfreeze:
            Config().hyp.fsthaw(agent.vm)


        while True:
            try:
                res = retq.get(True, 0.1)
                complete = True
                break
            except Queue.Empty:
                pass

            r = agent.vm.qemu_mon.query_block_jobs()

            for job in r:
                if job['device'] in args.drives:
                    yield agent_pb2.SaveDriveResult(
                        status = 'running',
                        len      = int(job['len']),
                        offset   = int(job['offset']),
                        drive    = job['device'])

        if 'error' in res:
            yield agent_pb2.GenericError(
                kind = agent_pb2.GenericError.AgentError,
                        description = res['error'])
        else:
            yield agent_pb2.SaveDriveResult(status='complete', len=1, offset=1)
        return

class HAResetReq(object):
    _name = "reset"
    __metaclass__ = HAReqClass

    @staticmethod
    def handle(agent, args, request_context):
        agent.vm.qemu_mon.system_reset()
        return agent_pb2.HelloResult()

class HAMonCmdReq(object):
    _name = "monitor_cmd"
    __metaclass__ = HAReqClass

    @staticmethod
    def handle(agent, args, request_context):
        res = agent.vm.qemu_mon.human_monitor_cmd(' '.join(args.cmd))
        return agent_pb2.MonitorCmdResult(output=res)

class QemuMonitor(object):
    def __init__(self, vm):
        self.vm = vm

        # Lock for the serial port and tag allocation
        self.wlock = threading.Lock()
        self.current_tag = 1

        # Pipe to notify the client thread
        self.sp_r, self.sp_w = os.pipe()

        # Context manager for callbacks
        self.sync_cb = Queue.Queue()
        self.async_cb = []

        self.sync_cb.put(self._handle_hello)

        qmp_file = Config().batch.get_vm_state_path(vm.rank, 'monitor_socket')
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.sock.connect(qmp_file)
        except Exception as e:
            raise PcoccError("Could not connect to Qemu monitor socket:" + str(e))

        self.sock_file = self.sock.makefile()

        self.databuff = ""
        # Read the VM agent serial port socket and handle messages
        threading.Thread(target=self._client_thread).start()

        # Signal the client thread to stop when we want to exit
        threading.Thread(target=self._killer_thread).start()

        self.negotiate_caps()

    def _handle_hello(self, data):
        if 'QMP' in data:
            logging.info('Qemu monitor said hello')
        else:
            raise PcoccError('Unexepected first message from Qemu ' + data)

    def negotiate_caps_cmd(self):
        return ('{"execute": "qmp_capabilities", "arguments":{} }\n\n')

    def negotiate_caps(self):
        self.validate_reply(self.exec_cmd_sync(self.negotiate_caps_cmd()))

    def _cancel_all_requests(self):
        logging.info('Qemu monitor: cancelling pending requests')

        for cb in self.async_cb:
            cb(None)

        self.async_cb = []

        while True:
            try:
                cb = self.sync_cb.get(None)
            except Queue.Empty:
                break
            cb(None)

    def _killer_thread(self):
        """Waits for a stop_threads event and signal the client thread to stop blocking"""
        stop_threads.wait()
        logging.info("Qemu monitor: signaling serial port reader thread to exit")
        os.write(self.sp_w, "x")

    def _client_thread(self):
        logging.info("Listening to Qemu monitor for VM %d",
                     self.vm.rank)

        while True:
            sdata = self._read_sock_line()
            if sdata == None:
                logging.info("Qemu monitor for VM %d disconnected"
                             , self.vm.rank)
                break

            if len(sdata.replace("\n","")) == 0:
                continue
            self._handle_monitor(sdata)

        # If we disconnect, cancel all pending requests to the host
        # agent
        self._cancel_all_requests()

    def _read_sock_line(self):
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

    def _handle_monitor(self, monitor_data):
        """
        Run the callback for a given Qemu Monitor answer or async notification
        """
        logging.debug("Qemu monitor: received %s",
                      str(monitor_data))

        try:
            json_msg = json.loads(monitor_data)
        except Exception as e:
            # TODO: We should implement a better recovery strategy
            # from leftover garbage in the serial port
            logging.error("Host agent: cannot decode data from Qemu monitor: %s",
                          str(e))
            return

        if 'event' in json_msg:
            kept_cbs = []
            for cb in self.async_cb:
                keep = cb(json_msg)
                if keep:
                    kept_cbs.append(cb)
            self.async_cb = kept_cbs
        else:
            try:
                cb = self.sync_cb.get(False)
            except Queue.Empty:
                logging.error("Qemu monitor sent unexpected reply: %s", json_msg)
                return
            cb(json_msg)

    def register_async_cb(self, cb):
        self.wlock.acquire()
        self.async_cb.append(cb)
        self.wlock.release()

    def exec_cmd_cb(self, payload, cb):
        self.wlock.acquire()
        self.sync_cb.put(cb)
        try:
            self.sock.sendall(payload)
        except IOError as e:
            logging.warning("Failed to send message to monitor due to %s",
                            str(e))
        self.wlock.release()

    def exec_cmd_sync(self, json_cmd):
        retq = Queue.Queue()

        def return_cb(result):
            retq.put(result)

        self.exec_cmd_cb(json_cmd, return_cb)

        return retq.get()

    def quit_cmd(self):
        return '{"execute": "quit"}\n\n'

    def quit(self):
        self.validate_reply(self.exec_cmd_sync(self.quit_cmd()))

    def stop_cmd(self):
        return '{"execute": "stop"}\n\n'

    def stop(self):
        self.validate_reply(self.exec_cmd_sync(self.stop_cmd()))

    def query_dump_cmd(self):
        return '{"execute": "query-dump"}\n\n'

    def query_dump(self):
        data = self.exec_cmd_sync(self.query_dump_cmd())
        self.validate_reply(data)

        try:
            return data["return"]
        except:
            raise PcoccError("Could not parse query-dump answer: " + data)

    def query_block_jobs_cmd(self):
        return '{"execute": "query-block-jobs"}\n\n'

    def query_block_jobs(self):
        data = self.exec_cmd_sync(self.query_block_jobs_cmd())
        self.validate_reply(data)

        try:
            return data["return"]
        except:
            raise PcoccError("Could not parse query-block-jobs answer: " + data)


    def query_status_cmd(self):
        return '{"execute": "query-status"}\n\n'

    def query_status(self):
        data = self.exec_cmd_sync(self.query_status_cmd())
        self.validate_reply(data)

        try:
            return data["return"]["status"]
        except:
            raise PcoccError("Could not parse query-status answer: " + data)

    def query_migration_cmd(self):
        return '{"execute": "query-migrate" }\n\n'

    def query_migration(self):
        data = self.exec_cmd_sync(self.query_migration_cmd())
        self.validate_reply(data)

        try:
            return data["return"]
        except:
            raise PcoccError("Could not parse query-migration answer: " + data)

    def cont_cmd(self):
        return '{"execute": "cont"}\n\n'

    def cont(self):
        self.validate_reply(self.exec_cmd_sync(self.cont_cmd()))

    def dump_cmd(self, dump_file):
        return (
    '{"execute": "dump-guest-memory", "arguments":{ '
    '"paging": true, '
    '"detach": true, '
    '"protocol": "file:%s"'
    '} }\n\n'  % dump_file)

    def dump(self, dump_file):
        self.validate_reply(self.exec_cmd_sync(self.dump_cmd(dump_file)))

    def system_reset_cmd(self):
        return ('{"execute": "system_reset"}\n\n')

    def system_reset(self):
        self.validate_reply(self.exec_cmd_sync(self.system_reset_cmd()))

    def system_powerdown_cmd(self):
        return '{"execute": "system_powerdown"}\n\n'

    def system_powerdown(self):
        self.validate_reply(self.exec_cmd_sync(self.system_powerdown_cmd()))

    def human_monitor_cmd_cmd(self, human_cmd):
        return ('{"execute": "human-monitor-command", "arguments":{'
                '"command-line": "%s"} }\n\n' % human_cmd)

    def human_monitor_cmd(self, human_cmd):
        data = self.validate_reply(self.exec_cmd_sync(
                  self.human_monitor_cmd_cmd(human_cmd)))

        try:
            return data["return"]
        except:
            raise PcoccError("Could not parse human-monitor-cmd answer: " + data)

    def start_migration_cmd(self, dest_mem_file):
        return ('{"execute": "migrate", "arguments":{'
                '"uri": "exec:lzop > %s"'
                '} }\n\n'%(dest_mem_file))

    def start_migration(self, dest_mem_file):
        self.validate_reply(self.exec_cmd_sync(self.start_migration_cmd(
            dest_mem_file)))

    def cancel_migration_cmd(self):
        return '{"execute": "migrate_cancel" }}\n\n'

    def cancel_migration(self, dest_mem_file):
        self.validate_reply(self.exec_cmd_sync(self.migrate_cancel_cmd()))

    def prepare_migration_cmd(self):
        return ('{"execute": "migrate_set_speed", "arguments":{'
                         '"value": 4294967296'
                         '} }\n\n')

    def prepare_migration(self):
        self.validate_reply(self.exec_cmd_sync(self.prepare_migration_cmd()))

    def drive_backup_cmd(self, devices, dests, sync_type):
        if sync_type == DRIVE_SAVE_MODE.FULL:
            sync_arg = 'full'
        elif sync_type == DRIVE_SAVE_MODE.TOP:
            sync_arg = 'top'

        return ('{"execute": "drive-backup",'
                '"arguments": { "device": "%s",'
                '"target": "%s", "sync": "%s"'
                '} }\n\n' % (devices[0], dests[0], sync_arg))

    def drive_backup(self, device, dest, sync_type):
        self.validate_reply(self.exec_cmd_sync(self.drive_backup_cmd(
            device, dest, sync_type)))

    def block_job_cancel_cmd(self, drive):
        return ('{ "execute": "block-job-cancel",'
                '"arguments": { "device": "%s"} }\n\n' % (drive))

    def block_job_cancel(self, drive):
        self.validate_reply(self.exec_cmd_sync(self.block_job_cancel_cmd(drive)))

    def query_cpus_cmd(self):
        return '{ "execute": "query-cpus" }'

    def query_cpus(self):
        data = self.validate_reply(self.exec_cmd_sync(self.query_cpus_cmd()))
        return data['return']

    def validate_reply(self, data):
        if data is None:
            raise PcoccError('Qemu monitor disconnected')

        if 'error' in data:
            if 'desc' in data['error']:
                raise PcoccError('Qemu monitor command failed: {}'.format(
                                 str(data['error']['desc'])))
            else:
                raise PcoccError('Qemu monitor command failed')

        return data


QMP_READ_SIZE=32768

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

        try:
            ret = batch.atom_update_key('global/user',
                                        'mmp/' + path,
                                        self._do_unlock_image)
            if ret:
                batch.delete_key('global/user',
                                 'mmp/' + path)
        except Exception:
            logging.exception("Failed to unlock image")

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

    def run(self, vm, ckpt_dir=None, user_data=None, docker=False):
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
            version_string = subprocess_check_output(['lstopo-no-graphics',
                                                      '--version'])
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

        if num_cores == len(coreset) and vm.bind_vcpus:
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
            dest_mem_file = checkpoint_mem_file(vm, ckpt_dir)

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

        cmdline += ['-S']
        cmdline += ['-rtc', 'base=utc']
        cmdline += ['-device', 'qxl-vga,id=video0,ram_size=67108864,'
                   'vram_size=67108864,vgamem_mb=16']

        self._set_vm_state('temporary-disk',
                           'configuring block devices',
                           None, vm.rank)

        # Use a scsi controller for cdrom and optionnaly
        # for disk drives
        cmdline += [ '-device', 'virtio-scsi-pci,id=scsi0']

        block_idx = 0
        if vm.image_type != DRIVE_IMAGE_TYPE.NONE:
            if ckpt_dir:
                image_path = checkpoint_img_file(vm, ckpt_dir)
            else:
                image_path = vm.image_path

            # Emulate -snapshot with qemu-img so that we
            # may save the image later if needed
            snapshot_path = batch.get_vm_state_path(vm.rank, 'image_snapshot')

            with open(os.devnull, 'w') as devnull:
                try:
                    subprocess.check_call(['qemu-img', 'create',
                                           '-f', 'qcow2',
                                        '-b', image_path, snapshot_path],
                                          stdout=devnull)
                except (OSError, subprocess.CalledProcessError) as err:
                    raise InvalidImageError('failed to create temporary disk')


            atexit.register(os.remove, snapshot_path)

            cmdline += qemu_gen_block_cmdline(vm.disk_model, snapshot_path, 'drive0',
                                              block_idx, vm.disk_cache)
            block_idx += 1

        for i, drive in enumerate(vm.persistent_drives):
            path = Config().resolve_path(drive, vm)
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
            cmdline += qemu_gen_block_cmdline(vm.disk_model, path, 'drive'+str(block_idx),
                                              block_idx,
                                              vm.persistent_drives[drive]['cache'])
            block_idx += 1

        if vm.kernel:
            cmdline += ['-kernel',
                        vm.kernel]
            # If not set manually set the serial port
            # and boot device
            if not '-append' in vm.custom_args:
                cmdline += ['-append', 'console=ttyS0 root=/dev/vda1']


        if not '-boot' in vm.custom_args:
            if not vm.kernel:
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



        if docker:
            cert_dir = Docker.init_server_certs(vm)
            vm.mount_points['pcocc_vm_certs'] = {'path': cert_dir,
                                                 'readonly':True}
            vm.mount_points['host_rootfs_'] = {'path': "/"}
            logging.info("Added mount points for Docker VM")

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
        cmdline += [ '-object', 'rng-random,filename=/dev/urandom,id=rng0']
        cmdline += [ '-device', 'virtio-rng-pci,rng=rng0']

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

            if user_data is None:
                user_data = vm.user_data

            if isinstance(user_data, str):
                shutil.copyfile(Config().resolve_path(user_data, vm),
                                user_data_file)
            elif isinstance(user_data, dict):
                with open(user_data_file, 'w') as f:
                    f.write("#cloud-config\n")
                    yaml.safe_dump(user_data, f)
            else:
                shutil.copyfile('/dev/null', user_data_file)

            with open(os.devnull, 'w') as devnull:
                subprocess.check_call(['genisoimage',
                                       '-output', iso_file, '-volid', 'cidata', '-joliet',
                                       '-rock', user_data_file,
                                       meta_data_file],
                                      stdout=devnull, stderr=devnull)

            cmdline += [ '-drive', 'id=cdrom0,if=none,format=raw,'
                         'readonly=on,file={0}'.format(iso_file)]
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

        # Intialize the qemu monitor
        # This also serves as waiting for Qemu to be initialized
        while True:
            try:
                qemu_mon = QemuMonitor(vm)
                break
            #FIXME: We should use a more specific exception
            except PcoccError:
                pid, status = os.waitpid(qemu_pid, os.WNOHANG)
                if pid:
                    ret = status >> 8
                    raise HypervisorError("qemu exited during init with"
                                          " status {}".format(ret))
                time.sleep(1)


        self._set_vm_state('qemu-start',
                           'binding vcpus',
                           None, vm.rank)

        vm.qemu_mon = qemu_mon

        if autobind_cpumem:
            infos = qemu_mon.query_cpus()
            # Bind each vcpu thread on its physical cpu
            for cpu_info in infos:
                cpu_id = cpu_info["CPU"]
                cpu_thread_id = cpu_info["thread_id"]
                phys_coreid = subprocess_check_output(
                    ['hwloc-calc' , '--po', '-I', 'PU',
                     'core:%s'%(virt_to_phys_coreid[cpu_id])]  +
                    topology_cache_args).strip()
                phys_coreid = phys_coreid.split(',')[0]
                subprocess_check_output(['taskset', '-p', '-c',
                                         phys_coreid, str(cpu_thread_id)])


        if ckpt_dir:
            # Signal VM restore
            self._set_vm_state('qemu-start',
                           'restoring',
                           None, vm.rank)

            while qemu_mon.query_status() == 'inmigrate':
                time.sleep(1)
            qemu_mon.cont()
        else:
            qemu_mon.cont()

        term_sigfd = fake_signalfd([signal.SIGTERM, signal.SIGINT])

        if systemd_notify('VM is booting...', ready=True):
            heartbeat = threading.Thread(None, self.heartbeat, args=[vm])
            heartbeat.start()

        vm.enable_agent_server(HostAgent(vm))

        # Proxy the VM console until Qemu closes it
        client_sock = None

        console_log_file = open(batch.get_vm_state_path(vm.rank,
                                                   'qemu_console_log'), 'w+',
                                1)

        qemu_socket_path = batch.get_vm_state_path(vm.rank,
                                                   'qemu_console_socket')
        pcocc_socket_path = batch.get_vm_state_path(vm.rank,
                                                   'pcocc_console_socket')

        logging.debug('Connecting to qemu console %s',
                      qemu_socket_path)
        qemu_console_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        t = None
        shutdown_attempts = 0
        base_list = [term_sigfd, qemu_console_sock]

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
        self._set_vm_state('running',
                           'The vm has started',
                           None, vm.rank)

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
                    logging.debug('Received SIGTERM')
                    os.read(term_sigfd, 1024)

                    if not vm.wait_for_poweroff:
                        logging.debug('Sending quit to Qemu monitor')
                        qemu_mon.quit()
                        qemu_console_sock = None
                        break

                    if shutdown_attempts >= 3:
                        logging.info('Timed out waiting for VM to poweroff')
                        # Exit loops
                        qemu_console_sock = None
                        break

                    logging.debug('Sending powerdown to Qemu monitor')
                    qemu_mon.system_powerdown()
                    logging.info('Waiting for VM to poweroff')
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
                                            term_sigfd, 5, "qemu cleanup")

        if os.WIFEXITED(status) and os.WEXITSTATUS(status):
            logging.error("qemu exited with status %d" % os.WEXITSTATUS(status))
            ret = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            logging.error("qemu killed by signal %d" % os.WTERMSIG(status))
            ret = -1
        else:
            ret = 0

        return ret

    def heartbeat(self, vm):
        logging.debug("Starting VM heartbeat thread")
        batch = Config().batch
        while not stop_threads.wait(10):
            try:
                s_ctl = self._get_agent_ctl_safe(vm, QEMU_GUEST_AGENT_PORT, 5,
                                                 False)
            except Exception:
                logging.warning("Failed to query guest")
            else:
                try:
                    _ = batch.write_ttl('global/user',
                                        'batch-local/heartbeat.vm/{0}.{1}'.format(batch.batchid,
                                                                                  vm.rank),
                                        '',
                                        30)
                except Exception:
                    logging.exception('Failed to update VM heartbeat')

            try:
                s_ctl.terminate()
                s_ctl.communicate()
            except Exception:
                pass

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


def qemu_gen_block_cmdline(model, path, name, index, cache):
    if model == 'virtio':
        return qemu_gen_vblk_cmdline(path, name, index, cache)
    elif model == 'ide':
        return qemu_gen_ide_cmdline(path, name, index, cache)
    elif model == 'virtio-scsi':
        return qemu_gen_scsi_cmdline(path, name, index, cache)

    raise HypervisorError('Unknown block device model: {}'.format(model))

def qemu_gen_ide_cmdline(path, name, index, cache):
    cmd = []
    if index == 0:
        cmd += ['-device', 'ich9-ahci,id=ahci,addr=06.0']

    cmd += ['-device', 'ide-hd,'
            'drive={0},bus=ahci.{1}'.format(name,index)]

    return cmd + qemu_gen_drive_cmdline(path, name, cache)

def qemu_gen_vblk_cmdline(path, name, index, cache):
    cmd = qemu_gen_iothread_cmdline(name)

    # Keep adressing scheme used in previous versions
    # for compatibility
    if index == 0:
        dev_addr = 6
        func = 0
    else:
        dev_addr = (index - 1)//3 + 7
        func = (index - 1) % 3

    cmd += ['-device',
            'virtio-blk-pci,id=vblk-{0},multifunction=on,'
            'drive={0},addr={1:02d}.{2}'.format(name, dev_addr, func)]

    return cmd + qemu_gen_drive_cmdline(path, name, cache)

def qemu_gen_scsi_cmdline(path, name, index, cache):
    cmd = qemu_gen_iothread_cmdline(name)

    cmd += ['-device',
            'scsi-hd,id=scsi-hd-{0},bus=scsi0.0,scsi-id={1},'
            'drive={0}'.format(name, index)]

    return cmd + qemu_gen_drive_cmdline(path, name, cache)

def qemu_gen_iothread_cmdline(name):
    return ['-object',
           'iothread,id=ioth-{0}'.format(name)]

def qemu_gen_drive_cmdline(path, name, cache):
    return ['-drive',
            'file={0},cache={1},id={2},discard=on,'
            'if=none'.format(path, cache, name)]

def checkpoint_mem_file(vm, ckpt_dir):
    return os.path.join(ckpt_dir,'memory-vm{}'.format(vm.rank))

def checkpoint_img_file(vm, ckpt_dir):
    return os.path.join(ckpt_dir,'disk-vm{}'.format(vm.rank))
