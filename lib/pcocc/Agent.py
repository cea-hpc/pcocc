"""
This module is responsible for sending
commands to the pcocc agent
"""
import logging
import threading
import signal
import select
import os
import sys
import errno
import fcntl
import struct
import termios
import random

from abc import ABCMeta

import agent_pb2

from Tbon import mt_chain
from ClusterShell.NodeSet import NodeSet, RangeSet
from ClusterShell.MsgTree import MsgTree
from google.protobuf.json_format import MessageToJson
from .Misc import ThreadPool
from .Error import AgentCommandError, PcoccError
from .Misc import fake_signalfd
from .scripts import click

DEFAULT_AGENT_TIMEOUT=60


class AgentCommandClass(ABCMeta):
    """ Helper meta-class to define RPC classes """
    def __init__(cls, name, bases, dct):
        if '_name' in dct:
            AgentCommand.register_command(dct['_name'],
                                          dct['_request_pb'],
                                          dct['_reply_pb'],
                                          cls)
        elif '_stream_name' in dct:
            AgentCommand.register_stream_command(dct['_stream_name'],
                                                 dct['_request_pb'],
                                                 dct['_reply_pb'],
                                                 cls)
        super(AgentCommandClass, cls).__init__(name, bases, dct)


class AgentCommand(object):
    __metaclass__ = AgentCommandClass

    """Base class for all AgentCommands"""
    _request_pb = None
    _reply_pb = None


    _lock = threading.Lock()
    _registered_execs = []

    def __init__(self):
        raise Exception

    @staticmethod
    def validate_args(**kwargs):
        pass

    @staticmethod
    def validate_reply(msg):
        pass

    @classmethod
    def pretty_str(cls, msg):
        if isinstance(msg, Exception):
            return str(msg)

        return "ok"

    @classmethod
    def register_command(cls, name, request_pb, reply_pb, cmd_class):
        def single_fn(index, cluster, timeout, direct, **kwargs):
            cmd_class.validate_args(**kwargs)
            request = request_pb(**kwargs)
            # pylint: disable=W0212
            reply =  cmd_class._send_rpc_single(cluster,
                                                timeout,
                                                direct,
                                                index,
                                                name,
                                                request)
            cmd_class.validate_reply(reply)
            return reply

        @staticmethod
        def fn(cluster, rng, timeout=10, direct=0, **kwargs):
            return cls._mt_run_func(name, cmd_class, cluster, timeout,
                                    direct, rng,  single_fn, **kwargs)

        setattr(cls, name, fn)


    @classmethod
    def register_stream_command(cls, name, request_pb, reply_pb, cmd_class):
        @staticmethod
        def stream_fn(cluster, indices, timeout=10, cancel_cb=None, **kwargs):
            cmd_class.validate_args(**kwargs)

            def encap_iterin():
                yield request_pb(**kwargs)

            res, ctx = cluster.vms[0].agent_client.route_stream(
                indices,
                name,
                "_none_",
                encap_iterin())

            if cancel_cb:
                ctx.add_callback(cancel_cb)

            def canceller():
                logging.info("Cancelling RPC")
                ctx.cancel()

            return ParallelAgentResult(name,
                                       res, indices, cls.pretty_str,
                                       canceller)

        setattr(cls, name, stream_fn)



    @staticmethod
    def _send_rpc_single(cluster, timeout, direct, vmid, command, data):
        if direct == 0 :
            return cluster.vms[0].agent_client.command(vmid, command, data, timeout)
        else:
            return cluster.vms[vmid].agent_client.command(vmid, command, data, timeout)

    @staticmethod
    def _mt_run_func(name, cmd_class, cluster, timeout, direct, rng, target, *args, **kwargs):
        pool = ThreadPool(16)

        for i in range(0, len(rng)):
            pool.add_task(target, rng[i], cluster, timeout, direct, *args, **kwargs)

        # FIXME: we use an extremely long timeout instead of an
        # infinite one otherwise python seems to block SIGINTs which
        # we want to be able to catch for the CLI. We should maybe run
        # everything in a thread instead.

        return ParallelAgentResult(name,
                                   pool.completion_iterator(2**32-1),
                                   rng,
                                   cmd_class.pretty_str)

    @classmethod
    def add_intr_handler(cls, cluster, indices, execid, ctx):
        cls._lock.acquire()
        cls._registered_execs.append((cluster, indices, execid, ctx))
        if len(cls._registered_execs) == 1:
            cls._intr_r = fake_signalfd([signal.SIGINT, signal.SIGTERM])
            cls._stop_sig_r, cls._stop_sig_w = os.pipe()
            cls._intr_th_instance = threading.Thread(None, cls.intr_handler_th, None,
                                                     args=(cls._intr_r, cls._stop_sig_r))
            cls._intr_th_instance.start()
        cls._lock.release()

    @classmethod
    def del_intr_handler(cls, cluster, indices, execid, ctx):
        logging.info("Removing interrupt handler")
        cls._lock.acquire()
        cls._registered_execs.remove((cluster, indices, execid, ctx))
        if len(cls._registered_execs) == 0:
            os.write(cls._stop_sig_w, "1")
        cls._lock.release()

    @classmethod
    def intr_handler_th(cls, stop_sig_r, intr_r):
        logging.info("Starting intr thread")
        while True:
            try:
                rdr, _, _ = select.select([stop_sig_r, intr_r], [], [])
            except select.error  as e:
                logging.info("Ignoring interrupt in select")
                if e.args[0] == 4:
                    continue
                else:
                    logging.info("Abandonning interrupt monitoring due to error")
                    break
            if cls._intr_r in rdr:
                logging.info("Interrupt received")
                os.read(cls._intr_r, 1)
                cls._lock.acquire()
                for cluster, indices, eid, ctx in cls._registered_execs:
                    logging.info("Interrupt received, sending kill to %d", eid)
                    cls.kill(cluster, indices, exec_id=eid)
                    timer = threading.Timer(10, ctx.cancel)
                    ctx.add_callback(timer.cancel)
                    timer.start()
                cls._lock.release()
                return
            elif cls._stop_sig_r in rdr:
                os.read(cls._stop_sig_r, 1)
                logging.debug("Interrupt handler thread was asked to stop")
                return

    @classmethod
    def attach(cls, cluster, indices, execid, iterin, cancel_cb=None):
        def encap_iterin():
            yield agent_pb2.AttachMessage(exec_id=execid)
            for i in iterin:
                yield i

        res, ctx = cluster.vms[0].agent_client.route_stream(indices,
                                                            "attach",
                                                            "stdin",
                                                            encap_iterin())

        def del_intr_handler():
            cls.del_intr_handler(cluster, indices, execid, ctx)

        cls.add_intr_handler(cluster, indices, execid, ctx)
        if cancel_cb:
            ctx.add_callback(cancel_cb)
        ctx.add_callback(del_intr_handler)

        def canceller():
            logging.info("Cancelling RPC")
            ctx.cancel()

        return ParallelAgentResult("attach",
                                   res, indices, cls.attach_string,
                                   canceller)

    @classmethod
    def attach_stdin(cls, cluster, indices, exec_id_list, stdin=None):
        if not isinstance(exec_id_list, list):
            exec_id_list = [exec_id_list]

        if stdin is None:
            stdin=os.dup(sys.stdin.fileno())

        def close_stdin():
            logging.debug("Closing dup'ed stdin at RPC termination")
            try:
                os.close(stdin)
            except OSError:
                pass

        # Attach a signal on sigwinch to send resize messages
        def sigwinch_handler(sig, frame):
            s = struct.pack('HHHH', 0, 0, 0, 0)
            t = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, s)
            ns = struct.unpack('HHHH', t)
            for execid in exec_id_list:
                cls.resize(cluster, indices,
                            exec_id=execid,
                            row=int(ns[0]),
                            col=int(ns[1]))

        if os.isatty(sys.stdout.fileno()):
            # We do it here as we must be in main thread
            signal.signal(signal.SIGWINCH, sigwinch_handler)
            # Call the handler once to send current size
            sigwinch_handler(0,None)

        def iterin(execid):
            while True:
                try:
                    rdr, _, _ = select.select([stdin], [], [], 5)
                    if not rdr:
                        # Timeout, retry. We use this timeout to
                        # recheck periodically whether the RPC has
                        # been cancelled behing our back and we're
                        # waiting for nothing. In that case the next
                        # select will detect that the fd has gone bad
                        continue

                    data = os.read(stdin, 1048576)
                except OSError as e:
                    if e.errno == errno.EBADF:
                        data = None
                    else:
                        logging.warning("%s while reading from stdin, closing", str(e))
                        return

                except select.error  as e:
                    if e.args[0] == errno.EBADF:
                        data = None
                    else:
                        raise
                if data:
                    yield agent_pb2.IOMessage(kind=agent_pb2.IOMessage.stdin,
                                              exec_id=execid,
                                              data=data, eof=False)
                else:
                    logging.debug("Received stdin EOF")
                    yield agent_pb2.IOMessage(kind=agent_pb2.IOMessage.stdin,
                                              exec_id=execid,
                                              eof=True)
                    logging.debug("Input stream terminated")
                    return

        rets = []
        for execid in exec_id_list:
            rets.append(cls.attach(cluster, indices, execid, iterin(execid), close_stdin))

        if len(rets) == 1:
            return rets[0]
        else:
            # Here we wrap the sub Result in a fake larger result
            def canceller():
                for e in rets:
                    e.cancel()

            return ParallelAgentResult("attach",
                                mt_chain([x.result_iter for x in rets]),
                                indices,
                                cls.attach_string,
                                canceller)

    @classmethod
    def attach_string(cls, msg):
        if isinstance(msg, agent_pb2.AttachResult):
            return "attached to command stream"
        elif isinstance(msg, agent_pb2.DetachResult):
            return "detached from command stream"
        elif isinstance(msg, agent_pb2.IOMessage):
            return msg.data
        elif isinstance(msg, agent_pb2.ExitStatus):
            return "exit {}".format(msg.status)

    @classmethod
    def exec_output(cls,
                    cluster,
                    rangeset,
                    cmd,
                    timeout=DEFAULT_AGENT_TIMEOUT,
                    expect_success=True):
        ret = cls.execoutput(cluster,
                             rangeset,
                             DEFAULT_AGENT_TIMEOUT,
                             filename=cmd[0],
                             args=cmd[1:],
                             exectimeout=timeout)
        result = [None] * len(rangeset)

        for k, v in ret.iterate(yield_results=True):
            if isinstance(v, agent_pb2.ExecOutputResult):
                result[int(k)] = v

        if expect_success:
            ret.raise_errors()

        return result

    @classmethod
    def parallel_execve(cls,
                        cluster,
                        indices,
                        cmd,
                        env,
                        user,
                        cpus,
                        display_errors=True,
                        timeout=DEFAULT_AGENT_TIMEOUT,
                        use_pty=False,
                        exec_id=None,
                        cwd=""):
        # Launch tasks on rangeset
        if not exec_id:
            exec_id = random.randint(0, 2**63-1)

        logging.debug('Running in parallel: %s, with env %s', cmd, env)

        ret = cls.execve(cluster,
                         indices,
                         timeout,
                         filename=cmd[0],
                         exec_id=exec_id,
                         args=cmd[1:],
                         env=env,
                         username=user,
                         pty=use_pty,
                         cpus=cpus,
                         cwd=cwd)

        # Check if some VMs had errors during launch
        for index, err in ret.iterate():
            if isinstance(err, PcoccError):
                if display_errors:
                    click.secho("vm{}: {}".format(index, err),
                                fg='red',
                                err=True)
            else:
                raise err

        return ret, exec_id

    @staticmethod
    def filter_vms(indices, result):
        return indices.difference(RangeSet(result.errors.keys()))

    @staticmethod
    def collect_output_bg(result_iterator,
                          display_results,
                          display_errors,
                          ignore_output=False):
        def collector_th():
            exit_status = 0
            try:
                for key, msg in result_iterator.iterate(yield_results=display_results,
                                                        keep_results=(not display_results)):
                    if isinstance(msg, agent_pb2.IOMessage):
                        if ignore_output:
                            continue
                        if msg.kind == agent_pb2.IOMessage.stdout:
                            sys.stdout.write(msg.data)
                            sys.stdout.flush()
                        else:
                            sys.stderr.write(msg.data)
                            sys.stderr.flush()
                    elif isinstance(msg, agent_pb2.ExitStatus):
                        logging.info("Received Exit status")
                        if msg.status != 0 and display_errors:
                            click.secho("vm{}:".format(key) +
                                        "exited with"
                                        " exit code {}".format(msg.status),
                                        fg='red',
                                        err=True)
                        if msg.status > exit_status:
                            exit_status = msg.status
                    elif isinstance(msg, agent_pb2.DetachResult):
                        logging.info("Agent asked us to detach")
                    else:
                        # We ignore other message types for now
                        logging.debug("Ignoring message of type %s from %d",
                                      type(msg),
                                      key)

                logging.debug("Last message received from output stream: "
                              "signalling main thread")
            except Exception as err:
                if display_errors:
                    click.secho(str(err), fg='red', err=True)
                if not exit_status:
                    exit_status = -1

            # Make sure the RPC is terminated in case we exited early due
            # to some error
            result_iterator.cancel()
            result_iterator.exit_status = exit_status

        output_th = threading.Thread(None, collector_th, None)
        output_th.start()
        return output_th

    @classmethod
    def multiprocess_attach(cls,
                            cluster,
                            indices,
                            exec_id,
                            exec_errors=None,
                            ignore_output=False,
                            display_errors=True):
        # Launch streaming "attach" RPC
        attach_ret = cls.attach_stdin(cluster, indices, exec_id)
        # Collect in background thread
        output_th = cls.collect_output_bg(attach_ret,
                                          display_results=True,
                                          display_errors=display_errors,
                                          ignore_output=ignore_output)
        # Wait for collection output (timeout to not block signals)
        output_th.join(2**32-1)
        logging.info("Output thread joined\n")
        exit_code = attach_ret.exit_status

        if exec_errors and not exit_code:
            return -1

        return exit_code

    @classmethod
    def multiprocess_call(cls,
                          cluster,
                          indices,
                          cmd,
                          env,
                          user,
                          cpus,
                          timeout=DEFAULT_AGENT_TIMEOUT,
                          use_pty=False,
                          ignore_output=False,
                          display_errors=True,
                          cwd=""):
        # Launch tasks on rangeset
        exec_ret, exec_id = cls.parallel_execve(cluster,
                                                indices,
                                                cmd,
                                                env,
                                                user,
                                                cpus,
                                                display_errors=display_errors,
                                                timeout=timeout,
                                                use_pty=use_pty,
                                                cwd=cwd)

        # Continue only on VMs on which the exec succeeded
        good_indices = cls.filter_vms(indices, exec_ret)
        if not good_indices:
            return -1

        return cls.multiprocess_attach(cluster,
                                       good_indices,
                                       exec_id,
                                       exec_ret.errors,
                                       ignore_output=ignore_output,
                                       display_errors=display_errors)


class WritableVMRootfs(object):

    def __init__(self, cluster, rangeset):
        self.rangeset = rangeset
        self.cluster = cluster
        # Now check if / is writable as root
        self.did_remount = False
        self.writable = self._check_root_writable()

    def _check_root_writable(self):
        ret = AgentCommand.writefile(self.cluster,
                                     self.rangeset,
                                     DEFAULT_AGENT_TIMEOUT,
                                     path="/.pcocctest",
                                     data="test",
                                     append=True,
                                     perms=0o0755)

        for _, _ in ret.iterate(yield_results=False):
            pass

        if ret.errors:
            return False

        # If we are here we created the test file now delete it
        ret = AgentCommand.remove(self.cluster,
                                  self.rangeset,
                                  DEFAULT_AGENT_TIMEOUT,
                                  path="/.pcocctest")

        for _, _ in ret.iterate(yield_results=False):
            pass

        return True

    def _set_root_mode(self, mode="rw"):
        cmd = ["mount", "-o", "remount," + mode, "/"]
        try:
            AgentCommand.exec_output(self.cluster,
                                     self.rangeset,
                                     cmd)
        except AgentCommandError:
            raise PcoccError("Failed to remount roots in read/write")


    def __enter__(self):
        if not self.writable:
            logging.info("Remounting VM rootfs in read-write")
            self._set_root_mode("rw")
            self.writable = self._check_root_writable()
            if not self.writable:
                raise PcoccError("Failed to remount roots in read-write")
            self.did_remount = True

    def __exit__(self, typ, value, traceback):
        if self.did_remount:
            logging.info("Remounting VM rootfs in read-only")
            self._set_root_mode("ro")
            self.writable = self._check_root_writable()
            if self.writable:
                raise PcoccError("Failed to remount roots in read-only")
            self.did_remount = False


class Hello(AgentCommand):
    _name = "hello"
    _request_pb = agent_pb2.HelloMessage
    _reply_pb = agent_pb2.HelloResult

class Mkdir(AgentCommand):
    _name = "mkdir"
    _request_pb = agent_pb2.MkdirMessage
    _reply_pb = agent_pb2.MkdirResult

class Chmod(AgentCommand):
    _name = "chmod"
    _request_pb = agent_pb2.ChmodMessage
    _reply_pb = agent_pb2.ChmodResult

class Hostname(AgentCommand):
    _name = "hostname"
    _request_pb = agent_pb2.HostnameMessage
    _reply_pb = agent_pb2.HostnameResult

    @classmethod
    def pretty_str(cls, msg):
        if isinstance(msg, Exception):
            return str(msg)

        return msg.hostname

class Chown(AgentCommand):
    _name = "chown"
    _request_pb = agent_pb2.ChownMessage
    _reply_pb = agent_pb2.ChownResult

class Truncate(AgentCommand):
    _name = "truncate"
    _request_pb = agent_pb2.TruncateMessage
    _reply_pb = agent_pb2.TruncateResult

class Stat(AgentCommand):
    _name = "stat"
    _request_pb = agent_pb2.StatMessage
    _reply_pb = agent_pb2.StatResult
    @classmethod
    def pretty_str(cls, msg):
        if isinstance(msg, Exception):
            return str(msg)

        return MessageToJson(msg)

class Symlink(AgentCommand):
    _name = "symlink"
    _request_pb = agent_pb2.SymlinkMessage
    _reply_pb = agent_pb2.SymlinkResult

class Readlink(AgentCommand):
    _name = "readlink"
    _request_pb = agent_pb2.ReadlinkMessage
    _reply_pb = agent_pb2.ReadlinkResult

class Remove(AgentCommand):
    _name = "remove"
    _request_pb = agent_pb2.RemoveMessage
    _reply_pb = agent_pb2.RemoveResult

class Move(AgentCommand):
    _name = "move"
    _request_pb = agent_pb2.MoveMessage
    _reply_pb = agent_pb2.MoveResult

class Freeze(AgentCommand):
    _name = "freeze"
    _request_pb = agent_pb2.FreezeMessage
    _reply_pb = agent_pb2.FreezeResult

class Thaw(AgentCommand):
    _name = "thaw"
    _request_pb = agent_pb2.ThawMessage
    _reply_pb = agent_pb2.ThawResult

class Exec(AgentCommand):
    _name = "execve"
    _request_pb = agent_pb2.ExecMessage
    _reply_pb = agent_pb2.ExecResult
    @classmethod
    def pretty_str(cls, msg):
        if isinstance(msg, Exception):
            return str(msg)

        return "task launched"

class Kill(AgentCommand):
    _name = "kill"
    _request_pb = agent_pb2.KillMessage
    _reply_pb = agent_pb2.KillResult

class Detach(AgentCommand):
    _name = "detach"
    _request_pb = agent_pb2.DetachMessage
    _reply_pb = agent_pb2.DetachResult

class WriteFile(AgentCommand):
    _name = "writefile"
    _request_pb = agent_pb2.WriteFileMessage
    _reply_pb = agent_pb2.WriteFileResult

class Listexec(AgentCommand):
    _name = "listexec"
    _request_pb = agent_pb2.ListExecMessage
    _reply_pb = agent_pb2.ListExecResult
    @classmethod
    def pretty_str(cls, msg):
        return "\n".join(["{}\t{}\t{}\t{}".format(execid, e.running,
                                                  e.attached, e.filename)
                          for execid, e in msg.execs.iteritems()])

class Reset(AgentCommand):
    _name = "reset"
    _request_pb = agent_pb2.ResetMessage
    _reply_pb = agent_pb2.ResetResult

class MonitorCmd(AgentCommand):
    _name = "monitor_cmd"
    _request_pb = agent_pb2.MonitorCmdMessage
    _reply_pb = agent_pb2.MonitorCmdResult
    @classmethod
    def pretty_str(cls, msg):
        if isinstance(msg, Exception):
            return str(msg)

        return str(msg.output)

class DumpCmd(AgentCommand):
    _stream_name = "dump"
    _request_pb = agent_pb2.DumpMessage
    _reply_pb = agent_pb2.DumpResult

class CheckpointCmd(AgentCommand):
    _stream_name = "checkpoint"
    _request_pb = agent_pb2.CheckpointMessage
    _reply_pb = agent_pb2.CheckpointResult

class SaveDriveCmd(AgentCommand):
    _stream_name = "save"
    _request_pb = agent_pb2.SaveDriveMessage
    _reply_pb = agent_pb2.SaveDriveResult

class Mount(AgentCommand):
    _name = "mount"
    _request_pb = agent_pb2.MountMessage
    _reply_pb = agent_pb2.MountResult

class UserInfo(AgentCommand):
    _name = "userinfo"
    _request_pb = agent_pb2.UserInfoMessage
    _reply_pb = agent_pb2.UserInfoResult

class Resize(AgentCommand):
    _name = "resize"
    _request_pb = agent_pb2.ResizeMessage
    _reply_pb = agent_pb2.ResizeResult

class Corecount(AgentCommand):
    _name = "corecount"
    _request_pb = agent_pb2.CoreCountMessage
    _reply_pb = agent_pb2.CoreCountResult

class ExecOutput(AgentCommand):
    _name = "execoutput"
    _request_pb = agent_pb2.ExecOutputMessage
    _reply_pb = agent_pb2.ExecOutputResult

class Getenv(AgentCommand):
    _name = "getenv"
    _request_pb = agent_pb2.GetEnvMessage
    _reply_pb = agent_pb2.GetEnvResult

class ParallelAgentResult(object):
    """
    Manages the results for parallel client commands
    """
    def __init__(self, cmd, result_iter, rng, pretty_str, canceller=None):
        self._result_iter = result_iter
        self._rng = rng
        self._pretty_str = pretty_str
        self._errors = {}
        self._res_tree = MsgTree()
        self._canceller = canceller
        self._cmd = cmd

    @property
    def result_iter(self):
        return self._result_iter

    def cancel(self):
        self._canceller()

    def iterate_all(self, print_results=False,
                keep_results=True):
        for _, _ in self.iterate(print_results, keep_results):
            pass

        self.raise_errors()

    def iterate(self, yield_results=False, print_results=False,
                keep_results=True, yield_errors=True):

        for key, res in self._result_iter:
            if isinstance(res, Exception):
                self._errors.setdefault(key, list()).append(res)
                if yield_errors:
                    yield key, res
            else:
                if keep_results:
                    self._res_tree.add(str(key),
                                       self._pretty_str(res))
                if yield_results:
                    yield key, res

    def raise_errors(self):
        if not self._errors:
            return

        raise AgentCommandError(
            self._cmd,
            "{} failed on {}".format(
                self._cmd,
                NodeSet.fromlist(["vm{}".format(i) for i in self.errors.keys()])),
            self._errors)

    @property
    def errors(self):
        return self._errors

    def __str__(self):
        return '\n'.join(["{0}: {1}".format(
            NodeSet.fromlist(map(lambda x: "vm"+x, keys)),
            m) for m, keys in self._res_tree.walk()])
