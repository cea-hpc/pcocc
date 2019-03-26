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

from abc import ABCMeta

import agent_pb2

from ClusterShell.NodeSet import NodeSet
from ClusterShell.MsgTree import MsgTree
from google.protobuf.json_format import MessageToJson
from .Misc import ThreadPool
from .Error import AgentCommandError
from .Misc import fake_signalfd


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
        pool = ThreadPool(256)

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
    def attach_stdin(cls, cluster, indices, execid, stdin=None):
        if stdin is None:
            stdin=os.dup(sys.stdin.fileno())

        def close_stdin():
            logging.debug("Closing dup'ed stdin at RPC termination")
            try:
                os.close(stdin)
            except OSError:
                pass

        def iterin():
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

        return cls.attach(cluster, indices, execid, iterin(), close_stdin)


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
