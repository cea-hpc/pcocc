"""
This module is responsible for sending
commands to the pcocc agent
"""
import json
import logging
import threading
import atexit

from ClusterShell.NodeSet import RangeSet

from .Misc import ThreadPool
import pcocc.Error

class AgentCommand(object):
    """
    This class is the entry point
    to send commands to VMs
    it requires an initialized Cluster
    and relies on the pcoccagent in VMs
    """
    def __init__(self, cluster, direct=0, log=True):
        if cluster is None:
            raise Exception("No cluster provided")

        self._cluster = cluster
        self._direct = direct
        self.logging = log

    def vm_count(self):
        """Return the number of VMs

        Returns:
            int -- Number of VMs
        """
        return self._cluster.vm_count()

    def unfold_range(self, rng):
        """Unfolds a range in pcocc sytax

        This is where '-w' parameters
        are parsed we currently use
        ClusterShell Ranges and '-' is 'all'

        Arguments:
            rng {string/int} -- The range to be unfolded

        Raises:
            NoAgentError -- The agent was not ready

        Returns:
            array -- The list of VMs matching the range
        """

        ret = []
        if isinstance(rng, int):
            ret = [rng]
        else:
            if rng == "-":
                ret = range(0, self.vm_count())
            else:
                vmset = RangeSet(str(rng))
                ret = []
                for vmid in vmset:
                    if int(vmid) in range(0, self.vm_count()):
                        ret.append(int(vmid))

        for vm in ret:
            if self._cluster.check_agent(vm) == 0:
                raise pcocc.Error.NoAgentError()

        return ret

    def run_func(self, rng, target, *args, **kwargs):
        """Run a function sending cmd on the TBON

                Run a function and its arguments
        on a given number of threads while
        managing retun values with indexes

        Arguments:
            rng {array} -- List of VMs
            target {function} -- Function to be run
            args {tuple} -- Arguments to be passed to 'target'

        Returns:
            dict -- Command object rescribing the response
        """
        pool = ThreadPool(16)

        for i in range(0, len(rng)):
            pool.add_task(target, rng[i], *args, **kwargs)

        pool.wait_completion()
        print pool.returns
        return pool.returns

    def _chk(self, ret):
        """
        This function is used to check the return
        value from the various commands it also
        displays the corresponding error message
        """
        if ret is None:
            return None
        if ret.cmd == "error":
            log = "\n****** Could not run command ******\n"
            log += "Pcocc agent returned:\n{0}\n".format(ret.data)
            log += "***********************************"
            if self.logging:
                logging.error(log)
            return None
        jdata = {}
        try:
            jdata = json.loads(ret.data)
        except ValueError as e:
            logging.error("Error loading data returned by the pcoccagent")
            logging.error(e)
        return jdata

    #
    # Commands supported by the agent
    #

    def _exec(self, alloc_id, command, args, uid=0, gid=0):
        data = {"exe": command,
                "args": json.dumps(args),
                "alloc_id": str(alloc_id),
                "uid": str(uid),
                "gid": str(gid)}
        ret = self._cluster.command(
            index,
            "exec",
            data,
            self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def doexec(self, indexr, alloc_id, command, args, uid=0, gid=0):
        """
        Run a command in a set of VMs

        Arguments:
            indexr {string/int} -- Range to run on
            alloc_id {int} -- Allocation id to be used (global)
            command {string} -- The command to run
            args {array} -- Arguments to be passed to the command

        Keyword Arguments:
            uid {int} -- UID to use to launch the commmand (default: {0})
            gid {int} -- GID to use to launch the command (default: {0})

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._exec, alloc_id, command,
                              args, uid, gid)

    def exec_stream(self, inputs):
        """
        Attach to the excecution outputs

        Arguments:
            inputs {generator} -- Inputs generator
        """
        for v in self._cluster.exec_stream(inputs):
            yield v

    def _alloc(self, size, desc, global_alloc_id):
        ret = self._cluster.command(index,
                             "alloc_new",
                             {"size": json.dumps(size),
                              "desc": desc,
                              "global_alloc_id": json.dumps(global_alloc_id)},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return -1
        if "alloc_id" in data:
            return int(data["alloc_id"])

    def alloc(self, indexr, size, desc, global_alloc_id):
        """
        Allocate cores in a given set of VMs

        Arguments:
            indexr {string/int} -- Range to run on
            size {int} -- Number of cores to allocate
            desc {string} -- Allocation description (optionnal)
            global_alloc_id {int} -- Global allocation ID

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - The LOCAL allocation ID in case of success
                - -1 in case of error
            {"0": -1, "1": 0, "2":8}
        """

        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._alloc, size, desc, global_alloc_id)

    def _allocfree(self):
        ret = self._cluster.command(index, "alloc_get_res", {}, self._direct)
        data = self._chk(ret)
        if data is None:
            return -1
        if "ressource_left" in data:
            return int(data["ressource_left"])

    def allocfree(self, indexr):
        """
        Get the number of free cores in a given set of VMs

        Arguments:
            indexr {string/int} -- Range to run on

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - The number of free cores on the vm
                - -1 in case of error
            {"0": -1, "1": 0, "2":8}
        """

        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._allocfree)

    def _release(self, gid):
        ret = self._cluster.command(index,
                             "alloc_free",
                             {"alloc_id": json.dumps(gid)},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def release(self, indexr, gid):
        """
        Release cores in a given set of VMs

        Arguments:
            indexr {string/int} -- Range to run on
            gid {int} -- Global allocation id to release (-1 for all)

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """

        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._release, gid)

    def _freeze(self):
        ret = self._cluster.command(index, "freeze", {}, self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def freeze(self, indexr):
        """
        Suspend events from the agent

        Arguments:
            indexr {string/int} -- Range to run on

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._freeze)

    def _thaw(self, index):
        ret = self._cluster.command(index, "thaw", {}, self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def thaw(self, indexr):
        """
        Resume events from the agent

        Arguments:
            indexr {string/int} -- Range to run on

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._thaw)

    def _detach(self, index):
        ret = self._cluster.command(index, "exec_detach", {}, self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def detach(self, indexr):
        """
        Notify detach from exec stream
        (suspends Agent process IO polling)

        Arguments:
            indexr {string/int} -- Range to run on

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._detach)

    def _eof(self, index):
        ret = self._cluster.command(index, "exec_stdin_eof", {}, self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def eof(self, indexr):
        """
        Notify end of input string for Agent processes
        (closes stdin on agent processes)

        Arguments:
            indexr {string/int} -- Range to run on

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._eof)

    def _attach(self, index):
        ret = self._cluster.command(index, "exec_attach", {}, self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def attach(self, indexr):
        """
        Attach to execution streams
        (resumes the output polling)

        Arguments:
            indexr {string/int} -- Range to run on

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._attach)

    def _hello(self, index):
        ret = self._cluster.command(index, "hello", {}, self._direct)
        data = self._chk(ret)

        try:
            return int(data["time"])
        except (TypeError, ValueError):
            return -1

    def hello(self, indexr):
        """
        Used to test vm connectivity
        returns the vm UNIX timestamp

        Arguments:
            indexr {string/int} -- Range to run on

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - Unix Timestamp in case of success
                - -1 in case of error
            {"0": -1, "1": 12589}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._hello)

    def _hostname(self, index):
        ret = self._cluster.command(index, "hostname", {}, self._direct)
        data = self._chk(ret)
        if data is None:
            return False
            return
        if "hostname" in data:
            pushret(index, data["hostname"])

    def hostname(self, indexr):
        """
        Get the hostname from vms

        Arguments:
            indexr {string/int} -- Range to run on

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - Hostname in case of success
                - 1 in case of error
            {"0": 1, "1": "vm1"}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._hostname)

    def _mkdir(self, index, path, mode=777):
        ret = self._cluster.command(index, "mkdir",
                             {"path": path, "mode": str(mode)},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def mkdir(self, indexr, path, mode=777):
        """
        Create a directory in the vms

        Arguments:
            indexr {string/int} -- Range to run on
            path {string} -- Path of the directory

        Keyword Arguments:
            mode {int} -- Mode of the new directory (default: {777})

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """

        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._mkdir, path, mode)

    def _chmod(self, index, path, mode=777):
        ret = self._cluster.command(index, "chmod",
                             {"path": path, "mode": str(mode)},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def chmod(self, indexr, path, mode=777):
        """
        Change rigths for a file on a set of VMs

        Arguments:
            indexr {string/int} -- Range to run on
            path {string} -- Path of the file to change rights

        Keyword Arguments:
            mode {int} -- Mode of the new directory (default: {777})

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._chmod, path, mode)

    def _chown(self, index, path, uid, gid):
        ret = self._cluster.command(index, "chown",
                             {"path": path, "uid": str(uid), "gid": str(gid)},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def chown(self, indexr, path, uid, gid):
        """
        Change ownership for a file on a set of VMs

        Arguments:
            indexr {string/int} -- Range to run on
            path {string} -- Path of the file to change rights
            uid {int} -- UID of the file owner
            gid {int} -- GID of the file owner

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._chown, path, uid, gid)

    def _ln(self, index, src, dest):
        ret = self._cluster.command(index, "ln",
                             {"src": src, "dest": dest},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def ln(self, indexr, src, dest):
        """
        Create a symlink in a given set of VMs

        Arguments:
            indexr {string/int} -- Range to run on
            src {string} -- source path
            dest {string} -- destination path

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """

        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._ln, src, dest)

    def _mv(self, index, src, dest):
        ret = self._cluster.command(index, "mv",
                             {"src": src, "dest": dest},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def mv(self, indexr, src, dest):
        """
        Move a file in a set of vms

        Arguments:
            indexr {string/int} -- Range to run on
            src {string} -- source path
            dest {string} -- destination path

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._mv, src, dest)

    def _stat(self, index, path):
        ret = self._cluster.command(index, "stat",
                             {"path": path},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            pushret(index, data)

    def stat(self, indexr, path):
        """
        Get file info in a given set of VMs

        Arguments:
            indexr {string/int} -- Range to run on
            path {string} -- path of the file

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - dict with infos in case of success
                - 1 in case of error
            {"0": 1, "1": {"size":12231}}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._stat, path)

    def _rm(self, index, path):
        ret = self._cluster.command(index, "rm",
                             {"path": path},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def rm(self, indexr, path):
        """
        Delete a file in a given set of VMs

        Arguments:
            indexr {string/int} -- Range to run on
            path {string} -- path of the file

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._rm, path)

    def _truncate(self, path, size):
        ret = self._cluster.command(index, "truncate",
                             {"path": path, "size": str(size)},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def truncate(self, indexr, path, size):
        """
        Truncate a file in a given set of VMs

        Arguments:
            indexr {string/int} -- Range to run on
            path {string} -- path of the file
            size {int} -- size to truncate to (bytes)

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._truncate, path, size)

    def _userinfo(self, index, login):
        ret = self._cluster.command(index, "userinfo",
                             {"login": login},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            pushret(index, data)

    def userinfo(self, indexr, login):
        """
        Get user info in a given set of VMs
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._userinfo, login)

    def _lookup(self, index, hostname):
        ret = self._cluster.command(index, "lookup",
                             {"host": hostname},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            pushret(index, data["ips"])

    def lookup(self, indexr, hostname="vm0"):
        """
        Get IPs for a given hostname
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._lookup, hostname)

    def _getip(self, index, iface):
        ret = self._cluster.command(index, "getip",
                             {"iface": iface},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            pushret(index, data["ip"])

    def getip(self, indexr, iface="eth0"):
        """
        Get IPs for a network interface
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._getip, iface)

    def _unsetenv(self, index, key):
        ret = self._cluster.command(index, "unsetenv",
                             {"key": key},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def unsetenv(self, indexr, key):
        """
        Unsets an env variable in the agent env on given set of VMs

        Arguments:
            indexr {string/int} -- Range to run on
            key {string} -- variable to be unset

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._unsetenv, key)

    def _getenv(self, index, key):
        ret = self._cluster.command(index, "getenv",
                             {"key": key},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            pushret(index, data["value"])

    def getenv(self, indexr, key):
        """
        Get an env variable in the agent env on given set of VMs

        Arguments:
            indexr {string/int} -- Range to run on
            key {string} -- variable to be unset

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - the variable in case of success
                - 1 in case of error
            {"0": 1, "1": "Foo"}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._getenv, key)

    def _setenv(self, index, key, value):
        ret = self._cluster.command(index, "setenv",
                             {"key": key, "value": value},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def setenv(self, indexr, key, value):
        """
        Set an env variable in the agent env on given set of VMs

        Arguments:
            indexr {string/int} -- Range to run on
            key {string} -- variable to be unset
            value {string} -- The value to be set

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._setenv, key, value)

    def _vmstat(self, index, interupt):
        ret = self._cluster.command(index, "vmstat",
                             {"interupt": str(interupt)},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            pushret(index, data)

    def vmstat(self, indexr, interupt=False):
        """
        Read statistics from VMs

        Arguments:
            indexr {string/int} -- Range to run on
            interupt {bool} -- Defines if interrupts are to be shown

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - dict of perf data in case of success
                - 1 in case of error
            {"0": 1, "1": {"cpu":100, ...}}
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._vmstat, interupt)

    def _readfile(self, index, path, base64):
        ret = self._cluster.command(index, "readfile",
                             {"path": path, "base64": str(base64)},
                             self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            pushret(index, data["content"])

    def readfile(self, indexr, path, base64=0):
        """
        Read a file in a set of vms

        Arguments:
            indexr {string/int} -- Range to run on
            path {string} -- Path to the file to read

        Keyword Arguments:
            base64 {int} -- Whether to read in Base64 (default: {0})

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - File content in case of success
                - 1 in case of error
            {"0": 1, "1": "lorem ipsum"}
        """

        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._readfile, path, base64)

    def _writefile(self, index, path, content, base64, append):
        sappend = "false"

        if append:
            sappend = "true"

        if base64:
            ret = self._cluster.command(index, "writefile",
                                 {"path": path,
                                  "content64": content,
                                  "base64": str(base64),
                                  "append": str(sappend)},
                                 self._direct)
        else:
            ret = self._cluster.command(index, "writefile",
                                        {"path": path,
                                         "content": content,
                                         "base64": str(base64),
                                         "append": str(sappend)},
                                        self._direct)
        data = self._chk(ret)
        if data is None:
            return False
        else:
            return True

    def writefile(self, indexr, path, content, base64=False, append=False):
        """
        Write a file to a set of vms

        Arguments:
            indexr {string/int} -- Range to run on
            path {string} -- Path to the file to write
            content {string} -- Data to write in the file

        Keyword Arguments:
            base64 {bool} -- If the data are provided in base64 (default: {False})
            append {bool} -- If the data are to be appended at end of file (default:{False})

        Returns:
            dict -- Result of the command on each vm
            For each vm:
                - 0 in case of success
                - 1 in case of error
            {"0": 1, "1": 0}
        """

        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._writefile,
                             path, content, base64, append)


class AgentCommandPrinter(object):
    """
    This is an helper class to print
    the return dict from each of the
    previous commands
    """
    def __init__(self, action, data):
        self.action = action
        self.data = data

    def __str__(self):
        return json.dumps(self.data, sort_keys=True,
                          indent=4, separators=(',', ': '))
