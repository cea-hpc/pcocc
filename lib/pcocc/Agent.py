"""
This module is responsible for sending
commands to the pcocc agent
"""
import json
import logging
import threading
import atexit

from ClusterShell.NodeSet import RangeSet
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
        cluster.check_command_client()
        self.c = cluster
        self.d = direct
        self.cnt = 0
        self.logging = log
        self.cntLock = threading.Lock()
        atexit.register(self.__del__)

    def vm_count(self):
        """Return the number of VMs
        
        Returns:
            int -- Number of VMs
        """
        return self.c.vm_count()

    def __del__(self):
        self.c.tbon_disconnect()

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
        # Now make sure that the agent has started
        for vm in ret:
            if self.c.check_agent(vm) == 0:
                raise pcocc.Error.NoAgentError()

        return ret

    #
    # Multi-Threaded Request Engine
    #

    def _runner_get_cnt(self):
        """
        Get the current number of requests
        """
        self.cntLock.acquire()
        ret = self.cnt
        self.cntLock.release()
        return ret

    def _runner_inc_cnt(self):
        """
        Increment the current number of requests
        """
        self.cntLock.acquire()
        self.cnt = self.cnt + 1
        self.cntLock.release()

    def _runner_dec_cnt(self):
        """
        Decrement the current number of requests
        """
        self.cntLock.acquire()
        self.cnt = self.cnt - 1
        self.cntLock.release()

    def run_func(self, rng, target, args):
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

        threads = []
        returns = {}
        returnslock = threading.Lock()

        def pushret(ident, ret):
            returnslock.acquire()
            returns[str(ident)] = ret
            returnslock.release()
            self._runner_dec_cnt()

        for i in range(0, len(rng)):
            while 10 < self._runner_get_cnt():
                pass
            t = threading.Thread(target=target, args=(pushret, rng[i],) + args)
            threads.append(t)
            self._runner_inc_cnt()
            t.start()

        for i in range(0, len(threads)):
            th = threads[i]
            th.join()

        return returns

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

    def _exec(self, pushret, index, alloc_id, command, args, uid=0, gid=0):
        data = {"exe": command,
                "args": json.dumps(args),
                "alloc_id": str(alloc_id),
                "uid": str(uid),
                "gid": str(gid)}
        ret = self.c.command(
            index,
            "exec",
            data,
            self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng,
                             self._exec,
                             (alloc_id,
                              command,
                              args,
                              uid,
                              gid,)
                             )

    def exec_stream(self, inputs):
        """
        Attach to the excecution outputs
        
        Arguments:
            inputs {generator} -- Inputs generator
        """

        for v in self.c.exec_stream(inputs):
            yield v

    def _alloc(self, pushret, index, size, desc, global_alloc_id):
        ret = self.c.command(index,
                             "alloc_new",
                             {"size": json.dumps(size),
                              "desc": desc,
                              "global_alloc_id": json.dumps(global_alloc_id)},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, -1)
            return
        if "alloc_id" in data:
            pushret(index, int(data["alloc_id"]))

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
        return self.run_func(rng, self._alloc, (size, desc, global_alloc_id))

    def _allocfree(self, pushret, index):
        ret = self.c.command(index, "alloc_get_res", {}, self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, -1)
            return
        if "ressource_left" in data:
            pushret(index, int(data["ressource_left"]))

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
        return self.run_func(rng, self._allocfree, ())

    def _release(self, pushret, index, gid):
        ret = self.c.command(index,
                             "alloc_free",
                             {"alloc_id": json.dumps(gid)},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng, self._release, (gid,))

    def _freeze(self, pushret, index):
        ret = self.c.command(index, "freeze", {}, self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng, self._freeze, ())

    def _thaw(self, pushret, index):
        ret = self.c.command(index, "thaw", {}, self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng, self._thaw, ())

    def _detach(self, pushret, index):
        ret = self.c.command(index, "exec_detach", {}, self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng, self._detach, ())

    def _eof(self, pushret, index):
        ret = self.c.command(index, "exec_stdin_eof", {}, self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng, self._eof, ())

    def _attach(self, pushret, index):
        ret = self.c.command(index, "exec_attach", {}, self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng, self._attach, ())

    def _hello(self, pushret, index):
        ret = self.c.command(index, "hello", {}, self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, -1)
            return
        if "time" in data:
            pushret(index, int(data["time"]))

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
        return self.run_func(rng, self._hello, ())

    def _hostname(self, pushret, index):
        ret = self.c.command(index, "hostname", {}, self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
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
        return self.run_func(rng, self._hostname, ())

    def _mkdir(self, pushret, index, path, mode=777):
        ret = self.c.command(index, "mkdir",
                             {"path": path, "mode": str(mode)},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng, self._mkdir, (path, mode,))

    def _chmod(self, pushret, index, path, mode=777):
        ret = self.c.command(index, "chmod",
                             {"path": path, "mode": str(mode)},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng, self._chmod, (path, mode,))

    def _chown(self, pushret, index, path, uid, gid):
        ret = self.c.command(index, "chown",
                             {"path": path, "uid": str(uid), "gid": str(gid)},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng, self._chown, (path, uid, gid,))

    def _ln(self, pushret, index, src, dest):
        ret = self.c.command(index, "ln",
                             {"src": src, "dest": dest},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng, self._ln, (src, dest, ))

    def _mv(self, pushret, index, src, dest):
        ret = self.c.command(index, "mv",
                             {"src": src, "dest": dest},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng, self._mv, (src, dest, ))

    def _stat(self, pushret, index, path):
        ret = self.c.command(index, "stat",
                             {"path": path},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
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
        return self.run_func(rng, self._stat, (path, ))

    def _rm(self, pushret, index, path):
        ret = self.c.command(index, "rm",
                             {"path": path},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng, self._rm, (path, ))

    def _truncate(self, pushret, index, path, size):
        ret = self.c.command(index, "truncate",
                             {"path": path, "size": str(size)},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng, self._truncate, (path, size, ))

    def _userinfo(self, pushret, index,  login):
        ret = self.c.command(index, "userinfo",
                             {"login": login},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, data)

    def userinfo(self, indexr, login):
        """
        Get user info in a given set of VMs
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._userinfo, (login, ))

    def _lookup(self, pushret, index, hostname):
        ret = self.c.command(index, "lookup",
                             {"host": hostname},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, data["ips"])

    def lookup(self, indexr, hostname="vm0"):
        """
        Get IPs for a given hostname
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._lookup, (hostname, ))

    def _getip(self, pushret, index, iface):
        ret = self.c.command(index, "getip",
                             {"iface": iface},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, data["ip"])

    def getip(self, indexr, iface="eth0"):
        """
        Get IPs for a network interface
        """
        rng = self.unfold_range(indexr)
        return self.run_func(rng, self._getip, (iface, ))

    def _unsetenv(self, pushret, index, key):
        ret = self.c.command(index, "unsetenv",
                             {"key": key},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng, self._unsetenv, (key, ))

    def _getenv(self, pushret, index, key):
        ret = self.c.command(index, "getenv",
                             {"key": key},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
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
        return self.run_func(rng, self._getenv, (key, ))

    def _setenv(self, pushret, index, key, value):
        ret = self.c.command(index, "setenv",
                             {"key": key, "value": value},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng, self._setenv, (key, value, ))

    def _vmstat(self, pushret, index, interupt):
        ret = self.c.command(index, "vmstat",
                             {"interupt": str(interupt)},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
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
        return self.run_func(rng, self._vmstat, (interupt, ))

    def _readfile(self, pushret, index, path, base64):
        ret = self.c.command(index, "readfile",
                             {"path": path, "base64": str(base64)},
                             self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
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
        return self.run_func(rng, self._readfile, (path, base64, ))

    def _writefile(self, pushret, index, path, content, base64, append):
        sappend = "false"

        if append:
            sappend = "true"

        if base64:
            ret = self.c.command(index, "writefile",
                                 {"path": path,
                                  "content64": content,
                                  "base64": str(base64),
                                  "append": str(sappend)},
                                 self.d)
        else:
            ret = self.c.command(index, "writefile",
                                 {"path": path,
                                  "content": content,
                                  "base64": str(base64),
                                  "append": str(sappend)},
                                 self.d)
        data = self._chk(ret)
        if data is None:
            pushret(index, 1)
        else:
            pushret(index, 0)

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
        return self.run_func(rng,
                             self._writefile,
                             (path, content, base64, append))


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
