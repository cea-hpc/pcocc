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
import re
import stat
import sys
import termios
import atexit
import time
import subprocess
import shutil
import pty
import random
import tempfile
import grp
import shlex
import json
import logging
import signal
import click

from distutils import spawn
from pwd import getpwnam
from ClusterShell.NodeSet import RangeSet

from .Agent import AgentCommand, DEFAULT_AGENT_TIMEOUT, WritableVMRootfs
from . import agent_pb2

from .Container import OciRuntimeConfig
from .Config import Config
from .Error import PcoccError
from .Image import ContainerBundleView
from .Misc import path_join, pcocc_at_exit, get_current_user, getgrouplist


class Runner(object):
    def is_native(self):
        """To be implemented in child classes."""
        raise NotImplementedError()

    def set_cwd(self, cwd, forced=False):
        """To be implemented in child classes."""
        raise NotImplementedError()

    def mirror_env(self):
        """To be implemented in child classes."""
        raise NotImplementedError()

    def run(self):
        """To be implemented in child classes."""
        raise NotImplementedError()

    def set_env_var(self, key, value, prefixexpand=None):
        """To be implemented in child classes."""
        raise NotImplementedError()

    def set_user(self, user):
        """To be implemented in child classes."""
        raise NotImplementedError()

    def set_script(self, script):
        """To be implemented in child classes."""
        raise NotImplementedError()

    def set_configuration(self,
                          proc,
                          node,
                          core,
                          nodelist=None,
                          part=None):
        """To be implemented in child classes."""
        raise NotImplementedError()

    # Common methods for runners
    def __init__(self):
        """Instanciates a generic runner."""
        self.argv = []
        self.pty = False
        self.launcher = []
        self.module = []
        self.user = get_current_user().pw_name

    def is_remote(self):
        return False

    def set_argv(self, argv):
        """Set the command inside the runner.

        Arguments:
            argv {array of strs} -- command to be run.

        Returns:
            Runner -- Runner to chain commands

        """
        self.argv = argv
        return self

    def set_pty(self, use_pty=True):
        """Run the command inside a PTY.

        Keyword Arguments:
            pty {bool} -- run in a PTY (default: {True})

        Returns:
            Runner -- Runner to chain commands

        """
        self.pty = use_pty
        return self

    def getenv(self, key):
        """Get an environment variable from CLI env.

        Arguments:
            key {string} -- Name of the key to retrieve

        Raises:
            PcoccError: no such key in environment

        Returns:
            string -- value of of the key
        """
        if key not in os.environ:
            raise PcoccError("Failed to retrieve {}".format(key) +
                             " environment variable")
        return os.environ[key]

    def add_mount(self, mnt):
        """Not implemented"""
        raise PcoccError("Mounts can only be defined within containers")


def _get_primary_group(user):
    try:
        gid = getpwnam(user).pw_gid
    except KeyError:
        raise PcoccError("User {} not found".format(user))

    return gid


def gen_user_group_list(user, gid):
    groups = getgrouplist(user, gid)
    r = {}
    for g in groups:
        r[grp.getgrgid(g).gr_name] = g

    return r

def make_raw_terminal(self_stdin):
    """Set the terminal to a RAW mode

    Arguments:
        self_stdin {fd} -- stdin file-descriptor to set

    Returns:
        termios -- Old terminal configuration
    """
    # Raw terminal
    old = termios.tcgetattr(self_stdin)
    new = list(old)
    new[3] = new[3] & ~termios.ECHO & ~termios.ISIG & ~termios.ICANON
    termios.tcsetattr(self_stdin, termios.TCSANOW, new)
    return old


def restore_terminal(old):
    """Restore terminalconfiguration

    Arguments:
        old {termios} -- Terminal configuration to restore
    """
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW,
                      old)


class Env(object):
    """This class handles environment variables for containers
    """
    @classmethod
    def _split_or_resolve_env_var(cls, variable):
        """Internal method used to parse environment variables

        Arguments:
            object {cls} -- Reference to class
            variable {str} -- environment variable to parse (A=B or A)

        Raises:
            PcoccError: Format was A and A is not in environment

        Returns:
            array of str -- [0] key [1] value
        """
        splitvar = variable.split("=")
        if len(splitvar) < 2:
            if not splitvar[0] in os.environ:
                raise PcoccError("Invalid environment variable format "
                                 "'{}' expected 'KEY=VALUE'".format(variable) +
                                 " or KEY with 'KEY' in current env")
            else:
                splitvar.append(os.environ[splitvar[0]])

        ret = []
        ret.append(splitvar[0])
        ret.append("=".join(splitvar[1:]))
        return ret

    @classmethod
    def _extract_with_re_from_env(cls, rex):
        """Extract environment variable using regular expression

        Arguments:
            rex {str} -- regular expression to be used

        Raises:
            PcoccError: Invalid regular expression

        Returns:
            array of str -- List of matching variable names
        """
        matches = []
        try:
            test_expr = re.compile(rex)
        except re.error:
            raise PcoccError("Environment matching expr " +
                             "re({}) does not seem ".format(rex) +
                             "to be a valid regexpr")

        for k in os.environ:
            match = test_expr.match(k)
            if match:
                matches.append(k)

        return matches

    @classmethod
    def append(cls, runner, array_of_vars):
        """Append a set a variable to a runner

        Arguments:
            runner {Runner} -- the runner to update
            array_of_vars {array of str} -- list of vars A=B A Re(*XX)
        """
        if array_of_vars is None:
            return

        # Detect widlcards
        rexpr = re.compile(r"re\((.+)\)")

        to_delete = []
        to_append = []

        # Make sure we have a list as .delete is convenient
        array_of_vars = list(array_of_vars)

        for variable in array_of_vars:
            match = rexpr.match(variable)
            if match and len(match.groups()) == 1:
                expr = match.group(1)
                matches = cls._extract_with_re_from_env(expr)
                # It is not safe to delete while walking the array
                to_delete.append(variable)
                # Save new vars for latter addition
                to_append = to_append + matches

        # Delete identified regular expressions
        for k in to_delete:
            array_of_vars.remove(k)

        # Push potential new vars (as 'A' value is retrieved below )
        array_of_vars = array_of_vars + to_append

        # Now walk the array for regular addition A[=B]
        for variable in array_of_vars:
            splitvar = cls._split_or_resolve_env_var(variable)
            runner.set_env_var(splitvar[0], splitvar[1])

    @classmethod
    def _path_append(cls,
                     runner,
                     array_of_path,
                     operation="PREFIX",
                     separ=":"):
        """Internal helper to handle path manipulation for env

        Arguments:
            runner {Runner} -- the target runner
            array_of_path {array of str} -- list of paths to append

        Keyword Arguments:
            op {str} -- operations to be perfommed (PREFIX/SUFFIX)
                        (default: {"PREFIX"})
            separ {str} -- Separator to use when concatenating (default: {":"})

        Raises:
            PcoccError: Failed to parse variable format
            PcoccError: No such operation ('op')
        """
        if array_of_path is None:
            return

        for path_entry in array_of_path:
            splitvar = cls._split_or_resolve_env_var(path_entry)
            if splitvar is None:
                raise PcoccError("Could not parse {}".format(path_entry))
            source_vals = splitvar[1].split(separ)

            try:
                current_val_in_target = runner.getenv(splitvar[0])
                target_vals = current_val_in_target.split(separ)
            except PcoccError:
                # Assume not present in target
                target_vals = []

            if operation == "PREFIX":
                new_list = source_vals + target_vals
            elif operation == "SUFFIX":
                new_list = target_vals + source_vals
            else:
                raise PcoccError("No such path"
                                 " operation '{}'".format(operation))

            runner.set_env_var(splitvar[0],
                               separ.join(new_list),
                               prefixexpand=operation)

    @classmethod
    def path_prefix(cls, runner, array_of_prefixes, separ=":"):
        """Add environment variable by prefixing to the runner

        Arguments:
            runner {Runner} -- target runner
            array_of_prefixes {array of str} -- list of vars to prefix A or A=B

        Keyword Arguments:
            separ {str} -- Separator to concat with (default: {":"})
        """
        cls._path_append(runner,
                         array_of_prefixes,
                         operation="PREFIX",
                         separ=separ)

    @classmethod
    def path_suffix(cls, runner, array_of_suffixes, separ=":"):
        """Add environment variable by suffixing to the runner

        Arguments:
            runner {Runner} -- target runner
            array_of_suffixes {array of str} -- list of vars to suffix A or A=B

        Keyword Arguments:
            separ {str} -- Separator to concat with (default: {":"})
        """
        cls._path_append(runner,
                         array_of_suffixes,
                         operation="SUFFIX",
                         separ=separ)


class Mount(object):
    """Mountpoint parsing and management
    """
    @classmethod
    def parse(cls, mountdef):
        """Parse a mountpoint to insert in container

        Arguments:
            object {cls} -- mount class
            mountdef {str} -- mountpoint definition
                              SRC:DEST or src=SRC,dest=DEST,type=XX,opt=A,B=X,C

        Raises:
            PcoccError: Opt param must be the last one
            PcoccError: Bad mount syntax
            PcoccError: No such parameter
            PcoccError: At least src is required

        Returns:
            dict -- OCI mountpoint definition
        """
        def full_expand_path(path, fstype="bind"):
            """Expand path for bind mounts

            Arguments:
                path {str} -- path to be expanded

            Keyword Arguments:
                fstype {str} -- type for fs not to expand
                                special fs (default: {"bind"})

            Returns:
                str -- expanded path or path if special fs
            """
            if fstype != "bind":
                return path
            path = os.path.expandvars(path)
            path = os.path.expanduser(path)
            return os.path.abspath(path)

        param = {}
        # Check if we have the SRC:MOUNT syntax
        spdot = mountdef.split(":")
        if len(spdot) == 2:
            # It is the simple : syntax
            param["src"] = full_expand_path(spdot[0])
            param["dest"] = spdot[1]
            return param
        # Here we now consider the more verbose syntax
        # src=/XX,dest=/XX,type=XX,opt=A,B=X,C
        known_param = ["src", "dest", "type", "opt"]
        # First extract the opt array
        dopt = mountdef.split("opt=")
        if len(dopt) > 1:
            # We have an option array
            # use a different separator
            opts = "".join(dopt[1:]).replace(",", ":")
            # Make sure that we parse correctly
            for kpr in known_param:
                if kpr + "=" in opts:
                    raise PcoccError("The 'opt' param must "
                                     "be the last for mounts "
                                     " in '{}'".format(mountdef))
            mountdef = dopt[0] + "opt=" + opts

        data = mountdef.split(",")

        for elem in data:
            splitvar = elem.split("=")
            if len(splitvar) < 2:
                raise PcoccError("Bad mount syntax {}".format(elem))
            key = splitvar[0]
            value = "=".join(splitvar[1:])
            if key not in known_param:
                raise PcoccError("No such parameter '{}' "
                                 "for mount ({})".format(key, elem))
            param[key] = value



        if "type" not in param:
            param["type"] = "bind"
        # Parse opt which should be an array
        if "opt" in param:
            # Rename "opt" to "options" to fit OCI
            param["options"] = param["opt"].split(":")
            del param["opt"]
        if "dest" not in param:
            if "src" not in param:
                raise PcoccError("At least 'src' is required"
                                 " to define a mount")
            else:
                param["dest"] = param["src"]

        # We now convert src to absolute PATH
        # as bubblewrap needs to CD
        param["src"] = full_expand_path(param["src"], param["type"])

        return param

    @classmethod
    def add(cls, runner, mountlist):
        for mnt in mountlist:
            if isinstance(mnt, str):
                # We need to parse the config
                conf = cls.parse(mnt)
            elif isinstance(mnt, dict):
                # Here the config is already parsed
                # this is the case when forwarded to slurm
                conf = mnt
            else:
                raise PcoccError("Mount.add expects dict or string")
            runner.add_mount(conf)


class VirtualMachine(Runner):
    def __init__(self, cluster, rangeset=None, timeout=DEFAULT_AGENT_TIMEOUT):
        Runner.__init__(self)

        self.cluster = cluster
        if rangeset:
            # Use input rangeset
            self.target_rangeset = rangeset
        else:
            # Rangeset is by default all VMs
            self.target_rangeset = RangeSet("0-" + str(cluster.vm_count() - 1))

        self.env = []
        self.timeout = timeout
        self.core = [0]
        self.cwd = ""
        # Used if we set a process / core / node configuration
        self.command_list = []

    def is_native(self):
        return False

    def set_cwd(self, cwd, forced=False):
        self.cwd = cwd

    def mirror_env(self):
        for e, v in list(os.environ.items()):
            self.set_env_var(e, v)

    def getenv(self, key):
        for vset in self.env:
            vset = vset.split("=")
            if key == vset[0]:
                return '='.join(vset[1:])

        rangeset = RangeSet("0")
        ret = AgentCommand.getenv(self.cluster, rangeset, varname=key)

        values = [None for _ in rangeset]

        for k, e in ret.iterate(yield_results=True):
            if isinstance(e, agent_pb2.GetEnvResult):
                values[int(k)] = e.value

        ret.raise_errors()

        # In the case of a single value
        # no need to return an array
        # so that we behave as other runner's getenv
        if len(values) == 1:
            return values[0]

        return values

    def set_env_var(self, key, value, prefixexpand=None):
        self.env.append("{}={}".format(key, value))


    def mount_rootfs(self, rangeset):
        # Check if the mount point is defined in all VM templates
        for i in rangeset:
            if "host_rootfs_" not in self.cluster.vms[i].mount_points:
                raise PcoccError("'host_rootfs_' is not defined as mountpoint"
                                 " in the VM template.")

        # Check if the rootfs is already mounted
        mount_output = AgentCommand.exec_output(self.cluster,
                                                rangeset,
                                                ["mount"])

        rootfs_mounted = [True if "host_rootfs_" in e.output else False
                          for e in mount_output]

        if len([e for e in rootfs_mounted if e]) == len(rangeset):
            logging.info("Rootfs already mounted in all vms")
            return

        to_mount = []
        for idx, mounted in enumerate(rootfs_mounted):
            if not mounted:
                to_mount.append(idx)

        # Mount in VMs where it is missing
        rangeset = RangeSet(to_mount)
        AgentCommand.mount(self.cluster,
                           rangeset,
                           path="/rootfs",
                           mountid="host_rootfs_")

    def mirror(self,):
        # Start by making sure VMs are UP
        ret = AgentCommand.hello(self.cluster,
                                 self.target_rangeset,
                                 timeout=300)
        ret.iterate_all()
        with WritableVMRootfs(self.cluster, self.target_rangeset):
            self.mount_rootfs(self.target_rangeset)

    def writefile(self,
                  rangeset,
                  source,
                  destination,
                  timeout=DEFAULT_AGENT_TIMEOUT):
        """Send a file inside the target VMs

        Arguments:
            rangeset {RangeSet} -- list of vm to send the file to
            source {str} -- path to the source file
            destination {str} -- where to write the file

        Keyword Arguments:
            timeout {int} -- timeout in seconds
                             (default: {DEFAULT_AGENT_TIMEOUT})

        Raises:
            PcoccError: Could not read the source file
        """
        try:
            with open(source, "rb") as f:
                source_data = f.read()
            perms = os.stat(source)[stat.ST_MODE]
        except IOError as err:
            raise PcoccError("unable to read source file for copy: {}"
                             .format(err))

        start_time = time.time()
        ret = AgentCommand.writefile(self.cluster,
                                     rangeset,
                                     path=destination,
                                     data=source_data,
                                     perms=perms,
                                     append=False,
                                     timeout=timeout)
        for k, e in ret.iterate():
            click.secho("vm{}: {}".format(k, e), fg='red', err=True)

        click.secho("{} VMs answered in {:.2f}s".format(
            len(rangeset), time.time() - start_time),
            fg='green', err=True)

        ret.raise_errors()

    def get_core_count(self, timeout=DEFAULT_AGENT_TIMEOUT):
        ret = AgentCommand.corecount(self.cluster, self.target_rangeset, timeout)
        vm_cores = [-1 for _ in range(0, self.cluster.vm_count())]

        for k, e in ret.iterate(yield_results=True):
            if isinstance(e, agent_pb2.CoreCountResult):
                vm_cores[int(k)] = int(e.count)

        if ret.errors:
            raise PcoccError("Failed to retrieve the number of cores in VMs")

        return vm_cores

    def set_user(self, user):
        self.user = user
        return self

    def set_pty(self, use_pty=True):
        super(VirtualMachine, self).set_pty(use_pty)
        if use_pty:
            # Propagate term env var
            if "TERM" in os.environ:
                self.set_env_var("TERM", os.environ['TERM'])
            old = make_raw_terminal(sys.stdin.fileno())
            atexit.register(restore_terminal, old)

    def set_script(self, script):
        basename = os.path.basename(script)
        dest = os.path.join('/tmp', basename)
        self.writefile(self.target_rangeset, script, dest, self.timeout)
        self.set_argv(['bash', dest])

    def set_configuration(self,
                          proc,
                          node,
                          core,
                          nodelist=None,
                          part=None):
        """Check if the configuration is compatible with Native exec.

        Keyword Arguments:
            proc {int} -- number of processes (default: {1})
            node {int} -- number of nodes (default: {1})
            core {int} -- number of cores per process (default: {1})
            nodelist {str} -- list of nodes to run onto
            part {str} -- slurm partition to be used (default: {None})

        Returns:
            Native -- runner to chain commands

        """
        if part:
            raise PcoccError("Cannot specifiy partitions for running within VMs")

        if not core and not node and not proc:
            self.target_rangeset = RangeSet(list(range(self.cluster.vm_count())))
            self.command_list = []
            return

        if not core:
            core = 1

        core_count = self.get_core_count()

        if not [1 for x in core_count if core <= x]:
            raise PcoccError("No VM provides {} cores ".format(core) +
                             " maximum is {}".format(max(core_count)))

        if node and len(core_count) < node:
            raise PcoccError("Only {} VMs allocated, ".format(len(core_count)) +
                             " cannot request {}".format(node))

        # If a number of node is given
        # filter core count to only keep the largest values
        # as they are the ones most likely to accomodate
        # our processes with their core constraint
        if node and node != self.cluster.vm_count():
            for _ in range(0, len(core_count) - node):
                core_count[core_count.index(min(core_count))] = "SKIP"

        # Now apply the nodelist filtering if present
        if nodelist:
            indices_range = RangeSet(nodelist.replace("vm", ""))
            for idx, _ in enumerate(core_count):
                if idx not in indices_range:
                    core_count[idx] = "SKIP"

        core_avail = sum([x for x in core_count if x != "SKIP"])
        if core * proc > core_avail:
            err_string = ("Cannot allocate {} processes * {} cores = {} cores "
                          .format(proc, core, proc * core) +
                          " only {} cores available".format(core_avail))
            if node:
                err_string = err_string + " on {} node(s)".format(node)
            raise PcoccError(err_string)

        # Handle the direct case where we fit in nodes
        # and that each node has enough cores (N == n)
        candidate_nodes = [c for c in core_count
                           if (core < c) and (c != "SKIP")]
        if proc == len([1 for x in candidate_nodes if x]):
            newset = RangeSet()
            for idx, target_node in enumerate(candidate_nodes):
                if target_node:
                    newset.add(idx)
            # Note that in this case we dont pin
            # as we have one process per node
            self.target_rangeset = newset
            self.command_list = []
            if core:
                self.core = list(range(0, core))
            return

        # As RangeSet cannot handle multiple times the same entry
        # we have to prepare a multi-stage execution to do so
        # we will generate a list of commands to be pushed
        # in the self.command_list array as objects
        # { 'range' : '0-9', 'cores': [0,1,3]} note that the command
        # is however always the same
        for _ in range(0, proc):
            # For each process look for a slot
            for idx, cnt in enumerate(core_count):
                if cnt == "SKIP":
                    # This node was removed by the 'node' param
                    continue
                if core <= cnt:
                    # Can fit in this slot
                    core_range = list(range(int(cnt) - int(core),
                                       int(cnt)))
                    core_count[idx] = int(cnt) - int(core)
                    self.command_list.append({'range': RangeSet(str(idx)),
                                              'cores': core_range})
                    break

        # We now try to gather the commands by CPU list in order
        # to generate the smallest number of commands
        cpu_sets = set([",".join(map(str, x['cores']))
                        for x in self.command_list])
        # We now have components create the same number of rangesets
        simplified_command_list = []
        for comp in cpu_sets:
            cpu_array = list(map(int, comp.split(",")))
            candidates = [x['range']
                          for x in self.command_list
                          if x['cores'] == cpu_array]
            new_range = RangeSet(",".join(map(str, candidates)))
            simplified_command_list.append({'range': new_range,
                                            'cores': cpu_array})

        # Now save the simplified command list
        self.command_list = simplified_command_list

    def run(self):
        """ Run a command inside VM"""
        if self.command_list:
            running_commands = RangeSet()
            # Gather commands under the same EID
            execs = []

            for cmd_config in self.command_list:
                exec_id = random.randint(0, 2**63 - 1)
                execs.append(exec_id)
                # Launch tasks on rangeset
                (exec_ret,
                 exec_id) = AgentCommand.parallel_execve(self.cluster,
                                                         cmd_config['range'],
                                                         self.argv,
                                                         self.env,
                                                         self.user,
                                                         cmd_config['cores'],
                                                         display_errors=True,
                                                         timeout=self.timeout,
                                                         use_pty=self.pty,
                                                         exec_id=exec_id,
                                                         cwd=self.cwd)

                # Continue only on VMs on which the exec succeeded
                good_indices = AgentCommand.filter_vms(cmd_config['range'],
                                                       exec_ret)
                running_commands.union_update(good_indices)

            if not running_commands:
                exit_code = -1
            else:
                exit_code = AgentCommand.multiprocess_attach(self.cluster,
                                                             running_commands,
                                                             execs,
                                                             exec_ret.errors)
        else:
            # We simply run the command on the target rangeset
            # this case is when there was not call to set_configuration
            # this is the case in 'pcocc agent run'
            exit_code = AgentCommand.multiprocess_call(self.cluster,
                                                       self.target_rangeset,
                                                       self.argv,
                                                       self.env,
                                                       self.user,
                                                       self.core,
                                                       self.timeout,
                                                       self.pty,
                                                       cwd=self.cwd)

        return exit_code


class Native(Runner):
    """Run commands locally.

    Arguments:
        Runner {Runner} -- parent class (mostly virtual)
    """

    def __init__(self):
        """Instanciate a Native runner."""
        Runner.__init__(self)
        self.to_delete = None
        self.env = {}
        self.mirror = False
        self.cwd = None
        self.command = []

    def is_native(self):
        """Return if the runner is intended to run in PODS.

        Returns:
            bool -- running inside a POD

        """
        return True

    def set_cwd(self, cwd, forced=False):
        self.cwd = cwd

    def run(self):
        """Run the command locally.

        Raises:
            e -- Execution returned an error (sent up)

        """
        ret = 0
        if self.user != get_current_user().pw_name:
            raise PcoccError("Cannot change user outside a container or VM")

        # Make sure args are strs
        self.argv = [str(arg) for arg in self.argv]
        self.launcher = [str(arg) for arg in self.launcher]

        envcmd = spawn.find_executable("env")
        if envcmd is None:
            raise PcoccError("Could not locate the 'env' binary")

        # We use 'env' to block and propagate variables
        env_prefix = [envcmd]

        if not self.mirror:
            env_prefix.append("-i")
        else:
            if not self.env:
                env_prefix = []

        for k in self.env:
            env_prefix.append("{}={}".format(k, self.env[k]))

        try:
            if self.cwd:
                # Set workdir
                old_cwd = os.getcwd()
                os.chdir(self.cwd)

            run_cmd = self.launcher + env_prefix + self.argv

            if self.pty and not sys.stdout.isatty():
                logging.debug("Local run with pty: %s", " ".join(run_cmd))

                # In V < 3.4 pty.spawn returns None
                # pylint: disable=E1111
                status = pty.spawn(run_cmd)

                if sys.version_info < (3, 4):
                    # pty.spawn returns waidpid status starting in 3.4
                    # so no need to wait anymore
                    _, status = os.waitpid(-1, 0)

                if os.WIFEXITED(status):
                    retcode = os.WEXITSTATUS(status)
                    if retcode != 0:
                        raise subprocess.CalledProcessError(retcode, run_cmd)
                elif os.WIFSIGNALED(status):
                    stopsig = os.WSTOPSIG(status)
                    raise PcoccError("Child PTY"
                                     " received signal {}".format(stopsig))
            else:
                # Run the command
                logging.debug("Local run: %s", " ".join(run_cmd))

                subprocess.check_call(run_cmd,
                                      stderr=subprocess.STDOUT)

        except (OSError, subprocess.CalledProcessError) as err:
            ret = err.returncode
        finally:
            if self.to_delete:
                os.unlink(self.to_delete)
            # Reset workdir
            if self.cwd:
                os.chdir(old_cwd)

        return ret
    def set_script(self, script):
        if not os.path.isfile(script):
            raise PcoccError("Could not locate: " + script)
        self.command = [script]

    def mirror_env(self):
        self.mirror = True

    def getenv(self, key):
        # No keys inside the env
        if not self.mirror:
            # Check if variables is defined
            if key in self.env:
                return self.env[key]

            # No such variables including in staging
            raise PcoccError("Failed to retrieve {}".format(key) +
                             " environment is not mirrored")
        else:
            # Call supercalls (regular getenv)
            # as the environment is actually propagated
            return super(Native, self).getenv(key)

    def set_env_var(self, key, value, prefixexpand=None):
        """Append environment variables to the run.

        Arguments:
            key {str} -- variable name
            value {str} -- variable value

        Returns:
            Native -- runner to chain commands

        """

        self.env[key] = value
        return self

    def set_user(self, user):
        """Set user for native exec

        Arguments:
            user {string} -- user to run as

        Returns:
            Native -- runner to chain commands

        """
        self.user = user
        return self

    def set_configuration(self,
                          proc,
                          node,
                          core,
                          nodelist=None,
                          part=None):
        """Check if the configuration is compatible with Native exec.

        Keyword Arguments:
            proc {int} -- number of processes (default: {1})
            node {int} -- number of nodes (default: {1})
            core {int} -- number of cores per process (default: {1})
            nodelist {str} -- list of nodes to run onto
            part {str} -- slurm partition to be used (default: {None})

        Returns:
            Native -- runner to chain commands

        """
        if not node:
            node = 1
        if not proc:
            proc = 1
        if not core:
            core = 1
        if nodelist:
            raise PcoccError("The singleton configuration does not support"
                             " the -w/--nodelist option")
        if int(proc) * int(node) * int(core) != 1:
            raise PcoccError("The singleton configuration cannot take "
                             "process, node or core count arguments")


class Slurm(Native):
    """Run a command using Slurm (srun).

    Arguments:
        Native {Native} -- several functions are from superclass
    """

    def __init__(self):
        """Instanciates an 'empty' slurm Runner."""
        Native.__init__(self)
        self.node = None
        self.pty = False
        self.proc = 1
        self.core = None
        self.part = None
        self.nodelist = None
        self.env_vars = []
        # No need to filter variables when running
        # from slurm it does the work so we tell
        # native no to alter variable propagation
        super(Slurm, self).mirror_env()

    def set_cwd(self, cwd, forced=False):
        # We do not use the -D option
        # instead we chdir before doing the srun
        # set_cwd is then handled by Native
        super(Slurm, self).set_cwd(cwd)

    def run(self):
        """Run the command."""
        slurm_cmd = ["srun"]
        if self.pty:
            # In slurm PTY can only run on a single process
            if self.proc > 1:
                raise PcoccError("Slurm runs PTYs on a single process")
            slurm_cmd += ["--pty"]
            # Do not nest PTYs as SLURM
            # already propagated it so we deactivate
            # the PTY flag to prevent the native runner
            # from starting its own PTY
            self.pty = False
        if self.nodelist:
            slurm_cmd += ["-w", self.nodelist]
        if self.node:
            slurm_cmd += ["-N", self.node]
        if self.core:
            slurm_cmd += ["-c", self.core]
        if self.part:
            slurm_cmd += ["-p", self.part]
        slurm_cmd += ["-n", self.proc]

        self.launcher = slurm_cmd + ["--export=ALL"]

        orig_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        r =  super(Slurm, self).run()
        signal.signal(signal.SIGINT, orig_handler)

        return r

    def mirror_env(self):
        pass

    def set_configuration(self,
                          proc,
                          node=None,
                          core=None,
                          nodelist=None,
                          part=None):
        """Define the configuration to be passed to srun.

        Keyword Arguments:
            proc {int} -- number of processes (default: {1})
            node {int} -- number of nodes (default: {None})
            core {int} -- number of cores per process (default: {None})
            nodelist {str} -- list of nodes to run onto
            part {str} -- slurm partition to be used (default: {None})

        Returns:
            Slurm -- runner to chain commands

        """
        self.node = node
        self.proc = proc
        self.core = core
        self.nodelist = nodelist
        self.part = part
        return self

    def is_remote(self):
        return True


class ContainerFs(object):
    def __init__(self,
                 runner,
                 image,
                 modules=None,
                 no_defaults=False,
                 no_user=False,
                 command=None):

        # Inherit user from runner as it may
        # be set by the CLI
        self.user = runner.user
        # As we run in container restore the runner user
        # to be the local user this is needed for native
        # runner which cannot change user
        runner.set_user(get_current_user().pw_name)

        self.pty = False
        self.forced_cwd = False
        self.script = None
        self.argv = None
        self.entrypoint = []
        self.runner = runner
        self.image = image
        self.no_user = no_user
        self.no_defaults = no_defaults
        self.rootless = self.runner.is_native()


        if runner.is_remote():
            return

        self.init_transposed_bundle()

        source_config_path = path_join(self.source_oci_bundle, "config.json")
        source_rootfs_path = path_join(self.source_oci_bundle, "rootfs")
        dest_config_path = path_join(self.dest_oci_bundle, "config.json")

        # Start from a generic OCI configuration
        self.oci_config = OciRuntimeConfig(rootless=self.rootless)

        # Merge the original container OCI config from the source bundle
        # XXX: only the process field is merged
        with open(source_config_path, "r") as f:
            self.oci_config.import_config(json.load(f), "process")

        # If a command is known apply it before computing config
        # it is important as some generators may need to inspect
        # the effective command

        if command:
            self.set_argv(command)


        # Aggregate template configurations for this container
        # FIXME: generators should be able to work on a more final bundle
        self.cont_tpl = Config().containers.get(image,
                                                modules,
                                                dest_config_path,
                                                source_rootfs_path,
                                                no_defaults)




        # Merge all configurations from the container template
        self.oci_config.merge_template(self.cont_tpl)

        # Environment variables may need to be passed to the runner
        Env.append(self, self.cont_tpl.env())
        Env.path_prefix(self, self.cont_tpl.pathprefix())
        Env.path_suffix(self, self.cont_tpl.pathsuffix())

        if not self.no_user:
            self.inject_current_user()

        self.oci_config.readonly(True)

        self.insert_default_mounts()

        self.save_oci_config()

    def set_cwd(self, cwd, forced=False):
        """Set current working directory in container

        Check if OCI CWD is currently empty
        if not it has higher priority than
        the "forced=false" CWD which is
        given when no "--cwd" is passed to run
        also we consider that a value of /
        present in several images can be overriden
        a CWD value of "-" can bypass this behavior
        in the exceptionnal case where the command
        is path relative from / as workdir

        Arguments:
            cwd {str} -- path to the new cwd

        Keyword Arguments:
            forced {bool} -- if the cwd was set by cli (default: {False})
        """
        oci_cwd = self.oci_config.cwd()
        if (oci_cwd and
                oci_cwd != "/" and
                not forced):
            return
        if cwd == "-":
            logging.info("OCI image CWD is forced")
            cwd = oci_cwd
        self.oci_config.set_cwd(cwd)

    def getenv(self, key):
        oci_env = self.oci_config.get_env()
        if key in oci_env:
            return oci_env[key]

        raise PcoccError("Failed to retrieve {}".format(key) +
                         " environment variable from OCI Config")

    def add_mount(self, mnt):
        self.oci_config.add_mount(mnt["src"],
                                  mnt["dest"],
                                  mount_type=mnt.get("type", "bind"),
                                  options=mnt.get("opt", None))

    def set_env_var(self, key, value, prefixexpand=None):
        # FIXME: the bwrap-oci launch method doesn't properly escape
        # environment variables
        if '\n' in value:
            logging.info("Ignoring variable: %s", key)
            return

        self.oci_config.set_env(["{}={}".format(key, value)])


    def _resolve_mount_destination(self):
        """Make sure all mounts have both a source and destination
        """
        for mount in self.oci_config.mounts:
            if "destination" not in mount:
                mount["destination"] = mount["source"]
            if "type" not in mount:
                mount["type"] = "bind"

    def _container_create_mount_directories(self):
        dest_fs = path_join(self.dest_oci_bundle, "rootfs")
        source_fs = path_join(self.source_oci_bundle, "rootfs")

        to_delete_mounts = []
        # Create a directory / empty file for each mount
        for mount in self.oci_config.mounts:
            msource = mount["source"]
            mtarget = mount["destination"]
            mtype = mount["type"]

            # We ignore the existence test for special FSs
            special_fs = ["proc", "sysfs", "tmpfs",
                          "devpts", "shm", "mqueue", "cgroup"]

            target_path = path_join(dest_fs, mtarget)
            source_path = path_join(source_fs, mtarget)

            if not os.path.exists(msource):
                if os.path.islink(msource):
                    mtarget_type = "file"
                    if not os.path.exists(msource):
                        # Skip broken links, insert them in the tree instead of mounting
                        to_delete_mounts.append(mount)
                        linkto = os.readlink(msource)
                        os.symlink(linkto, target_path)
                        continue
                elif (mtype in special_fs) or (msource in special_fs):
                    # Assume directory
                    mtarget_type = "dir"
                else:
                    logging.warning("Asked to mount '%s' "
                                    "which does not exist, "
                                    "skipping.\n",
                                    msource)
                    to_delete_mounts.append(mount)
                    continue
            elif os.path.isdir(msource):
                mtarget_type = "dir"
            else:
                mtarget_type = "file"

            if (not os.path.exists(source_path) and
                    not os.path.exists(target_path)):
                logging.info("Need to reverse mount for %s", target_path)
                if mtarget_type == "file":
                    parent_dir = os.path.dirname(target_path)
                    if not os.path.exists(parent_dir):
                        os.makedirs(parent_dir)
                    open(target_path, "a").close()
                elif mtarget_type == "dir":
                    os.makedirs(target_path)

        for mnt in to_delete_mounts:
            self.oci_config.mounts.remove(mnt)

    def _container_reverse_mount(self, rootfs_path=None):
        source_fs = path_join(self.source_oci_bundle, "rootfs")
        dest_fs = path_join(self.dest_oci_bundle, "rootfs")

        forward_mounts = set([m["destination"]
                              for m in self.oci_config.mounts])
        reverse_mounts = set()

        def update_work_rootfs(path="/"):
            work_path = path_join(dest_fs, path)
            source_path = path_join(source_fs, path)
            dir_content = set(os.listdir(work_path))

            if not dir_content:
                if os.path.exists(source_path) and path not in forward_mounts:
                    reverse_mounts.add(path)
                return

            if os.path.exists(source_path):
                source_content = set(os.listdir(source_path))
                to_create = source_content - dir_content
                for elem in to_create:
                    work_elem_path = path_join(work_path, elem)
                    source_elem_path = path_join(source_path, elem)

                    if not os.path.exists(work_elem_path):
                        if os.path.islink(source_elem_path):
                            linkto = os.readlink(source_elem_path)
                            os.symlink(linkto, work_elem_path)
                        elif os.path.isdir(source_elem_path):
                            os.mkdir(work_elem_path)
                        else:
                            open(work_elem_path, "w").close()
                            if os.stat(source_elem_path).st_size > 0:
                                reverse_mounts.add(path_join(path, elem))
                            else:
                                # Maybe check file permissions
                                pass

            # Recurse in children directories (ignore symlinks)
            new_dir_content = set(os.listdir(work_path))
            next_level = [e for e in new_dir_content
                          if (not os.path.islink(path_join(work_path, e)) and
                              os.path.isdir(path_join(work_path, e)))]
            for elem in next_level:
                update_work_rootfs(path_join(path, elem))

        update_work_rootfs()

        logging.debug('reverse_mounts: %s', str(reverse_mounts))
        for mnt in reverse_mounts:
            if rootfs_path:
                mount_source_fs = path_join(rootfs_path, mnt)
            else:
                mount_source_fs = path_join(source_fs, mnt)
            self.oci_config.add_mount(mount_source_fs,
                                      mnt,
                                      prepend=True)


    def insert_default_mounts(self):
        self.oci_config.mirror_mount("/dev/shm/", transpose=False)
        self.oci_config.mirror_mount("/tmp/", transpose=False)
        self.oci_config.mirror_mount("/etc/resolv.conf", transpose=False)


    def setup_transposed_bundle(self, rootfs_path=None):
        self._resolve_mount_destination()
        self._container_create_mount_directories()
        self._container_reverse_mount(rootfs_path=rootfs_path)
        self.save_oci_config()

    def init_transposed_bundle(self):
        # Get a view into the source bundle from the cache
        self.source_bundle_view = ContainerBundleView(self.image)
        self.source_oci_bundle = self.source_bundle_view.get()

        if self.rootless:
            self.dest_oci_bundle = tempfile.mkdtemp()
        else:
            tmp_rootfs_dir = os.path.join(Config().batch.cluster_state_dir,
                                         "cont_bundles")
            if not os.path.exists(tmp_rootfs_dir):
                os.makedirs(tmp_rootfs_dir, mode=0o700)
            self.dest_oci_bundle = tempfile.mkdtemp(dir=tmp_rootfs_dir)

        pcocc_at_exit.register(self.cleanup_transposed_bundle)

        # Make sure to resolve symlinks
        self.dest_oci_bundle = os.path.realpath(self.dest_oci_bundle)

        # Copy the config in the transposed bundle
        shutil.copy(path_join(self.source_oci_bundle, "config.json"),
                    path_join(self.dest_oci_bundle, "config.json"))

        # Create an empty rootfs in the transposed bundle
        os.makedirs(path_join(self.dest_oci_bundle, "rootfs"))

    def cleanup_transposed_bundle(self):
        self.source_bundle_view.cleanup()
        shutil.rmtree(self.dest_oci_bundle)

    def save_oci_config(self):
        bundle_config = path_join(self.dest_oci_bundle, "config.json")
        logging.debug("Saving OCI config: %s", self.oci_config.config)
        self.oci_config.save(bundle_config, transpose_prefix=(not self.rootless))

    def insert_user_in_etc_passwd(self,
                                  etcpasswd,
                                  user,
                                  home,
                                  uid,
                                  gid,
                                  outfile=None):
        """Insert a new user in container.

        Arguments:
            etcpasswd {str} -- path to target /ect/passwd
            user {str} -- username to be inserted
            home {str} -- path to user's home
            uid {int} -- UID of the new user
            gid {int} -- GID of the new user

        Keyword Arguments:
            outfile {str} -- where to output the new file (default: {None})
        """
        if not os.path.exists(etcpasswd):
            # No /etc/passwd ignore
            return

        data = ""
        with open(etcpasswd, "r") as pwdf:
            data = pwdf.read()

        lines = data.split("\n")

        ret = ""

        user_found = False
        for line in lines:
            entries = line.split(":")
            if len(entries) == 7:
                if entries[0] == user:
                    # We need to alter
                    entries[2] = str(uid)
                    entries[3] = str(gid)
                    entries[5] = home
                    user_found = True

                ret = ret + ":".join(entries) + "\n"

        if not user_found:
            ret = (ret + user + ":x:" +
                   str(uid) + ":" + str(gid) +
                   "::" + home + ":/bin/sh")

        if not outfile:
            outfile = etcpasswd

        # Now add the user to the container
        with open(outfile, "w") as pwdf:
            pwdf.write(ret)

    def insert_groups_in_etc_group(self, etcgroup, user, gid, outfile=None):
        """Injects calling user's groups in the container.

        Arguments:
            etcgroup {str} -- path to the target /etc/group
            user {str} -- user to be considered
            gid {str} -- user's main GID

        Keyword Arguments:
            outfile {str} -- output to a different file (default: {None})
        """
        if not os.path.exists(etcgroup):
            # No /etc/group ignore
            return
        data = ""
        with open(etcgroup, "r") as pwdf:
            data = pwdf.read()

        lines = data.split("\n")

        ret = ""

        groups = gen_user_group_list(user, gid)
        lgroups = dict(groups)

        if gid not in list(lgroups.values()):
            # Add the self group if not present
            # and use the last group membership
            # as a default
            lgroups[user] = gid

        for line in lines:
            entries = line.split(":")

            if len(entries) == 4:
                # Is is a candidate ?
                if entries[0] in lgroups:
                    # We need to alter
                    entries[2] = str(lgroups[entries[0]])
                    del lgroups[entries[0]]
                    # Now check we are in list
                    members = entries[3].split(",")
                    if user not in members:
                        members.append(user)
                        entries[3] = ",".join(members)

                ret = ret + entries[0] + ":" + entries[1] +\
                    ":" + entries[2] + ":" + entries[3] + "\n"
        # Now all the remaining groups need to be inserted
        for key, value in list(lgroups.items()):
            ret = ret + key + ":x:" + str(value) + ":" + user + "\n"

        if not outfile:
            outfile = etcgroup

        # Now add the user to the container
        with open(outfile, "w") as pwdf:
            pwdf.write(ret)

    def inject_current_user(self):
        """Inject calling user inside the container."""

        # Get user infos
        user = self.user

        try:
            host_home = getpwnam(user).pw_dir
            ctr_uid   = getpwnam(user).pw_uid
        except KeyError:
            raise PcoccError('User {} not found'.format(user))

        ctr_gid   = _get_primary_group(user)

        # Set UID and GID
        self.oci_config.set_uid(ctr_uid)
        self.oci_config.set_gid(ctr_gid)
        self.oci_config.set_additional_gids(getgrouplist(user, ctr_gid))


        if "user" in self.oci_config.namespaces:
            host_uid = getpwnam(get_current_user().pw_name).pw_uid
            host_gid = _get_primary_group(get_current_user().pw_name)

            self.oci_config.append_uid_mapping(host_uid, ctr_uid)
            self.oci_config.append_gid_mapping(host_gid, ctr_gid)

        self.oci_config.set_env({'HOME': host_home})

        if not self.oci_config.is_mounted(host_home):
            # Since the container rootfs is read only, we mount a TMPFS
            # if there is no bind mount covering the home

            options = ["nosuid",
                       "nodev",
                       "mode=1777",
                       "rw",
                       "uid=" + str(ctr_uid),
                       "gid=" + str(ctr_gid)]

            self.oci_config.add_mount(host_home,
                                      mount_type = "tmpfs",
                                      transpose  = False,
                                      options    = options)


        # Create passwd and group files with our user
        # and bind mount them in the container
        source_passwd = path_join(self.source_oci_bundle,
                                  "rootfs/etc/passwd")
        source_group = path_join(self.source_oci_bundle,
                                 "rootfs/etc/group")

        if os.path.exists(source_passwd):
            dest_pwd_path = path_join(self.dest_oci_bundle, "passwd")
            self.insert_user_in_etc_passwd(source_passwd,
                                           user,
                                           host_home,
                                           ctr_uid,
                                           ctr_gid,
                                           outfile=dest_pwd_path)
            self.oci_config.add_mount(dest_pwd_path,
                                      "/etc/passwd")

        if os.path.exists(source_group):
            dest_grp_path = path_join(self.dest_oci_bundle, "group")
            self.insert_groups_in_etc_group(source_group,
                                            user,
                                            ctr_gid,
                                            outfile=dest_grp_path)
            self.oci_config.add_mount(dest_grp_path, "/etc/group")

    def set_argv(self, argv):
        self.argv = argv
        if argv is None:
            return

        logging.debug("Updating argv to %s", argv)

        self.oci_config.set_command(list(argv))

        return self

    def set_entrypoint(self, entrypoint):
        self.entrypoint = entrypoint
        if entrypoint is None:
            return

        if entrypoint:
            self.oci_config.set_entrypoint(list(entrypoint))

    def set_pty(self, use_pty=True):
        self.pty = use_pty
        self.runner.set_pty(use_pty)
        self.oci_config.set_terminal(use_pty)

    def set_user(self, user):
        return

    def set_script(self, script):
        if script is None:
            return

        self.script = script

        script_path = path_join(self.dest_oci_bundle, "/.pcocc_ctr_script")
        try:
            shutil.copy(script, script_path)
        except Exception:
            raise PcoccError("Unable to copy script " + script)

        self.oci_config.add_mount(script_path,
                                  "/.pcocc_ctr_script",
                                  transpose=self.transpose_path)

        self.set_argv(["/.pcocc_ctr_script"])

class NativeContainer(ContainerFs):
    """This is the configuration to run a rootless container."""

    def __init__(self,
                 runner,
                 image=None,
                 modules=None,
                 conf=None,
                 no_defaults=False,
                 no_user=False,
                 command=None):

        self.local = not runner.is_remote()

        if conf:
            self.import_configuration(runner, conf)
        else:
            if not image:
                raise PcoccError("NativeContainer requires an image")

            self.command = command
            self.no_defaults = no_defaults
            self.no_user = no_user
            self.image = image
            self.script = None
            self.env = {}
            self.argv = []
            self.prepend_env = {}
            self.append_env = {}
            self.mounts = []
            self.cwd = None
            self.modules = modules

            super(NativeContainer, self).__init__(runner,
                                                  image,
                                                  modules=self.modules,
                                                  no_defaults=self.no_defaults,
                                                  no_user=self.no_user,
                                                  command=self.command)

    def serialize_configuration(self):
        """Serialize configuration to send to the
           pcocc internal run-ctr command

        Returns:
            str -- serialized cli configuration
        """
        ret = {}
        ret["user"] = self.user
        ret["image"] = self.image
        ret["script"] = self.script
        ret["pty"] = self.pty
        ret["argv"] = self.argv
        ret["env"] = self.env
        ret["prepend_env"] = self.prepend_env
        ret["append_env"] = self.append_env
        ret["mounts"] = self.mounts
        ret["cwd"] = self.cwd
        ret["forced_cwd"] = self.forced_cwd
        ret["modules"] = self.modules
        ret["no_user"] = self.no_user
        ret["no_defaults"] = self.no_defaults
        ret["entrypoint"] = self.entrypoint
        return json.dumps(ret)

    def import_configuration(self, runner, conf):
        logging.debug("Importing serialized configuration")

        self.modules = conf["modules"]
        self.no_defaults = conf["no_defaults"]
        self.no_user = conf["no_user"]

        super(NativeContainer, self).__init__(runner,
                                              conf["image"],
                                              modules=self.modules,
                                              no_user=self.no_user,
                                              no_defaults=self.no_defaults,
                                              command=conf["argv"])

        self.set_user(conf["user"])
        self.set_argv(conf["argv"])
        self.set_entrypoint(conf["entrypoint"])
        self.set_script(conf["script"])
        self.set_pty(conf["pty"])

        # Now inject env vars in the singleton configuration
        for k in conf["env"]:
            self.set_env_var(k, conf["env"][k])

        for k, l in list(conf["prepend_env"].items()):
            for v in l:
                Env.path_prefix(self, ["{}={}".format(k, v)])

        for k, l in list(conf["append_env"].items()):
            for v in l:
                Env.path_suffix(self, ["{}={}".format(k, v)])

        self.set_cwd(conf["cwd"], forced=conf["forced_cwd"])
        Mount.add(self, conf["mounts"])

    def mirror_env(self):
        for key, value in list(os.environ.items()):
            self.set_env_var(key, value)

    def set_script(self, script):
        if self.local:
            super(NativeContainer, self).set_script(script)
        else:
            self.script = script

    def set_pty(self, use_pty=True):
        if self.local:
            super(NativeContainer, self).set_pty(pty)
        else:
            # Set runner PTY for SLURM propagation
            self.runner.set_pty(use_pty)
            self.pty = use_pty

    def set_argv(self, argv):
        logging.info("Setting native container argv")
        if self.local:
            super(NativeContainer, self).set_argv(argv)
        else:
            self.argv = argv

    def set_entrypoint(self, entrypoint):
        if self.local:
            super(NativeContainer, self).set_entrypoint(entrypoint)
        else:
            self.entrypoint = entrypoint

    def getenv(self, key):
        if self.local:
            return super(NativeContainer, self).getenv(key)

        raise PcoccError("Container environment not available")

    def set_cwd(self, cwd, forced=False):
        if self.local:
            super(NativeContainer, self).set_cwd(cwd, forced)
        else:
            self.cwd = cwd
            self.forced_cwd = forced

    def add_mount(self, mnt):
        if self.local:
            super(NativeContainer, self).add_mount(mnt)
        else:
            # Cache to forward to slurm step
            self.mounts.append(mnt)

    def set_env_var(self, key, value, prefixexpand=None):
        if self.local:
            super(NativeContainer, self).set_env_var(key, value)
        else:
            # We do not save variabes from prefix expanding
            # as we want them to be processed at slurm step
            # otherwise the variables expanded now would
            # overwrite the newly exposed variables when
            # spawned by slurm
            if prefixexpand:
                if prefixexpand == "PREFIX":
                    self.prepend_env.setdefault(key, []).append(value)
                elif prefixexpand == "SUFFIX":
                    self.append_env.setdefault(key, []).append(value)
                else:
                    raise PcoccError("No such env operation")
            else:
                # Save for configuration propagation
                self.env[key] = value

    def run_propagate(self):
        conf = self.serialize_configuration()
        command = (["pcocc"] + Config().verbose_opt + ["internal", "run-ctr", conf])

        self.runner.mirror_env()
        self.runner.set_argv(command)

        return self.runner.run()

    def run(self):
        if self.local:
            return self.run_local_bwrap()
        else:
            return self.run_propagate()

    def run_local_bwrap(self):
        # XXX
        # Workaround quoting issues with bwrap-oci arguments
        self.oci_config.quote_env()

        self.setup_transposed_bundle()

        # Time to generate the bwrapp configuration
        bwrap = spawn.find_executable("bwrap")

        if not bwrap:
            raise PcoccError("Could not locate bubblewrap")

        pwd = os.getcwd()

        os.chdir(self.dest_oci_bundle)

        try:
            bwcmd = subprocess.check_output(["bwrap-oci",
                                             "--bwrap",
                                             bwrap,
                                             "--dry-run"])
        except subprocess.CalledProcessError as err:
            raise PcoccError("Failed to generate bwrap cmdline: {}".format(err.output))
        except Exception as e:
            raise PcoccError("Failed to generate bwrap cmdline: {}".format(str(e)))

        # Needed to enable the removal of the PID namespace
        # which is not compatible with MPI SHM segments
        bwcmd = bwcmd.decode()
        bwcmd = bwcmd.replace("--as-pid-1", "")

        # Do not force CGROUP unsharing (not supported on centos)
        bwcmd = bwcmd.replace("--unshare-cgroup",
                              "--unshare-cgroup-try")

        # remove tmpfs on TMP
        # (it shall be bind mounted bug in bwrap-oci as it always add it)
        bwcmd = bwcmd.replace("--tmpfs /tmp", "")

        # If we are in an alloc do not bind /dev/tty
        if "SLURM_JOB_ID" in os.environ:
            bwcmd = bwcmd.replace("--dev-bind /dev/tty " +
                                  "/dev/tty", "")

        if self.user == get_current_user().pw_name:
            bwcmd = re.sub(r"--uid [0-9]+", "", bwcmd)
            bwcmd = re.sub(r"--gid [0-9]+", "", bwcmd)
        elif not "user" in self.oci_config.namespaces:
            raise PcoccError('Cannot change user: user namespaces are not enabled')

        bwcmd = bwcmd.replace("--sync-fd FD", "")
        bwcmd = bwcmd.replace("--info-fd FD", "")
        bwcmd = bwcmd.replace("--block-fd FD", "")

        self.runner.set_argv(shlex.split(bwcmd))
        ret = self.runner.run()

        os.chdir(pwd)
        return ret

def Container(runner,
              image=None,
              modules=None,
              conf=None,
              no_defaults=False,
              no_user=False,
              command=None):

    if runner.is_native():
        return NativeContainer(runner,
                               image,
                               modules,
                               conf,
                               no_defaults=no_defaults,
                               no_user=no_user,
                               command=command)
    else:
        raise PcoccError("Container image cannot be executed through the VM agent")
