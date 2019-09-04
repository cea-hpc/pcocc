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
import threading
import tempfile
from distutils import spawn
from pwd import getpwnam
import getpass
import grp
import shlex
import json
import logging
import signal
from ClusterShell.NodeSet import RangeSet

from .Agent import AgentCommand, DEFAULT_AGENT_TIMEOUT, WritableVMRootfs
from . import agent_pb2
from .scripts import click
from .Container import OciConfig
from .Config import Config
from .Error import PcoccError
from .Image import ContainerBundleView
from .Misc import path_join, pcocc_at_exit


class Runner(object):
    """Main class to be specialized for each runner type.

    Raises:
        NotImplementedError -- if the function was not specialized.

    """

    #
    # The virtual interface
    #
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

    def set_module(self, module):
        """To be implemented in child classes."""
        self.module.append(module)

    #
    # Common methods for runners
    #
    def __init__(self):
        """Instanciates a generic runner."""
        self.argv = []
        self.pty = False
        self.launcher = []
        self.module = []
        self.user = getpass.getuser()

    def set_argv(self, argv):
        """Set the command inside the runner.

        Arguments:
            argv {array of strs} -- command to be run.

        Returns:
            Runner -- Runner to chain commands

        """
        self.argv = argv
        return self

    def wrap_argv(self, wrapper):
        """Wrap the runner command with another (prefix).

        Arguments:
            wrapper {array of str} -- wrapper command.

        Returns:
            Runner -- Runner to chain commands

        """
        self.argv = wrapper + self.argv
        return self

    def set_launcher(self, launcher):
        """Define a launcher command to prefix the launch.

        Arguments:
            launcher {array of str} -- launcher command.

        Returns:
            Runner -- Runner to chain commands

        """
        self.launcher = launcher
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
        raise PcoccError("It is only possible to define mounts "
                         "(-v) inside containers")


def _get_primary_group(user):
    """Get the primary group for an user

    Arguments:
        user {str} -- user to inspect

    Returns:
        int -- primary group id
    """
    if user == getpass.getuser():
        return os.getgid()

    try:
        uid = getpwnam(user).pw_gid
    except KeyError:
        raise PcoccError("Could not locate user {}".format(user))

    return uid


def _getgroups_call_id(user):
    """Get group membership using the 'id' command

    Arguments:
        user {str} -- user to inspect

    Returns:
        dict -- Name -> GID
    """
    out_ids = ""
    out_groups = ""

    try:
        out_ids = subprocess.check_output(["id", "-G", user])
    except (subprocess.CalledProcessError, OSError):
        raise PcoccError("Could not use ID to find out user groups")

    try:
        out_groups = subprocess.check_output(["id", "-Gn", user])
    except (subprocess.CalledProcessError, OSError):
        raise PcoccError("Could not use ID to find out user groups")

    ids = out_ids.replace("\n", "").split(" ")
    groups = out_groups.replace("\n", "").split(" ")

    if (len(ids) == len(groups)) and groups:
        return dict(zip(groups, ids))

    raise PcoccError("Could not use ID to find out user groups")


def gen_user_group_list(user):
    """Generate group list for user.

    Arguments:
        user {str} -- NOT WORKING user to inspect (only self)

    Raises:
        PcoccError -- Tried to inspect another user (only self right now)

    Returns:
        dict -- Name -> GID

    """
    member_of = {}

    if user == getpass.getuser():
        my_groups = os.getgroups()

        for gid in my_groups:
            name = grp.getgrgid(gid).gr_name
            member_of[name] = gid

        return member_of
    else:
        # In python < 3.3 we do not have acces to getgrouplist
        # to retrieve groups from another user
        try:
            return _getgroups_call_id(user)
        except PcoccError:
            raise PcoccError("Failed at extracting user groups")


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
            runner.set_env_var(splitvar[0].encode('ascii', 'ignore'),
                               splitvar[1].encode('ascii', 'ignore'))

    @classmethod
    def _path_append(cls,
                     runner,
                     array_of_path,
                     operation="PREFIX",
                     separ=":",
                     unique=True):
        """Internal helper to handle path manipulation for env

        Arguments:
            runner {Runner} -- the target runner
            array_of_path {array of str} -- list of paths to append

        Keyword Arguments:
            op {str} -- operations to be perfommed (PREFIX/SUFFIX)
                        (default: {"PREFIX"})
            separ {str} -- Separator to use when concatenating (default: {":"})
            unique {bool} -- Force entry uniqueness (default: {True})

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

            if unique:
                # If the value is already here we remove
                # it in order to move it accordingly
                for val in source_vals:
                    try:
                        target_vals.remove(val)
                    except ValueError:
                        pass

            if operation == "PREFIX":
                new_list = source_vals + target_vals
            elif operation == "SUFFIX":
                new_list = target_vals + source_vals
            else:
                raise PcoccError("No such path"
                                 " operation '{}'".format(operation))

            runner.set_env_var(splitvar[0].encode('ascii', 'ignore'),
                               (separ.join(new_list))
                               .encode('ascii', 'ignore'),
                               prefixexpand=operation)

    @classmethod
    def path_prefix(cls, runner, array_of_prefixes, separ=":", unique=True):
        """Add environment variable by prefixing to the runner

        Arguments:
            runner {Runner} -- target runner
            array_of_prefixes {array of str} -- list of vars to prefix A or A=B

        Keyword Arguments:
            separ {str} -- Separator to concat with (default: {":"})
            unique {bool} -- If unicity should be ensured (default: {True})
        """
        cls._path_append(runner,
                         array_of_prefixes,
                         operation="PREFIX",
                         separ=separ,
                         unique=unique)

    @classmethod
    def path_suffix(cls, runner, array_of_suffixes, separ=":", unique=True):
        """Add environment variable by suffixing to the runner

        Arguments:
            runner {Runner} -- target runner
            array_of_suffixes {array of str} -- list of vars to suffix A or A=B

        Keyword Arguments:
            separ {str} -- Separator to concat with (default: {":"})
            unique {bool} -- If unicity should be ensured (default: {True})
        """
        cls._path_append(runner,
                         array_of_suffixes,
                         operation="SUFFIX",
                         separ=separ,
                         unique=unique)


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
        # as bublewrapp needs to CD
        param["src"] = full_expand_path(param["src"], param["type"])

        return param

    @classmethod
    def add(cls, runner, mountlist):
        for mnt in mountlist:
            if isinstance(mnt, (str, unicode)):
                # We need to parse the config
                mnt = mnt.encode('ascii', 'ignore')
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
        if not cluster:
            raise PcoccError("A VM cluster is required for this runner")
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
        self.cwd = path_join("/rootfs", cwd)

    def mirror_env(self):
        for e, v in os.environ.items():
            self.set_env_var(e, v)

    def getenv(self, key):
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

    def add_current_user_in_vm(self, rangeset):
        user = getpass.getuser()
        uid = getpwnam(user).pw_uid
        gid = os.getgroups()[0]
        groups = gen_user_group_list(user)

        ret = AgentCommand.useradd(self.cluster, rangeset,
                                   uid=uid, gid=gid,
                                   user=user, groups=groups)

        for k, message in ret.iterate():
            click.secho("vm{}: {}".format(k, message), fg='red', err=True)

        if ret.errors:
            raise PcoccError("Failed to insert user {0}".format(user))

    def _host_rootfs_is_present(self):
        for target_vm in self.cluster.vms:
            if "host_rootfs_" not in target_vm.mount_points:
                return False

        return True

    def mount_rootfs(self, rangeset):
        # We first need to make sure that the host_rootfs_
        # key is indeed present in the template mounts
        # otherwise we raise an exception asking to do so
        if not self._host_rootfs_is_present():
            raise PcoccError("'host_rootfs_' is not defined as mountpoint"
                             " in the VM template.")
        # First check if the rootfs is already mounted
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
        # Only send mount to identified rangeset
        rangeset = RangeSet(to_mount)

        AgentCommand.mount(self.cluster,
                           rangeset,
                           path="/rootfs",
                           mountid="host_rootfs_")

    def mount_current_user_home(self, rangeset):
        user = getpass.getuser()

        local_home = getpwnam(user).pw_dir
        # Make sure to follow any symbolic link
        local_home = os.path.realpath(local_home)

        # Make sure homes are all at the same place
        ret = AgentCommand.userinfo(self.cluster, rangeset,
                                    user=user)

        homes = {}
        for k, e in ret.iterate(yield_results=True):
            if isinstance(e, agent_pb2.UserInfoResult):
                homes[k] = e.home

        if ret.errors:
            raise PcoccError("Failed to retrieve home from VMs")

        seen_home = None
        all_same_home = True
        for _, h in homes.items():
            if seen_home is None:
                seen_home = h
            else:
                if seen_home != h:
                    all_same_home = False
                    break

        def _insert_home_on_rangeset(cluster, rangeset, seen_home, local_home):
            ret = AgentCommand.readlink(cluster, rangeset, path=seen_home)
            home_is_already_set = True
            for k, readlink_result in ret.iterate(yield_results=True):
                if isinstance(readlink_result, agent_pb2.ReadlinkResult):
                    if (os.path.normpath(readlink_result.pointee) !=
                       os.path.normpath(path_join("/rootfs", local_home))):
                        home_is_already_set = False
                else:
                    home_is_already_set = False

            if home_is_already_set:
                return

            # And now simply symlink from /rootfs/
            ret = AgentCommand.symlink(cluster, rangeset,
                                       src=path_join("/rootfs/", local_home),
                                       dst=seen_home)

            for k, e in ret.iterate():
                click.secho("vm{}: {}".format(k, e), fg='red', err=True)

            if ret.errors:
                raise PcoccError("Failed to insert user's home at {0}"
                                 .format(seen_home))

        if all_same_home:
            # Insert home in all VMs at once
            _insert_home_on_rangeset(self.cluster,
                                     rangeset,
                                     seen_home,
                                     local_home)
        else:
            # Insert home on a perVM basis
            for vm in rangeset:
                _insert_home_on_rangeset(self.cluster,
                                         RangeSet([vm]),
                                         homes[vm],
                                         local_home)

    def mirror(self,
               rangeset=None,
               adduser=True,
               mounthome=True,
               rootfs=True):
        if not rangeset:
            rangeset = self.target_rangeset
        # Start by making sure VMs are UP
        # we have a larger timeout to give some
        # time to slower VMs
        ret = AgentCommand.hello(self.cluster,
                                 rangeset,
                                 timeout=300)
        ret.iterate_all()

        with WritableVMRootfs(self.cluster, rangeset):
            if adduser:
                self.add_current_user_in_vm(rangeset)
            if rootfs:
                self.mount_rootfs(rangeset)
            if adduser and rootfs and mounthome:
                self.mount_current_user_home(rangeset)

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
            with open(source) as f:
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

    def get_core_count(self):
        ret = AgentCommand.corecount(self.cluster, self.target_rangeset)
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
        if not core:
            core = 1

        core_count = self.get_core_count()

        if not [1 for x in core_count if core <= x]:
            raise PcoccError("No VM provides {} cores ".format(core) +
                             " maximum is {}".format(max(core_count)))

        if node and len(core_count) < node:
            raise PcoccError("Only {} VMs allocated".format(len(core_count)) +
                             " cannot fulfill -N {}".format(node))

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
                self.core = range(0, core)
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
                    core_range = range(int(cnt) - int(core),
                                       int(cnt))
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
            cpu_array = map(int, comp.split(","))
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
            logging.debug(self.command_list)
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

        if exit_code != 0:
            raise subprocess.CalledProcessError(exit_code, self.argv)


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
        if self.user != getpass.getuser():
            raise PcoccError("Cannot change user when running native")

        # Make sure args are strs
        self.argv = [str(arg) for arg in self.argv]
        # Same for launcher
        self.launcher = [str(arg) for arg in self.launcher]

        envcmd = spawn.find_executable("env")
        env_prefix = []

        if envcmd is None:
            # We could not locate 'env'
            if not self.mirror:
                click.secho("Could not locate the 'env' binary "
                            "environment mirror (-m) is assumed", fg="yellow")

            for k in self.env:
                # Propapage in local env
                os.environ[k] = self.env[k]
        else:
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
            # If you need to debug container layout
            # time.sleep(1000)
            if self.pty and not sys.stdout.isatty():
                logging.debug("NATIVE RUN PTY: %s", " ".join(run_cmd))

                # Yes in V < 3.4 pty.spawn returns None ingore pylint warning
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
                logging.debug("NATIVE RUN: %s", " ".join(run_cmd))

                subprocess.check_call(run_cmd,
                                      stderr=subprocess.STDOUT)

        except (OSError, subprocess.CalledProcessError) as err:
            # Note that we do not catch the error here
            # to enable special handling to upper layers
            raise err
        finally:
            if self.to_delete:
                os.unlink(self.to_delete)
            # Reset workdir
            if self.cwd:
                os.chdir(old_cwd)

    def set_script(self, script):
        """Use a script to be run instead of the command.

        Arguments:
            script {str} -- script to be run

        Keyword Arguments:
            target_dir {str} -- where to store the script (default: {"~"})
            random {bool} -- randomize name (default: {True})

        Returns:
            str, str -- path to script dir, script name

        """
        if not os.path.isfile(script):
            raise PcoccError("Could not locate: " + script)
        self.command = [script]

    def mirror_env(self):
        self.mirror = True
        return self

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
        self.slurm_mirror = False
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
        slurm_cmd = ["srun", "--mpi=pmi2"]
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
        # Set launcher command and environment variables
        self.launcher = slurm_cmd + ["--export=" + ",".join(self.env_vars)]
        try:
            super(Slurm, self).run()
        except subprocess.CalledProcessError as err:
            sys.exit(err.returncode)

    def getenv(self, key):
        # This is a bit similar to the Native code
        # except that we wanted Slurm to propagate the "ALL"
        # case by itself reason why we do some bypassing here
        if not self.slurm_mirror:
            # Check if variables is defined in staging
            for entry in self.env_vars:
                splitvar = entry.split("=")
                if len(splitvar) < 2:
                    # Do not touch "ALL"
                    continue
                name = splitvar[0]
                if name == key:
                    return "=".join(splitvar[1:])

            # No such variables including in staging
            raise PcoccError("Failed to retrieve {}".format(key) +
                             " environment is not mirrored")
        else:
            # Call supercalls (regular getenv)
            # as the environment is actually propagated
            return super(Slurm, self).getenv(key)

    def mirror_env(self):
        # It is faster to let slurm Mirror ALL
        # instead of manually copying
        self.slurm_mirror = True
        self.env_vars.append("ALL")

    def set_env_var(self, key, value, prefixexpand=None):
        """Add an environment variable to the job.

        Arguments:
            key {str} -- variable name
            value {str} -- variable value

        Returns:
            Slurm -- runner to chain commands

        """
        # Do we need to replace a value already staged ?
        for i in range(0, len(self.env_vars)):
            entry = self.env_vars[i]
            splitvar = entry.split("=")
            if len(splitvar) < 2:
                # Do not touch "ALL"
                continue
            if key == splitvar[0]:
                # Found do replace
                self.env_vars[i] = "{}={}".format(key, value)
                # Done
                return self

        # Not found just append a value
        self.env_vars.append(key + "=" + value)
        return self

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


class ContainerFs(object):
    """This class exports container images to bundle using the cache."""

    def __init__(self,
                 runner,
                 image,
                 module=None,
                 singleton=True,
                 no_defaults=False,
                 no_user=False,
                 command=None):
        """Initialize the image for a given container.

        Arguments:
            object {[type]} -- [description]
            runner {NativeRunner/SlurmRunner} -- runner to run the command.
            image {str} -- URI of the target image

        Keyword Arguments:
            rootless {bool} -- if the image is run natively (default: {True})
        """
        # Inherit user from runner as it may
        # be set by the CLI
        self.user = runner.user
        # As we run in container restore the runner user
        # to be the local user this is needed for native
        # runner which cannot change user

        runner.set_user(getpass.getuser())
        self.pty = False
        self.forced_cwd = False
        self.script = None
        self.argv = []
        self.entrypoint = []
        self.runner = runner
        self.image = image
        self.no_user = no_user
        self.no_defaults = no_defaults
        self.rootless = self.runner.is_native()
        self.oci_source_bundle = None
        self.cleanup_transposed_bundle = None

        self.cont_view = ContainerBundleView(image)
        self.cont_view.prepare()

        self.oci_source_bundle = self.locate_bundle()

        if (self.rootless and
                not singleton and
                Config().containers.config.use_squashfs):
            # When using squashfs we want the rootfs to be mounted
            # on the target as we cannot rely on the shared FS
            # in this case we therefore skip setup on CLI side
            return

        # Now transpose to separate local configuration
        self.oci_bundle = self.transposed_bundle(self.oci_source_bundle,
                                                 rootless=self.rootless)
        # Pcocc container config
        pcocc_cont_cf = Config().containers

        # Generate rootless container spec
        self.oci_config = OciConfig(rootless=self.rootless)

        # If a command is known apply it before computing config
        # it is important as some generators may need to inspect
        # the effective command
        if command:
            self.set_argv(command)

        # Load container configuration
        # (default (if enabled) and for this image)
        cconf = pcocc_cont_cf.per_cont
        self.cont_config = cconf.build_for_container(image,
                                                     no_defaults=no_defaults)

        if singleton and module:
            # Check if the runner has a runtime flavor
            for mod in module:
                # We now try to locate the MPI configuration
                # in order to apend it to the current container config
                mconf = pcocc_cont_cf.module_cont
                module_conf = mconf.build_for_container(mod,
                                                        required=True)
                # And we append this to current container config
                self.cont_config.append(module_conf)

        #
        #  Proceed to load the source container OCI config
        #
        orig_container_conf = OciConfig(os.path.join(self.oci_source_bundle,
                                                     "config.json"))

        # Import command from original config
        self.oci_config.import_process(orig_container_conf)

        #
        #  Apply pcocc configuration file
        #
        config_path = path_join(self.oci_bundle, "config.json")
        rootfs_path = path_join(self.oci_source_bundle, "rootfs")

        self.oci_config.apply_container_config(self.cont_config,
                                               config_path=config_path,
                                               rootfs_path=rootfs_path)
        # Apply env for pcocc configuration files
        self.setup_container_env()

        #
        # Final config generation
        #

        if not self.no_user:
            self.inject_current_user()

        #
        # Set the container rootfs READONLY
        #
        self.oci_config.readonly(True)

        self.check_mounts()

        self.save_oci_config()

    def check_bundle_from_env(self):
        """Check is the bundle is exported in env (case of slurm propagation).

        Returns:
            str -- path to bundle (or None)

        """
        # This is imported when building the child object
        # note that it only happens when running with unpacked rootfs
        # otherwise everyting is done at singleton level (not CLI)
        if hasattr(self, "oci_source_bundle"):
            return self.oci_source_bundle

    def locate_bundle(self):
        """Try to locate an existing bundle from ENV, CACHE or creation.

        Arguments:
            image {str} -- URI of the image to retrieve a bundle for

        Returns:
            str -- path to OCI bunble

        """
        # Try to get the image from env
        oci_bundle = self.check_bundle_from_env()

        # Otherwise acquire the container view
        if not oci_bundle:
            oci_bundle = self.cont_view.get()

        return oci_bundle

    def setup_container_env(self):
        """Load and set variables from pcocc container config
        """
        # Set OCI environ config
        contconf_env = self.cont_config.env()
        Env.append(self, contconf_env)
        # Load PATH prefixing
        contconf_pathpr = self.cont_config.pathprefix()
        Env.path_prefix(self, contconf_pathpr)
        # Load PATH sufixing
        contconf_pathsf = self.cont_config.pathsuffix()
        Env.path_suffix(self, contconf_pathsf)

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
            # We forced the OCI_CWD
            cwd = oci_cwd
        self.oci_config.set_cwd(cwd)
        self.save_oci_config()

    def getenv(self, key):
        """Retrieve an environment var from container

        Arguments:
            key {str} -- variable name

        Raises:
            PcoccError: No such variable

        Returns:
            str -- variable value
        """
        oci_env = self.oci_config.get_env()
        if key in oci_env:
            return oci_env[key]

        raise PcoccError("Failed to retrieve {}".format(key) +
                         " environment variable from OCI Config")

    def add_mount(self, mnt):
        """Add a mountpoint to the container

        Arguments:
            mnt {dict} -- mount as defined by OCI
        """
        # logging.debug(args)
        if "type" not in mnt:
            mnt["type"] = "bind"

        if "opt" not in mnt:
            mnt["opt"] = None

        self.oci_config.add_mount(mnt["src"],
                                  mnt["dest"],
                                  mount_type=mnt["type"],
                                  options=mnt["opt"],
                                  transpose=self.transpose_path)
        self.save_oci_config()

    def mirror_env(self):
        """Set current environment in the container
        """
        for key, value in os.environ.items():
            self.oci_config.set_env(["{}={}".format(key, value)])
        self.save_oci_config()

    def set_env_var(self, key, value, prefixexpand=None):
        """Set environment variable in the container

        Arguments:
            key {str} -- variable name
            value {str} -- variable value

        Keyword Arguments:
            prefixexpand {str} -- Ignored (default: {None})
        """
        self.oci_config.set_env(["{}={}".format(key, value)])
        self.save_oci_config()

    @property
    def transpose_path(self):
        """Define if paths are to be projected in a VM

        Returns:
            bool -- yes transpose (i.e. add /rootfs to paths)
        """
        return not self.rootless

    def _resolve_mount_destination(self):
        """Make sure all mounts have both a source and destination
        """
        for mount in self.oci_config.mounts:
            if "destination" not in mount:
                mount["destination"] = mount["source"]
            if "type" not in mount:
                mount["type"] = "bind"

    def _container_create_mount_directories(self):
        dest_fs = path_join(self.oci_bundle, "rootfs")
        source_fs = path_join(self.oci_source_bundle, "rootfs")

        to_delete_mounts = []
        # Create a directory / empty file for each mount
        for mount in self.oci_config.mounts:
            msource = mount["source"]
            mtarget = mount["destination"]
            mtype = mount["type"]

            # TODO: pourquoi doit on se preocupper de ca ici ?
            # Et si on veut vraiement monter
            # quelquechose qui commence par rootfs ?
            # A revoir
            if msource.startswith("/rootfs"):
                msource = re.sub(r"^/rootfs", "", msource)

            # We ignore the existence test for special FSs
            special_fs = ["proc", "sysfs", "tmpfs",
                          "devpts", "shm", "mqueue", "cgroup"]

            if not os.path.exists(msource):
                if os.path.islink(msource):
                    mtarget_type = "file"
                    if not os.path.exists(msource):
                        # Skip broken links instead insert them in the tree
                        to_delete_mounts.append(mount)
                        linkto = os.readlink(msource)
                        os.symlink(linkto, path_join(dest_fs, mtarget))
                        continue
                elif (mtype in mtype) or (msource in special_fs):
                    # Assume directory
                    mtarget_type = "dir"
                else:
                    logging.warning("'%s' defined in mount "
                                    "does not exists, "
                                    "skipping.\n%s",
                                    msource,
                                    json.dumps(mount))
                    to_delete_mounts.append(mount)
                    continue
            elif os.path.isdir(msource):
                mtarget_type = "dir"
            else:
                mtarget_type = "file"

            # It is now time to create the corresponding files/dirs
            # if not already done
            target_path = path_join(dest_fs, mtarget)
            source_path = path_join(source_fs, mtarget)

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
        """Apply reverse mount to the transposed bundle
           effectively mounting the container in the empty
           transposed bundle

        Keyword Arguments:
            rootfs_path {str} -- (opt) alternative bundle path
                                 (default: {None})
        """
        source_fs = path_join(self.oci_source_bundle, "rootfs")
        dest_fs = path_join(self.oci_bundle, "rootfs")

        forward_mounts = set([m["destination"]
                              for m in self.oci_config.mounts])
        reverse_mounts = set()

        def update_work_rootfs(path="/"):
            """Recursive function called to unfold reverse mounts

            Keyword Arguments:
                path {str} -- target path (default: {"/"})
            """
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
            # Is the rootfs mounted elsewere ?
            if rootfs_path:
                mount_source_fs = path_join(rootfs_path, mnt)
            else:
                mount_source_fs = path_join(source_fs, mnt)
            self.oci_config.add_mount(mount_source_fs,
                                      mnt,
                                      transpose=self.transpose_path,
                                      prepend=True)

    def container_update_rootfs(self, rootfs_path=None):
        """Main entry point for reverse mount update
           generating directories and then computing
           reverse mounts before saving the config

        Keyword Arguments:
            rootfs_path {str} -- (opt) alternative
                                  bundle path (default: {None})
        """
        self._resolve_mount_destination()
        self._container_create_mount_directories()
        self._container_reverse_mount(rootfs_path=rootfs_path)
        self.save_oci_config()

    def check_mounts(self):
        """Insert common mounts in the container.
           and do reverse mount of the container"""
        # Insert /dev/shm
        self.oci_config.mirror_mount("/dev/shm/",
                                     transpose=False)
        # Insert /tmp
        self.oci_config.mirror_mount("/tmp/", transpose=False)
        # Insert resolv.conf
        self.oci_config.mirror_mount("/etc/resolv.conf",
                                     transpose=False)

    def transposed_bundle(self, bundle_path, rootless=True):
        """Create a dedicated instance of bundle

        Arguments:
            bundle_path {str} -- path to reference bundle

        Returns:
            str -- path to the duplicated bundle

        """
        if rootless:
            bundle_dest = tempfile.mkdtemp()
        else:
            tmp_roofs_dir = os.path.join(Config().batch.cluster_state_dir,
                                         "cont_bundles")
            if not os.path.exists(tmp_roofs_dir):
                os.makedirs(tmp_roofs_dir)
            # We run inside a VM use a shared directory
            # as the CLI is setting up the rootfs
            bundle_dest = tempfile.mkdtemp(dir=tmp_roofs_dir)

        def cleanup_transposed_bundle():
            """This function is to be deffered to clean the
               transposed bundle"""
            shutil.rmtree(bundle_dest)

        self.cleanup_transposed_bundle = cleanup_transposed_bundle
        pcocc_at_exit.register(self.cleanup_transposed_bundle)

        # Make sure to resolve symlinks
        bundle_dest = os.path.realpath(bundle_dest)
        os.chmod(bundle_dest, 0o700)

        # Copy the config in the transposed bundle
        shutil.copy(path_join(bundle_path, "config.json"),
                    path_join(bundle_dest, "config.json"))

        return bundle_dest

    def save_oci_config(self):
        """Save the OCI config to bundle (or tansposed bundle)."""
        bundle_config = path_join(self.oci_bundle, "config.json")
        logging.debug("OCI CONFIG: %s", bundle_config)
        self.oci_config.save(bundle_config)

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

        groups = gen_user_group_list(user)
        lgroups = dict(groups)

        if gid not in lgroups.values():
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
        for key, value in lgroups.items():
            ret = ret + key + ":x:" + str(value) + ":" + user + "\n"

        if not outfile:
            outfile = etcgroup

        # Now add the user to the container
        with open(outfile, "w") as pwdf:
            pwdf.write(ret)

    def inject_current_user(self):
        """Inject calling user inside the container."""

        def remove_trailing_slash(path):
            """ we have to make sure CWD matched HOME"""
            if path.endswith(os.sep):
                return path[:-1]
            return path

        # Get user infos
        user = self.user

        os_user_home = remove_trailing_slash(getpwnam(user).pw_dir)
        # We do this to remove any symlink
        os_real_user_home = os.path.realpath(os_user_home)
        os_real_user_home = remove_trailing_slash(os_real_user_home)

        # Use the real home
        real_user_home = os_real_user_home

        cont_uid = getpwnam(user).pw_uid
        cont_gid = _get_primary_group(user)

        if self.runner.is_native():
            source_passwd = path_join(self.oci_source_bundle,
                                      "rootfs/etc/passwd")
            source_group = path_join(self.oci_source_bundle,
                                     "rootfs/etc/group")
        else:
            # The bundle transpose will have extracted this file
            # from the rootfs for us (we cant read it as it is only
            # mounted in the VM)
            source_passwd = path_join(self.oci_bundle, "passwd")
            source_group = path_join(self.oci_bundle, "group")

        # Do not try to mount somebody else's home
        if (getpass.getuser() == user and
                self.oci_config.is_mounted(os_user_home)):
            # In this case user's home is mounted
            # Make sure to update path if HOME is symlinked
            self.oci_config.set_env({'HOME': os_user_home})

            # In this case we want CWD to point to the $HOME
            # not the symlink in the CWD case if it is set
            # by the user manually this setting is overwritten
            cwd = os.getcwd()
            if cwd.startswith(real_user_home):
                cwd = cwd.replace(real_user_home, os_user_home)
            self.oci_config.set_cwd(remove_trailing_slash(cwd))
        else:
            # Make sure to update $HOME in container
            self.oci_config.set_env({'HOME': real_user_home})

            # This is an edge case to avoid that CWD points to the realpath
            # whereas we mounted the symlinked home in the container
            # this would lead to a "no such directory" when launching
            # the container here we simply rewrite to use the symlink home
            cwd = os.path.realpath(os.getcwd())
            if cwd.startswith(os_user_home):
                cwd = cwd.replace(os_user_home, os_real_user_home + "/")
            self.oci_config.set_cwd(remove_trailing_slash(cwd))

            # Add a tmpfs to create the dir only if there is not
            # already a mount covering this directory
            # (the case of manual mount by the user)
            options = ["nosuid",
                       "nodev",
                       "mode=1777",
                       "rw",
                       "uid=" + str(cont_uid),
                       "gid=" + str(cont_gid)]

            self.oci_config.add_mount_if_needed("tmpfs",
                                                real_user_home,
                                                mount_type="tmpfs",
                                                options=options,
                                                transpose=False)

        # Set UID and GID
        self.oci_config.set_uid(cont_uid)
        self.oci_config.set_gid(cont_gid)

        # Generate mappings for rootless run
        host_uid = getpwnam(getpass.getuser()).pw_uid
        host_gid = _get_primary_group(getpass.getuser())

        self.oci_config.append_uid_mapping(host_uid, cont_uid)
        self.oci_config.append_gid_mapping(host_gid, cont_gid)

        if os.path.exists(source_passwd):
            # Eventually proceed to insert the user and his groups in rootfs
            pwd_path = path_join(self.oci_bundle, "passwd")
            self.insert_user_in_etc_passwd(source_passwd,
                                           user,
                                           real_user_home,
                                           cont_uid,
                                           cont_gid,
                                           outfile=pwd_path)
            self.oci_config.add_mount(pwd_path,
                                      "/etc/passwd",
                                      transpose=self.transpose_path)

        if os.path.exists(source_group):
            grp_path = path_join(self.oci_bundle, "group")
            self.insert_groups_in_etc_group(source_group,
                                            user,
                                            cont_gid,
                                            outfile=grp_path)
            # Now bind mount the configuration files

            self.oci_config.add_mount(grp_path,
                                      "/etc/group",
                                      transpose=self.transpose_path)

    def set_argv(self, argv):
        """Set command in container config file.

        Arguments:
            argv {array of str} -- command to be run

        Returns:
            ContainerFS -- self to chain commands

        """
        self.argv = argv
        if argv:
            # Set command
            self.oci_config.set_command(list(argv))
            # Regenerate OCI config
            self.save_oci_config()
        return self

    def set_entrypoint(self, entrypoint):
        """Set container entrypoint (docker semantics)

        Arguments:
            entrypoint {array of str} -- entrypoint command
        """
        self.entrypoint = entrypoint
        if entrypoint:
            self.oci_config.set_entrypoint(list(entrypoint))
            self.save_oci_config()

    def set_pty(self, use_pty=True):
        """Set the config to run using a TTY.

        Arguments:
            pty {bool} -- TTY enabled

        Returns:
            ContainerFS -- self to chain commands

        """
        self.pty = use_pty
        self.runner.set_pty(pty)
        self.oci_config.set_terminal(pty)
        self.save_oci_config()
        return self

    def set_user(self, user):
        """Set the user in container

        Arguments:
            _ {str} -- user to be set

        Raises:
            PcoccError: For containers the user is inherited from underlying
                        runner it is not set on container once initialized
        """
        return

    def set_script(self, script):
        """Inject a script in the container (bind mount).

        Arguments:
            script {str} -- path to script

        Returns:
            ContainerFS -- self to chain commands

        """
        if not script:
            return
        if not os.path.isfile(script):
            raise PcoccError("Could not read script: " + script)
        self.script = script
        # Inject the script
        script_path = path_join(self.oci_bundle, "pcocc-script")
        shutil.copy(script, script_path)

        # And bind mount the script
        self.oci_config.add_mount(script_path,
                                  "/pcocc-script",
                                  transpose=self.transpose_path)
        # Set script as new command
        self.set_argv(["/pcocc-script"])


class RootlessRunner(object):
    """This class is intended as generator for subclass runners.

    Call the RootlessRunner.new function to acquire a subclass runner.
    """

    def __init__(self, oci_bundle, runner):
        """Instanciate a rootless runner.

        Arguments:
            oci_bundle {str} -- path to OCI bundle
            runner {NativeRunner/SlurmRunner} -- runner used to run the command

        """
        self.oci_bundle = oci_bundle
        self.runner = runner

    @staticmethod
    def has_user_ns():
        """Determine if target system has User NS enabled.

        Returns:
            bool, str -- User NS supported (bool), Reason why (str)

        """
        # First check for DEBIAN like systems
        # the feature has to be enabled
        # https://lwn.net/Articles/673597/
        try:
            userns_clone = "/proc/sys/kernel/unprivileged_userns_clone"
            with open(userns_clone, "r") as fnsc:
                ret = fnsc.read()
                if not ret.startswith("1"):
                    # No suport
                    return (False,
                            (userns_clone +
                             " is '0' and should be '1' for User NS support"))
        except IOError:
            pass

        # Now check the number of allowed user NS (0 by default on Centos)
        try:
            with open("/proc/sys/user/max_user_namespaces") as fmuns:
                ret = fmuns.read()
                if ret.startswith("0"):
                    # No user NS are allowed
                    return (False,
                            ("/proc/sys/user/max_user_namespaces"
                             " is '0' and should be '> 0' for"
                             " User NS support"))
        except IOError:
            return (False, ("User NS are not enabled in your kernel OR\n"
                            "Your kernel does not support User Namespaces\n"
                            "minimum version is >= 3.8"
                            " and recommended >= 3.9"))

        return True, "User NS seem to be enabled"

    @staticmethod
    def new(oci_bundle, runner):
        """Instanciate a RootlessRunner according to present runtimes.

        Arguments:
            oci_bundle {str} -- path to target bundle
            runner {NativeRunner/SlurmRunner} -- runner used to run the command

        Raises:
            PcoccError -- No runtime is installed
            PcoccError -- runc is selected with no user NS support

        Returns:
            RootlessRunner -- correct instance of runtime (runc/bwrap)

        """
        bwrap = spawn.find_executable("bwrap")
        runc = spawn.find_executable("runc")

        if bwrap and not Config().containers.config.use_runc:
            return BubblewrapRootless(oci_bundle, runner)
        elif runc:
            has_user_ns, no_ns_reason = RootlessRunner.has_user_ns()

            if not has_user_ns:
                raise PcoccError("You cannot run rootless containers " +
                                 "using runc without user NS\n" +
                                 no_ns_reason)

            return RuncRootless(oci_bundle, runner)
        else:
            raise PcoccError("Could not locate a rootless "
                             "container runtime please install "
                             "either Bubblewrap or runc")


class BubblewrapRootless(RootlessRunner):
    """This is an instance of bwrap to run rootless containers."""

    def __init__(self, oci_bundle, runner):
        """Call the superclass constructor.

        Arguments:
            oci_bundle {str} -- path to OCI bundle
            runner {NativeRunner/SlurmRunner} -- runner used to run the command
        """
        RootlessRunner.__init__(self, oci_bundle, runner)

    @staticmethod
    def run_hook(cont_state, hook_infos):
        """A function to run OCI hooks

        Arguments:
            cont_state {dict} -- container state as defined by OCI
            hook_infos {dict} -- hook configuration as provided by OCI

        Raises:
            PcoccError: No 'path' in hook
            PcoccError: Execution timed-out
            PcoccError: Execution failed (ret!=0)
        """
        def hook_error(msg):
            """Helper to raise error"""
            raise PcoccError(msg)

        if "path" not in hook_infos:
            hook_error("No 'path' provided in hook")
            return

        path = hook_infos["path"]

        env = {}
        if "env" in hook_infos:
            env_list = hook_infos["env"]
            for elem in env_list:
                splitvar = elem.split("=")
                if len(splitvar) >= 2:
                    env[splitvar[0]] = "=".join(splitvar[1:])

        args = []
        if "args" in hook_infos:
            args = hook_infos["args"]

        timeout = None
        if "timeout" in hook_infos:
            timeout = hook_infos["timeout"]

        cmd = [path] + args

        hook_cmd = subprocess.Popen(cmd,
                                    env=env,
                                    stdin=subprocess.PIPE)

        # Send the container state to stdin
        state_dat = json.dumps(cont_state)
        hook_cmd.stdin.write(state_dat)
        # Close stdin
        hook_cmd.stdin.close()

        wait_time = 0

        while True:
            if timeout and (timeout < wait_time):
                hook_cmd.kill()
                hook_error("OCI hook execution of '{}'".format(" ".join(cmd)) +
                           " reached its timeout of {} s".format(timeout))
                break
            ret = hook_cmd.poll()
            if ret is None:
                time.sleep(0.1)
                wait_time += 0.1
            else:
                break

        if ret != 0:
            hook_error("OCI hook execution of '{}'".format(" ".join(cmd)) +
                       " exited badly with code {}".format(ret))

    @staticmethod
    def bwrap_hook_thread(oci_bundle,
                          info_r_fd,
                          info_w_fd,
                          block_r_fd,
                          block_w_fd,
                          sync_r_fd,
                          sync_w_fd):
        """This thread is in charge of running hooks as the container runs

        Arguments:
            oci_bundle {str} -- path to OCI bundle
            info_r_fd {int(fd)} -- file descriptor to read the container info
            info_w_fd {int(fd)} -- write end of the child fd
            block_w_fd {int(fd)} -- fd blocking container start
            sync_r_fd {int(fd)} -- Closed when the container stops
            sync_w_fd {int(fd)} -- Write end passed to child process
        """

        # First load the OCI configuration
        oci_config = {}
        with open(os.path.join(oci_bundle, "config.json")) as config_file:
            oci_config = json.load(config_file)

        hooks = {}
        if "hooks" in oci_config:
            hooks = oci_config["hooks"]

        # Fill in the first infos for the OCI state
        oci_state = {"ociVersion": oci_config["ociVersion"],
                     "id": os.path.basename(oci_bundle),
                     "bundle": oci_bundle,
                     "status": "creating"}

        info_data = ""
        while True:
            data = os.read(info_r_fd, 1)
            if data:
                # On first read close the input FD as we
                # are sure that the child is running as it speaks
                if info_w_fd:
                    os.close(info_w_fd)
                    info_w_fd = None
                info_data += data
            else:
                break

        # We need to retrieve the container PID
        pid_infos = json.loads(info_data)

        if "child-pid" in pid_infos:
            oci_state["pid"] = pid_infos["child-pid"]
        else:
            logging.error("ERROR: Bad info from container "
                          "Failed to run OCI hooks, skipping")
            # But unlock the container before leaving
            # it is better to run instead of all time crashing
            os.write(block_w_fd, "1")
            return

        # We can close the block_r fd
        os.close(block_r_fd)

        # Emit the prestart hooks if present
        oci_state["status"] = "created"

        def run_poststop_hooks():
            """ Run poststop hooks on prestart failure and stop"""
            oci_state["status"] = "stopped"

            if "poststop" in hooks:
                for hook in hooks["poststop"]:
                    try:
                        # poststop hooks can fail without crash
                        BubblewrapRootless.run_hook(oci_state,
                                                    hook)
                    except PcoccError:
                        pass

        if "prestart" in hooks:
            for hook in hooks["prestart"]:
                try:
                    # Prestart hooks can create failure see
                    # https://github.com/opencontainers/runtime-spec/blob/master/runtime.md#lifecycle
                    BubblewrapRootless.run_hook(oci_state,
                                                hook)
                except PcoccError as err:
                    logging.error(err)
                    # One of the hook failed kill the container
                    os.kill(oci_state["pid"], signal.SIGKILL)
                    run_poststop_hooks()
                    return

        # We are done starting notify the container
        os.write(block_w_fd, "1")

        # As the container is clearly running
        # We now close the control blocking FD
        os.close(block_w_fd)

        # And our side of the sync FD
        os.close(sync_w_fd)

        # Now we can run the post-start hooks
        oci_state["status"] = "running"

        if "poststart" in hooks:
            for hook in hooks["poststart"]:
                try:
                    # poststart hooks can fail without crash
                    BubblewrapRootless.run_hook(oci_state,
                                                hook)
                except PcoccError:
                    pass

        # We now wait for completion of the container
        os.read(sync_r_fd, 1)

        run_poststop_hooks()

    def run(self):
        """Run the command using bubblewrap exit with return code.

        Raises:
            PcoccError -- bwrap could not be found

        """
        # Time to generate the bwrapp configuration
        bwrap = spawn.find_executable("bwrap")

        if not bwrap:
            raise PcoccError("Could not locate BubbleWrapp (bwrap)")

        pwd = os.getcwd()
        os.chdir(self.oci_bundle)

        bwcmd = subprocess.check_output(["bwrap-oci",
                                         "--bwrap",
                                         bwrap,
                                         "--dry-run"])

        # Only keep last non-empty line as --dry-run produces env-variables
        bwcmd = [e for e in bwcmd.split("\n") if e != ""][-1]

        # Needed to enable the removal of the PID namespace
        # which is not compatible with MPI SHM segments
        bwcmd = bwcmd.replace("--as-pid-1", "")

        # Remove newline
        bwcmd = bwcmd.replace("\n", "")
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

        # Do not try to unshare user if runner's user is ourselves
        if self.runner.user == getpass.getuser():
            bwcmd = re.sub(r"--uid [0-9]+", "", bwcmd)
            bwcmd = re.sub(r"--gid [0-9]+", "", bwcmd)

        # Check if OCI hooks are enabled and setup the monitor
        # FDs accordingly if it is the case
        hook_support = Config().containers.config.enable_oci_hooks

        if hook_support:
            hookth = None

            # On this FD bwrap returns the container state
            info_r, info_w = os.pipe()
            bwcmd = bwcmd.replace("--info-fd FD",
                                  "--info-fd {}".format(info_w))

            # On this FD bwrap waits for a write before actually
            # starting the container
            block_r, block_w = os.pipe()
            bwcmd = bwcmd.replace("--block-fd FD",
                                  "--block-fd {}".format(block_r))

            # BWRAP opens this FD and closes it when exiting
            # it is used to monitor the container exit
            sync_r, sync_w = os.pipe()
            bwcmd = bwcmd.replace("--sync-fd FD",
                                  "--sync-fd {}".format(sync_w))

            bw_hook_func = BubblewrapRootless.bwrap_hook_thread

            hookth = threading.Thread(target=bw_hook_func,
                                      args=(self.oci_bundle,
                                            info_r,
                                            info_w,
                                            block_r,
                                            block_w,
                                            sync_r,
                                            sync_w))
            hookth.daemon = True
            hookth.start()
        else:
            logging.info("OCI hooks are disabled (see enable_oci_hooks in "
                         "containers.yaml config file)")
            bwcmd = bwcmd.replace("--sync-fd FD", "")
            bwcmd = bwcmd.replace("--info-fd FD", "")
            bwcmd = bwcmd.replace("--block-fd FD", "")

        bwcmd = shlex.split(bwcmd)

        # And now proceed to run with bublewrapp
        self.runner.set_argv(bwcmd)

        self.runner.run()

        os.chdir(pwd)


class RuncRootless(RootlessRunner):
    """This is an instance of runc to run rootless containers."""

    def __init__(self, oci_bundle, runner):
        """Call the superclass constructor.

        Arguments:
            oci_bundle {str} -- path to OCI bundle
            runner {NativeRunner/SlurmRunner} -- runner used to run the command
        """
        RootlessRunner.__init__(self, oci_bundle, runner)

    def _check_bundle_config(self):
        oci_conf = path_join(self.oci_bundle, "config.json")

        if (not spawn.find_executable("newgidmap") or
                not spawn.find_executable("newuidmap")):
            raise PcoccError("newgidmap and newuidmap tools are required"
                             " to run rootless containers with runc")

        if not os.path.isfile(oci_conf):
            raise PcoccError("runc: failed to locate bundle config")

        config = {}
        with open(oci_conf, "r") as in_fd:
            config = json.load(in_fd)

        # Make sure target UID is root
        process = config.setdefault("process", {})
        user = process.setdefault("user", {})

        if user["uid"] != 0:
            raise PcoccError("Runc can only run container"
                             " using runc as root consider adding '-u root'")

        # Update mappings
        linux = config.setdefault("linux", {})
        uidm = linux.setdefault("uidMappings", [])
        if not uidm:
            raise PcoccError("Config.json should contain UID mappings")

        gidm = linux.setdefault("gidMappings", [])
        if not gidm:
            raise PcoccError("Config.json should contain GID mappings")

        # Make sure that the userns is present
        namespaces = linux.setdefault("namespaces", [])
        namespaces_list = [e["type"] for e in namespaces if "type" in e]

        if "user" not in namespaces_list:
            raise PcoccError("User namespaces are required to run with runc")

        # Remove any gid/uid parameter from mounts
        mounts = config.setdefault("mounts", [])

        for mnt in mounts:
            if "options" not in mnt:
                continue

            new_opts = []
            for opt in mnt["options"]:
                if "gid=" not in opt or "uid=" not in opt:
                    new_opts.append(opt)
            mnt["options"] = new_opts

        # Save the updated config
        with open(oci_conf, "w") as out_fd:
            json.dump(config, out_fd)

    def run(self):
        """Run the command using runc exit with return code.

        Raises:
            PcoccError -- runc could not be found

        """
        self._check_bundle_config()
        runc = spawn.find_executable("runc")

        if not runc:
            raise PcoccError("Could not locate runc")

        runc_command = ["runc",
                        "--rootless",
                        "true",
                        "run",
                        "-b",
                        self.oci_bundle,
                        "pcocc_cont"]

        self.runner.set_argv(runc_command)
        self.runner.run()


class NativeContainer(ContainerFs):
    """This is the configuration to run a rootless container."""

    def __init__(self,
                 runner,
                 image=None,
                 singleton=True,
                 cont_conf=None,
                 no_defaults=False,
                 no_user=False,
                 command=None):
        """Create a rootless container (wraps a runner).

        Arguments:
            runner {NativeRunner/SlurmRunner} -- the runner to be wrapped
            image {str} -- name of the image to run
            singleton {bool} -- if the image is to be explicitly run natively
            config {dict} -- if config is present providing args except runner

        Raises:
            PcoccError -- No image was provided
            PcoccError -- Trying to run Native with a non native runner

        """
        self.singleton = singleton
        self.no_defaults = no_defaults
        self.no_user = no_user
        self.command = command
        if not runner or not runner.is_native():
            raise PcoccError("NativeContainer require a native runner")
        if cont_conf:
            self.import_configuration(runner, cont_conf)
        else:
            if not image:
                raise PcoccError("NativeContainer requires an image")
            self.image = image
            self.script = None
            self.env = {}
            self.argv = []
            self.prepend_env = {}
            self.append_env = {}
            self.mounts = []
            self.cwd = None
            if hasattr(runner, "module"):
                self.module = runner.module
            else:
                self.module = []
            super(NativeContainer, self).__init__(runner,
                                                  image,
                                                  module=self.module,
                                                  singleton=singleton,
                                                  no_defaults=self.no_defaults,
                                                  no_user=self.no_user,
                                                  command=self.command)

    def serialize_configuration(self):
        """Serialize configuration to send to the
           pcocc internal runnativecont command

        Returns:
            str -- serialized cli configuration
        """
        ret = {}
        ret["user"] = self.user
        ret["image"] = self.image
        ret["script"] = self.script
        ret["oci_source_bundle"] = self.oci_source_bundle
        ret["pty"] = self.pty
        ret["argv"] = self.argv
        ret["env"] = self.env
        ret["prepend_env"] = self.prepend_env
        ret["append_env"] = self.append_env
        ret["mounts"] = self.mounts
        ret["cwd"] = self.cwd
        ret["forced_cwd"] = self.forced_cwd
        ret["module"] = self.module
        ret["no_user"] = self.no_user
        ret["no_defaults"] = self.no_defaults
        ret["entrypoint"] = self.entrypoint
        return json.dumps(ret)

    def import_configuration(self, runner, conf):
        """Load configuration from serialized config

        Arguments:
            runner {Runner} -- target runner
            conf {string} -- serialized json config to load
        """
        # Make sure to set the source bundle
        # to avoid recreating the target image
        self.oci_source_bundle = conf["oci_source_bundle"]
        if conf["module"]:
            module = conf["module"]
        else:
            module = []
        self.no_defaults = conf["no_defaults"]
        self.no_user = conf["no_user"]
        super(NativeContainer, self).__init__(runner,
                                              conf["image"],
                                              module=module,
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
        Env.path_prefix(self, ["{}={}".format(k, v)
                               for k, v in conf["prepend_env"].items()])
        Env.path_suffix(self, ["{}={}".format(k, v)
                               for k, v in conf["append_env"].items()])
        self.set_cwd(conf["cwd"], forced=conf["forced_cwd"])
        Mount.add(self, conf["mounts"])

    def mirror_env(self):
        for key, value in os.environ.items():
            self.set_env_var(key, value)

    def set_script(self, script):
        if self.singleton:
            super(NativeContainer, self).set_script(script)
        else:
            self.script = script

    def set_pty(self, use_pty=True):
        if self.singleton:
            super(NativeContainer, self).set_pty(pty)
        else:
            # Set runner PTY for SLURM propagation
            self.runner.set_pty(use_pty)
            self.pty = use_pty

    def set_argv(self, argv):
        if self.singleton:
            super(NativeContainer, self).set_argv(argv)
        else:
            self.argv = argv

    def set_entrypoint(self, entrypoint):
        if self.singleton:
            super(NativeContainer, self).set_entrypoint(entrypoint)
        else:
            self.entrypoint = entrypoint

    def getenv(self, key):
        if self.singleton:
            return super(NativeContainer, self).getenv(key)

        raise PcoccError("Container environment not available")

    def set_cwd(self, cwd, forced=False):
        if not cwd:
            return
        if self.singleton:
            super(NativeContainer, self).set_cwd(cwd, forced)
        else:
            self.cwd = cwd
            self.forced_cwd = forced

    def add_mount(self, mnt):
        if self.singleton:
            # Directly set in OCI
            super(NativeContainer, self).add_mount(mnt)
        else:
            # Cache to forward to slurm step
            self.mounts.append(mnt)

    def set_env_var(self, key, value, prefixexpand=None):
        if self.singleton:
            # Directly set in OCI
            super(NativeContainer, self).set_env_var(key, value)
        else:
            # We do not save variabes from prexix expanding
            # as we want them to be processed at slurm step
            # otherwise the variables expanded now would
            # overwrite the newly exposed variables when
            # spawned by slurm
            if prefixexpand:
                if prefixexpand == "PREFIX":
                    self.prepend_env[key] = value
                elif prefixexpand == "SUFFIX":
                    self.append_env[key] = value
                else:
                    raise PcoccError("No such env operation")
            else:
                # Save for configuration propagation
                self.env[key] = value

    def _clean_singleton(self):
        self.cont_view.cleanup()

        shutil.rmtree(self.oci_bundle)
        pcocc_at_exit.deregister(self.cleanup_transposed_bundle)
        self.cleanup_transposed_bundle = None

    def run_singleton(self):
        """Run the container in a singleton configuration."""
        rootless = RootlessRunner.new(self.oci_bundle, self.runner)

        self.container_update_rootfs()

        try:
            rootless.run()
        except subprocess.CalledProcessError as err:
            # Cleanup
            # Just forward the code up
            sys.exit(err.returncode)
        finally:
            self._clean_singleton()

    def run_propagate(self):
        """Propagate the execution to slurm (srun a singleton run)."""
        conf = self.serialize_configuration()
        # Generate verbosity option
        verbosity = ["-" + "v" * Config().verbose] if Config().verbose else []

        command = (["pcocc"] + verbosity + ["internal",
                                            "runnativecont",
                                            conf])
        # When running on the target node we need to have
        # pcocc in the PATH so we propagate the env
        self.runner.mirror_env()
        self.runner.set_argv(command)
        try:
            self.runner.run()
        except subprocess.CalledProcessError as err:
            # We just forward the return code up
            sys.exit(err.returncode)

    def run(self):
        """Run either natively or through srun after unpack."""
        # Do we run on a per-process basis ?
        if self.singleton:
            self.run_singleton()
        else:
            # Only unpack the image and then
            # generate a slurm command to run in singleton
            # on target node using previously unpacked img
            self.run_propagate()


class VmContainer(ContainerFs):
    """Container interface to run in virtual machines
       squashfs is required to run containers in VMs
    """
    def __init__(self,
                 runner,
                 image,
                 no_defaults=False,
                 no_user=False,
                 command=None):
        if not image:
            raise PcoccError("VmContainer requires an image")
        if not Config().containers.config.use_squashfs:
            raise PcoccError("Squashfs support is required to run in VMs")
        self.image = image
        self.script = None
        self.singleton = False
        ContainerFs.__init__(self,
                             runner,
                             image,
                             no_defaults=no_defaults,
                             no_user=no_user,
                             command=command)

    def squash_mountpoint(self):
        """Mountpoint for the squashfs image

        Returns:
            str -- path to mountpoint
        """
        ret = os.path.join(self.oci_bundle, "squashfs")
        if not os.path.exists(ret):
            os.mkdir(ret, 0o777)
        return ret

    def squashfs_rootfs(self):
        """Path to rootfs inside the squashfs

        Returns:
            str -- path to rootfs
        """
        return path_join(self.squash_mountpoint(), "/rootfs/")

    def mount_squash_in_vms(self):
        """Mount squashfs image inside the vms
        """
        vm_path = self.squash_mountpoint()
        squash_fs_image = Config().images.cache_get(self.image,
                                                    "cached_squashfs")
        cmd = ["mount",
               "-t",
               "squashfs",
               "-o", "ro",
               path_join("/rootfs/", squash_fs_image),
               path_join("/rootfs/", vm_path)]

        AgentCommand.exec_output(self.runner.cluster,
                                 self.runner.target_rangeset,
                                 cmd)

        logging.debug(" ".join(cmd))

    def umount_squash_in_vms(self):
        """Umount squashfs inside the vms
        """
        vm_path = self.squash_mountpoint()
        AgentCommand.exec_output(self.runner.cluster,
                                 self.runner.target_rangeset,
                                 ["umount",
                                  vm_path])

    def remove_cli_squashfs(self):
        """Remove the command line squashfs used to intialize bundle
        """
        if Config().containers.config.use_squashfs:
            self.cont_view.cleanup()

    def run(self):
        """Run comand inside VMs

        Raises:
            err: Excecution failed
        """
        # Mirror rootfs inside VMs
        self.runner.mirror()
        # Proceed to reverse mount in the rootfs
        # notre that the target dir is in the per alloc directory
        # and therefore automatically cleaned up
        self.container_update_rootfs(rootfs_path=self.squashfs_rootfs())
        # We are done we can umount the squash in CLI
        self.remove_cli_squashfs()
        # Eventually mount the squashfs inside the VMs
        self.mount_squash_in_vms()
        pcocc_at_exit.register(self.umount_squash_in_vms)
        # As we itend to run containers
        # the UID / GID of the underlying runner
        # is always 0 actual user is set in OCI Config
        self.runner.set_user("root")
        # We use an intermediate shell as we need a way of
        # generating an unique container ID on the fly
        container_cmd = ["sh", "-c", "runc run -b /rootfs/" +
                         self.oci_bundle + " pcocc_cont${RANDOM}${RANDOM}"]
        logging.debug(" ".join(container_cmd))
        self.runner.set_argv(container_cmd)
        try:
            self.runner.run()
        except subprocess.CalledProcessError as err:
            # We just forward the return code up
            sys.exit(err.returncode)
        finally:
            self.umount_squash_in_vms()
            pcocc_at_exit.deregister(self.umount_squash_in_vms)


def Container(runner,
              image=None,
              singleton=True,
              cont_conf=None,
              no_defaults=False,
              no_user=False,
              command=None):
    """Unified container interface constructing either a native or a vm
       container in function of the nature of the runner"""
    if runner.is_native():
        # Instanciate a native runner
        return NativeContainer(runner,
                               image,
                               singleton,
                               cont_conf,
                               no_defaults=no_defaults,
                               no_user=no_user,
                               command=command)

    # Instanciate a VM runner
    return VmContainer(runner,
                       image,
                       no_defaults=no_defaults,
                       no_user=no_user,
                       command=command)
