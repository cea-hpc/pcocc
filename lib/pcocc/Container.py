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

import yaml
import json
import errno
import logging
import os
import stat
import shlex
import jsonschema
from distutils import spawn
import subprocess

from .Error import InvalidConfigurationError, PcoccError
from .Misc import path_join
from .Config import Config

# A basic OCI configuration
OCI_CONTAINER_CONFIG = """
{
    "ociVersion": "1.0.0",
    "process": {
        "terminal": false,
        "user": {
            "uid": 0,
            "gid": 0
        },
        "args": [
            "sh"
        ],
        "env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM=xterm"
        ],
        "cwd": "/",
        "capabilities": {
            "bounding": [
                "CAP_AUDIT_WRITE",
                "CAP_KILL",
                "CAP_NET_BIND_SERVICE"
            ],
            "effective": [
                "CAP_AUDIT_WRITE",
                "CAP_KILL",
                "CAP_NET_BIND_SERVICE"
            ],
            "inheritable": [
                "CAP_AUDIT_WRITE",
                "CAP_KILL",
                "CAP_NET_BIND_SERVICE"
            ],
            "permitted": [
                "CAP_AUDIT_WRITE",
                "CAP_KILL",
                "CAP_NET_BIND_SERVICE"
            ],
            "ambient": [
                "CAP_AUDIT_WRITE",
                "CAP_KILL",
                "CAP_NET_BIND_SERVICE"
            ]
        },
        "rlimits": [
            {
                "type": "RLIMIT_NOFILE",
                "hard": 1024,
                "soft": 1024
            }
        ],
        "noNewPrivileges": true
    },
    "root": {
        "path": "rootfs",
        "readonly": true
    },
    "mounts": [
        {
            "destination": "/proc",
            "type": "proc",
            "source": "proc"
        },
        {
            "destination": "/dev",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": [
                "nosuid",
                "strictatime",
                "mode=755",
                "size=65536k"
            ]
        },
        {
            "destination": "/dev/pts",
            "type": "devpts",
            "source": "devpts",
            "options": [
                "nosuid",
                "noexec",
                "newinstance",
                "ptmxmode=0666",
                "mode=0620"
            ]
        },
        {
            "destination": "/dev/shm",
            "type": "tmpfs",
            "source": "shm",
            "options": [
                "nosuid",
                "noexec",
                "nodev",
                "mode=1777",
                "size=65536k"
            ]
        },
        {
            "destination": "/tmp",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": [
                "nosuid",
                "nodev",
                "mode=1777",
                "size=65536k",
                "rw"
            ]
        },
        {
            "destination": "/dev/mqueue",
            "type": "mqueue",
            "source": "mqueue",
            "options": [
                "nosuid",
                "noexec",
                "nodev"
            ]
        },
        {
            "destination": "/sys",
            "type": "sysfs",
            "source": "sysfs",
            "options": [
                "nosuid",
                "noexec",
                "nodev",
                "ro"
            ]
        },
        {
            "destination": "/sys/fs/cgroup",
            "type": "cgroup",
            "source": "cgroup",
            "options": [
                "nosuid",
                "noexec",
                "nodev",
                "relatime",
                "ro"
            ]
        }
    ],
    "linux": {
        "resources": {
            "devices": [
                {
                    "allow": false,
                    "access": "rwm"
                }
            ]
        },
        "namespaces": [
            {
                "type": "pid"
            },
            {
                "type": "network"
            },
            {
                "type": "ipc"
            },
            {
                "type": "uts"
            },
            {
                "type": "mount"
            }
        ],
        "maskedPaths": [
            "/proc/kcore",
            "/proc/latency_stats",
            "/proc/timer_list",
            "/proc/timer_stats",
            "/proc/sched_debug",
            "/sys/firmware",
            "/proc/scsi"
        ],
        "readonlyPaths": [
            "/proc/asound",
            "/proc/bus",
            "/proc/fs",
            "/proc/irq",
            "/proc/sys",
            "/proc/sysrq-trigger"
        ]
    }
}
"""

# A basic rootless OCI configuration
OCI_CONTAINER_ROOTLESS_CONFIG = """
{
   "process":{
      "args":[
         "/bin/sh"
      ],
      "terminal":false,
      "rlimits":[
         {
            "soft":1024,
            "hard":1024,
            "type":"RLIMIT_NOFILE"
         }
      ],
      "env":[
         "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
         "TERM=xterm"
      ],
      "noNewPrivileges":true,
      "cwd":"/"
   },
   "linux":{
      "readonlyPaths":[
         "/proc/bus",
         "/proc/fs",
         "/proc/irq",
         "/proc/sys",
         "/proc/sysrq-trigger"
      ],
      "namespaces":[
         {
            "type":"mount"
         },
         {
            "type":"pid"
         },
         {
            "type":"ipc"
         }
      ],
      "resources":{
         "devices":[
            {
               "access":"rwm",
               "allow":false
            }
         ]
      }
   },
   "mounts":[
      {
         "source":"proc",
         "destination":"/proc",
         "type":"proc"
      },
      {
         "source":"tmpfs",
         "destination":"/dev",
         "type":"tmpfs",
         "options":[
            "nosuid",
            "strictatime",
            "mode=755",
            "size=65536k"
         ]
      },
      {
         "source":"devpts",
         "destination":"/dev/pts",
         "type":"devpts",
         "options":[
            "nosuid",
            "noexec",
            "newinstance",
            "ptmxmode=0666",
            "mode=0620"
         ]
      },
      {
         "source":"shm",
         "destination":"/dev/shm",
         "type":"tmpfs",
         "options":[
            "nosuid",
            "noexec",
            "nodev",
            "mode=1777",
            "size=65536k"
         ]
      },
      {
         "source":"mqueue",
         "destination":"/dev/mqueue",
         "type":"mqueue",
         "options":[
            "nosuid",
            "noexec",
            "nodev"
         ]
      },
      {
        "destination": "/sys",
        "type": "none",
        "source": "/sys",
        "options": [
            "rbind",
            "nosuid",
            "noexec",
            "nodev",
            "ro"
        ]
      }
   ],
   "ociVersion":"1.0.0",
   "root":{
      "path":"rootfs",
      "readonly":false
   }
}
"""


class OciConfig(object):
    """Load update and save OCI configurations from containers.
    """
    def __init__(self, path=None, rootless=True):
        """Initialize an OCI configuration.

        Keyword Arguments:
            path {string} -- path to load (default: {None})
            rootless {bool} -- is rootless (default: {True})
        """
        self.config = None
        self.rootless = rootless

        if path is None:
            if rootless:
                # Get the generic rootless config
                initial_config = OCI_CONTAINER_ROOTLESS_CONFIG
            else:
                # This is the non-rootless case
                initial_config = OCI_CONTAINER_CONFIG
            self.config = json.loads(initial_config)
        else:
            #
            # Here we load the config.json
            #
            with open(path) as config_file:
                self.config = json.load(config_file)

    @property
    def mounts(self):
        return self.config.setdefault("mounts", [])

    def _check_ipc_mounts(self):
        linux = self.config.setdefault("linux", {})
        # Make sure that the userns is present
        ns = linux.setdefault("namespaces", [])
        nsl = [e["type"] for e in ns if "type" in e]

        mounts = self.config.setdefault("mounts", [])

        # If the IPC namespace is not present remove the mqueue mount
        nml = []
        if "ipc" not in nsl:
            for m in mounts:
                if "type" in m and m["type"] == "mqueue":
                    logging.info("Ignoring mqueue"
                                 " mount as IPC namespace not present")
                    # Convert to a bindmount
                    m["source"] = "/dev/mqueue"
                    m["type"] = "bind"
                    m["options"] = ['rbind', 'rw']
                nml.append(m)
            self.config["mounts"] = nml

    def save(self, path):
        """Save OCI configuration file.

        Arguments:
            path {string} -- path to config.json
        """
        self._check_ipc_mounts()
        # As entrypoint is not standard if it is present
        # we need to concatenate it to the command just before saving
        # so that it yields the same behavior
        proc_conf = self.config.setdefault("process", {})

        if "args" in proc_conf:
            original_args = proc_conf["args"]
        else:
            original_args = []

        new_cmd = list(original_args)

        if "entrypoint" in proc_conf:
            new_cmd = proc_conf["entrypoint"] + new_cmd

        proc_conf["args"] = new_cmd

        with open(path, 'w') as outfile:
            json.dump(self.config, outfile, indent=4)

        # print(json.dumps(self.config, outfile, indent=4))

        # Restore the previous args af if nothing happened
        proc_conf["args"] = original_args

    def readonly(self, value=True):
        """Mark the container FS as writable.
        """
        self.config.setdefault("root", {})["readonly"] = value

    def set_gid(self, gid):
        """Set GID for running the container.

        Arguments:
            gid {int} -- GID to use for running
        """
        self.config.setdefault("process", {})\
                   .setdefault("user", {})["gid"] = gid

    def set_uid(self, uid):
        """Set the UID for running the container.

        Arguments:
            uid {int} -- UID to use for running
        """
        self.config.setdefault("process", {})\
                   .setdefault("user", {})["uid"] = uid

    def append_uid_mapping(self, hostid, contid, size=1):
        linux = self.config.setdefault("linux", {})
        uidmap = linux.setdefault("uidMappings", [])
        mp = {"hostID": hostid, "containerID": contid, "size": size}
        uidmap.append(mp)

    def append_gid_mapping(self, hostid, contid, size=1):
        linux = self.config.setdefault("linux", {})
        uidmap = linux.setdefault("gidMappings", [])
        mp = {"hostID": hostid, "containerID": contid, "size": size}
        uidmap.append(mp)

    def set_hostname(self, hostname):
        """Set hostname in container.

        Arguments:
            hostname {string} -- container hostname
        """
        self.config.setdefault("linux", {})\
                   .setdefault("namespaces", {})\
                   .setdefault("uts", {})["hostname"] = hostname

    def env(self):
        proc = self.config.setdefault("process", {})
        return proc.setdefault("env", [])

    def get_env(self):
        current_keys = {}
        for v in self.config["process"]["env"]:
            entry = v.split("=")
            if len(entry) >= 2:
                name = entry[0]
                val = "=".join(entry[1:])
                current_keys[name] = val
        return current_keys

    def set_env(self, env, filt=None):
        """Set environment variables inside the container.

        Arguments:
            env {array or dict} -- array/dict of environment variables

        Keyword Arguments:
            filt {string} -- Keep only keys starting with (default: {None})

        Raises:
            InvalidConfigurationError -- filt can only be applied to dict 'env'
        """
        self.config.setdefault("process", {})\
                   .setdefault("env", [])

        if isinstance(env, list):
            # We append env as a list
            if filt:
                raise InvalidConfigurationError(
                    "Cannot filter entries when appending an array in env")

            # Load current keys in a dict
            current_keys = self.get_env()
            candidate_keys = {}

            # Load candiate keys from 'env' arg
            for v in env:
                entry = v.split("=")
                if len(entry) >= 2:
                    name = entry[0]
                    val = "=".join(entry[1:])
                    candidate_keys[name] = val

            # Now replace with new vars
            for k in candidate_keys:
                current_keys[k] = candidate_keys[k]

            # Save new keys
            self.config["process"]["env"] = [x + "=" +
                                             v for x, v in
                                             current_keys.items()]
        else:
            # Env is a dict simply merge
            for k, v in env.items():
                if filt:
                    if not k.startswith(filt):
                        continue
                self.config["process"]["env"].append(k + "=\"" + v + "\"")

    def cwd(self):
        proc = self.config.setdefault("process", {})
        if "cwd" in proc:
            return proc["cwd"]
        else:
            return None

    def set_cwd(self, cwd):
        """Set the run workdir for the container.

        Arguments:
            cwd {string} -- path to workdir
        """
        self.config.setdefault("process", {})["cwd"] = cwd

    def set_entrypoint(self, entrypoint):
        """Set the entrypoint command for the container.

        Arguments:
            entrypoint {array} -- entrypoint command for the container
        """
        # Entrypoint is not standard in config.json !
        # it will be 'linearized' as args in SAVE
        self.config.setdefault("process", {})["entrypoint"] = entrypoint

    def set_command(self, command):
        """Set the run command for the container.

        Arguments:
            command {array} -- argv of command to be run
        """
        self.config.setdefault("process", {})["args"] = command

    def set_terminal(self, isterminal):
        """Whether to run in a pty.

        Arguments:
            isterminal {bool} -- run in a terminal
        """
        self.config.setdefault("process", {})["terminal"] = bool(isterminal)

    def apply_container_config(self,
                               container,
                               config_path=None,
                               rootfs_path=None):
        """Merge Container configuration inside OCI image.

        Arguments:
            container {Container} -- configuration to apply
        """
        # We check the container config only when
        # actually using it
        container.check(config_path, rootfs_path)

        self.config.setdefault("linux", {})

        # Handle namespaces
        ns = container.ns_list()
        self.config["linux"]["namespaces"] = ns

        # Handle hooks
        oci_hooks = self.config.setdefault("hooks", {})
        for k, v in container.hooks().items():
            array = oci_hooks.setdefault(k, [])
            array += v

        # Handle mounts
        if self.rootless:
            mounts = container.mount_list(transpose=False)
        else:
            mounts = container.mount_list(transpose=True)

        self.config["mounts"] = self.config["mounts"] + mounts

    def _import_from_process(self, original_config, key):
        conf = original_config.config

        self.config.setdefault("process", {})

        if "process" in conf:
            if key in conf["process"]:
                print("IMPORT " + key)
                self.config["process"][key] = conf["process"][key]

    def import_process(self, original_config):
        """Import process config from another OCI configuration.

        Arguments:
            original_config {OciConfig} -- OCI conf from which to import
        """
        conf = original_config.config

        self.config.setdefault("process", {})

        if "process" in conf:
            self.config["process"] = conf["process"]

    def import_cwd(self, original_config):
        """Import cwd from another OCI configuration.

        Arguments:
            original_config {OciConfig} -- OCI conf from which to import
        """
        self._import_from_process(original_config, "cwd")

    def import_env(self, original_config):
        """Import env from another OCI configuration.

        Arguments:
            original_config {OciConfig} -- OCI conf from which to import
        """
        self._import_from_process(original_config, "env")

    def is_mounted(self, src, dest=None):
        if not dest:
            dest = src

        # Make sure path is not manually mounted
        mounted_path = False

        for m in self.mounts:
            mdest = m["destination"]
            # print("dest {} {}  == {} {}".format(dest,
            #                                     os.path.realpath(dest),
            #                                     mdest,
            #                                     os.path.realpath(mdest)))
            if dest.startswith(mdest):
                mounted_path = True
                break

        return mounted_path

    def add_mount_if_needed(self,
                            src,
                            dest=None,
                            mount_type="bind",
                            options=None,
                            transpose=False):
        if not self.is_mounted(src, dest):
            self.add_mount(src, dest, mount_type, options,  transpose)

    def add_mount(self,
                  src,
                  dest=None,
                  mount_type='bind',
                  options=None,
                  transpose=False,
                  prepend=False):
        if not options:
            if mount_type == "tmpfs":
                options = ["nosuid", "nodev", "mode=1777", "rw"]
            else:
                # Default to bind
                options = ['rbind', 'rw']

        if dest is None:
            dest = src

        # Apply pcocc substitutions
        src = Config().resolve_path(src)
        if mount_type == 'bind':
            # Normalize source path
            src = os.path.normpath(src)
            # Only resolve bindmounts
            src = os.path.realpath(src)
            # Now append
            if transpose:
                src = path_join("/rootfs/", src)
        dest = Config().resolve_path(dest)

        new_mount = {'source': src,
                     'destination': dest,
                     'type': mount_type,
                     'options': options}

        logging.debug(str(new_mount))

        if prepend:
            self.mounts.insert(0, new_mount)
        else:
            self.mounts.append(new_mount)

    def mirror_mount(self, path, transpose=True):
        """Add a mountpoint in config (replacing previous).

        Arguments:
            path {string} -- path to mount

        Keyword Arguments:
            transpose {bool} -- prefix for VM (default: {True})
        """
        mounts = self.mounts
        # First remove from current image
        mounts = [m
                  for m in mounts
                  if (os.path.normpath(m["destination"]) !=
                      os.path.normpath(path))]

        # As no path matching home was specified
        # in mounts we inject the User's one
        self.add_mount(path, path, transpose=transpose)


class Container(dict):
    """Define a container and its attached configuration.

    Raises:
        InvalidConfigurationError -- Bad parameters were passed as config
    """

    def __init__(self, name, settings):
        """Intialize a container instance.

        Arguments:
            name {string} -- container name
            settings {dict} -- key-value list of settings
        """
        self["name"] = name
        self.append(settings)

    def _extract_command_lines(self, program_output, flag):
        mlist = program_output.split("\n")
        mount_flag = flag
        flist = [e[len(mount_flag):].strip()
                 for e in mlist
                 if e.startswith(mount_flag) and len(e)]
        # Filter possible empty commands
        flist = [e for e in flist if len(e)]
        return flist

    def _expand_command_based_mounts(self, program_output):
        mlist = self._extract_command_lines(program_output, "MOUNT ")

        new_mounts = []

        def handle_mount(path):
            src = path
            dest = path
            if ":" in path:
                # Path has a dest
                sp = path.split(":")
                src = sp[0]
                dest = sp[1]

            try:
                mode = os.stat(src).st_mode
            except os.error:
                logging.warning("Could not locate '{}' ".format(path) +
                                "generated from mountpoint")
                return

            if (stat.S_ISDIR(mode) or
                    stat.S_ISREG(mode) or
                    stat.S_ISFIFO(mode) or
                    stat.S_ISSOCK(mode)):
                # Regular mount
                new_mounts.append({"source": src,
                                   "destination": dest})
            elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                # Devices
                new_mounts.append({"source": src,
                                   "destination": dest,
                                   "options": ["dev"]})
            elif stat.S_ISLNK(mode):
                # Link we need to resolve to the real path
                src = os.readlink(src)
                handle_mount(src + ":" + dest)

        for p in mlist:
            handle_mount(p)

        # Convert to a dict
        cnt = 0
        to_add = {}
        for e in new_mounts:
            to_add["mount_" + str(cnt)] = e
            cnt = cnt + 1

        # Now update mounts with new mounts
        self["mounts"].update(to_add)

    def _expand_command_based_env(self, program_output):
        elist = self._extract_command_lines(program_output, "ENV ")

        conf_env = self.setdefault("env", [])
        for e in elist:
            conf_env.append(e)

        conf_prefix = self.setdefault("pathprefix", [])
        plist = self._extract_command_lines(program_output, "PATHPREFIX ")
        for e in plist:
            conf_prefix.append(e)

        conf_suffix = self.setdefault("pathsuffix", [])
        slist = self._extract_command_lines(program_output, "PATHSUFFIX ")
        for e in slist:
            conf_suffix.append(e)

    def _expand_command_based_modules(self, program_output):
        mlist = self._extract_command_lines(program_output, "MODULE ")

        for m in mlist:
            if m in container_config.module_cont:
                mc = container_config.module_cont
                module_conf = mc.build_for_container(m,
                                                     required=True)
                self.append(module_conf)
            else:
                logging.warning("Could not locate '{}' ".format(m) +
                                "generated from modules")

    def apply_generator_config(self, cmd, config_path=None, rootfs_path=None):
        # Apply command-based configurations

        logging.info("Expanding configuration generator"
                     " from '%s'" % (cmd))

        # Now run the command
        argv = shlex.split(cmd) + [config_path, rootfs_path]
        output = ""

        try:
            output = subprocess.check_output(argv)
        except (subprocess.CalledProcessError, OSError) as e:
            raise PcoccError("Could not run "
                             "generator '{}': {}\n".format(" ".join(argv),
                                                           output)
                             + str(e))

        # And parse it for the various elems
        self._expand_command_based_mounts(output)
        self._expand_command_based_env(output)
        self._expand_command_based_modules(output)

    def sanitize_mounts(self):
        """Walk the container list to ensure that mounts are correct.
        """
        for n, m in self["mounts"].items():
            if "source" not in m:
                raise InvalidConfigurationError(
                    ("Container [{0}] mountpoint {1} should"
                     " have a least a 'source'").format(self["name"], n))
            else:
                m["source"] = Config().resolve_path(m["source"])
                m["source"] = os.path.realpath(m["source"])

            if "type" not in m:
                m["type"] = "bind"
                logging.info(("Container [%s] Assuming"
                              " 'bind' type for mountpoint %s")
                             % (self["name"], n))

            if "options" not in m:
                if m["type"] == "bind":
                    m["options"] = ["rbind", "rw"]
                    logging.info(("Container [%s] Default bind"
                                  " options for mountpoint %s")
                                 % (self["name"], n))

            if "destination" not in m:
                m["destination"] = m["source"]
                logging.info(("Container [%s] Assuming 'destination' "
                              "is same as 'source' for mountpoint %s")
                             % (self["name"], n))

            m["destination"] = Config().resolve_path(m["destination"])

    def unfold_device_mounts(self):
        """ Make sure no directory is mounted with
        device permisions by unfolding such mounts
        """
        to_remove = []
        to_add = {}

        for n, m in self["mounts"].items():
            if "options" not in m:
                continue
            opt = m["options"]
            if "dev" not in opt:
                continue
            # If we are here we have a mountpoint
            # which is flagged as device
            src = os.path.normpath(m["source"])
            is_dir = os.path.isdir(src)

            if not is_dir:
                # Nothing to do
                continue

            to_remove.append(n)

            dest = src

            cnt = 0

            if "destination" in m:
                dest = os.path.normpath(m["destination"])

            for root, _, files in os.walk(src):
                for f in files:
                    target = path_join(root, f)
                    cnt = cnt + 1

                    reloc = os.path.normpath(target).replace(src, dest)

                    logging.debug("Expanding device"
                                  " dir %s --> %s" % (target, reloc))

                    to_add[n + "_" + str(cnt)] = {"source": target,
                                                  "destination": reloc,
                                                  "options": m["options"]}

        for e in to_remove:
            del self["mounts"][e]

        # And add the new ones
        self["mounts"].update(to_add)

    def check(self, config_path=None, rootfs_path=None):
        """Validate container configuration.
        """
        # Apply the command list just before running
        if "generator" in self:
            for cmd in self["generator"]:
                self.apply_generator_config(cmd, config_path, rootfs_path)

        self.unfold_device_mounts()
        self.sanitize_mounts()

    def _insert_unique_array(self, key, settings):
        """Merge local setting and incoming settings array.

        Arguments:
            key {string} -- Key to be merged in self and settings
            settings {dict} -- Container configuration to import
        """
        # First the key exists
        if key in settings:
            # Do we already have an entry then append
            if key in self:
                self[key] = self[key] + settings[key]
            else:
                # No current entry assign
                self[key] = settings[key]
            # Remove duplicates
            self[key] = list(set(self[key]))

    def append(self, settings):
        """Append a configuration to the container.

        Arguments:
            settings {dict} -- configuration object
        """
        # Handle command note that we gather the various
        # commands in a list as we want to be able to handle
        # multiple commands when several modules are used
        if "generator" in settings:
            generators = self.setdefault("generator", [])
            self["generator"] = settings["generator"] + generators

        # Handle Mounts
        self.setdefault("mounts", {})
        if "mounts" in settings:
            self["mounts"].update(settings["mounts"])

        if "inherits" in settings:
            self.setdefault("inherits", [])
            self["inherits"] = settings["inherits"]

        # Handle Namespaces
        self._insert_unique_array("ns", settings)

        # Handle hooks
        if "hooks" in settings:
            self["hooks"] = settings["hooks"]

        # Handle environment variables
        if "pathprefix" in settings:
            self.setdefault("pathprefix", []).extend(settings["pathprefix"])
        if "pathsuffix" in settings:
            self.setdefault("pathsuffix", []).extend(settings["pathsuffix"])
        self._insert_unique_array("env", settings)

    def hooks(self):
        return self.setdefault("hooks", {})

    def mount_list(self, transpose=True):
        """Generate mount list.

        Keyword Arguments:
            transpose {bool} -- Prefix with 9P mountpoint (default: {True})

        Returns:
            array -- array of mounts

        """
        ret = []
        self.setdefault("mounts", {})
        for _, v in self["mounts"].items():
            tmp = dict(v)
            if "source" in v:
                if transpose:
                    # Transpose to the 9P mountpoint
                    tmp["source"] = path_join("/rootfs/", tmp["source"])
            ret.append(tmp)

        return ret

    def ns_list(self):
        """Generate namespace list.

        Returns:
            array -- array of namespaces

        """
        ret = []
        self.setdefault("ns", [])
        for v in self["ns"]:
            ret.append({"type": v})
        return ret

    def pathsuffix(self):
        self.setdefault("pathsuffix", [])
        return self["pathsuffix"]

    def pathprefix(self):
        self.setdefault("pathprefix", [])
        return self["pathprefix"]

    def env(self):
        self.setdefault("env", [])
        return self["env"]


def load_yaml(filename, required=False):
    try:
        with open(filename, 'r') as stream:
            res_config = yaml.safe_load(stream)
            return res_config
    except yaml.YAMLError as err:
        # Failed to parse and validate
        raise InvalidConfigurationError(str(err))
    except IOError as err:
        if required or err.errno != errno.ENOENT:
            # Not found and required
            raise InvalidConfigurationError(str(err))
        else:
            return None


class ContainerConfig(dict):
    """Load container configuration file.

    Raises:
        InvalidConfigurationError -- Failed to parse and validate YAML
        InvalidConfigurationError -- Required configuration file not found
    """
    container_config_schema = """
    type: object
    additionalProperties:
        type: object
        properties:
            generator:
                type : array
                items:
                    type: string
            inherits:
                anyOf:
                    - type: string
                    - type: array
                      items:
                        type: string
            mounts:
                type: object
                additionalProperties:
                    type: object
                    properties:
                        source:
                            type : string
                        destination:
                            type : string
                        type:
                            type: string
                        options:
                            type : array
                            items:
                                type: string
            hooks:
                type: object
                additionalProperties:
                    type: array
                    items:
                        type: object
                        properties:
                            path:
                                type: string
                            args:
                                type: array
                                items:
                                    type: string
                            env:
                                type: array
                                items:
                                    type: string
                            timeout:
                                type: integer
                        required:
                            - path
            ns:
                type: array
                items:
                    type: string
                    enum:
                        - uts
                        - pid
                        - ipc
                        - mount
                        - network
                        - user
            pathprefix:
                type: array
                items:
                    type: string
            pathsuffix:
                type: array
                items:
                    type: string
            env:
                type: array
                items:
                    type: string
        additionalProperties: False
    """

    def _check_inheritance_loops(self,
                                 cont_name,
                                 current_list=None):
        if current_list is None:
            current_list = []
        if cont_name not in self:
            raise InvalidConfigurationError("No such container "
                                            "config {} ".format(cont_name) +
                                            "in heritance")
        cont = self[cont_name]
        if "inherits" in cont:
            new_herit = cont["inherits"]

            for new_parent in new_herit:
                # Check that it is not already in list
                if new_parent in current_list:
                    message = ("Double inheritance detected "
                               "for configuration {}".format(cont_name))
                    raise InvalidConfigurationError(message)
                current_list.append(new_parent)

                # Recursive check on next cont
                self._check_inheritance_loops(new_parent, current_list)
        else:
            return

    def _rec_inherit(self, cont, current_cont):
        cont.append(current_cont)
        if "inherits" in current_cont:
            for c in current_cont["inherits"]:
                self._rec_inherit(cont, self[c])

    def _apply_inheritance(self):
        list_of_cont = [k for k in self]
        for cont_name in list_of_cont:
            self._check_inheritance_loops(cont_name)
            cont = self[cont_name]
            if "inherits" in cont:
                for c in cont["inherits"]:
                    self._rec_inherit(cont, self[c])

    def load(self, filename, required=False):
        """Load a containers.yaml configuration file.

        Arguments:
            filename {string} -- path to the configuration file to load

        Keyword Arguments:
            required {bool} -- raise an erorr if not found (default: {False})

        Raises:
            InvalidConfigurationError -- required and not found
            InvalidConfigurationError -- failed to parse and validate
        """
        res_config = load_yaml(filename, required=required)
        if res_config is None:
            # We will error when loading the file if it is required
            return
        self.load_obj(res_config)

    def load_obj(self, res_config):
        try:
            # Load and validate the configuration file
            schema = yaml.safe_load(self.container_config_schema)
            jsonschema.validate(res_config,
                                schema)
        except jsonschema.exceptions.ValidationError as err:
            # Failed to parse and validate
            raise InvalidConfigurationError(str(err))

        # If the config contains string inheritance
        # convert them to list inheritance to handle a single case later on
        for _, res_attr in res_config.iteritems():
            if "inherits" in res_attr:
                if isinstance(res_attr["inherits"], str):
                    res_attr["inherits"] = [res_attr["inherits"]]

        # We now register each entry as a container in
        # local dict (this class inherits from dict)
        for name, res_attr in res_config.iteritems():
            if name in self:
                # Already here append params
                self[name].append(res_attr)
            else:
                # New configuration just create
                self[name] = Container(name, res_attr)
        # Now that all configs are loaded we need to
        # linearize them by following potential
        # inheritance links
        self._apply_inheritance()

    def build_for_container(self, name, required=False, no_defaults=False):
        """Retrieve configuration for a given container.

        Arguments:
            name {string} -- container to configure

        Returns:
            Container -- container specifically configured

        """
        # Build a new container
        ret = Container(name, {})
        if not no_defaults:
            # Apply the 'default' configuration
            if "default" in self:
                ret.append(self["default"])
        else:
            # Here we use the empty default
            # with basic namespaces
            ret.append({"ns": ["mount"]})
        # Override with the container specific conf
        if name in self:
            ret.append(self[name])
        else:
            if required:
                raise PcoccError("No such container "
                                 "configuration {}".format(name))
        # Return the new container
        return ret


class ContainerOptions(dict):

    pcocc_container_option_schema = """
    type: object
    properties:
        container_shm_work_path:
            type: string
        container_shm_work_limit:
            type: integer
        use_squashfs:
            type: boolean
        squashfs_image_mountpoints:
            type: array
            items:
                type: string
        enable_oci_hooks:
            type: boolean
        docker_path:
            type: string
        docker_use_ip_address:
            type: boolean
        docker_pod:
            type: string
        use_runc:
            type: boolean
        docker_mounts:
            type: array
            items:
                type: object
                properties:
                    src:
                        type: string
                    dest:
                        type: string
                required:
                    - src
    additionalProperties: false
    """

    def __init__(self):
        self["docker_path"] = None
        self["docker_use_ip_address"] = False
        self["docker_pod"] = None
        self["docker_mounts"] = []
        self["docker_test_path"] = "/var/run/docker/metrics.sock"
        self["enable_oci_hooks"] = False
        self["use_squashfs"] = False
        self["squashfs_image_mountpoints"] = []
        self["container_shm_work_path"] = "/dev/shm"
        self["container_shm_work_limit"] = 250
        self["use_runc"] = False

    @property
    def use_runc(self):
        return self["use_runc"]

    @property
    def container_shm_work_path(self):
        return self["container_shm_work_path"]

    @property
    def container_shm_work_limit(self):
        return self["container_shm_work_limit"]

    @property
    def squashfs_image_mountpoints(self):
        return set(self["squashfs_image_mountpoints"] + ["/etc/resolv.conf",
                                                         "/etc/group",
                                                         "/etc/passwd"])

    @property
    def use_squashfs(self):
        return self["use_squashfs"]

    @property
    def docker_test_path(self):
        return self["docker_test_path"]

    @property
    def enable_oci_hooks(self):
        return self["enable_oci_hooks"]

    @property
    def docker_mounts(self):
        return self["docker_mounts"]

    @property
    def docker_path(self):
        if self["docker_path"] is None:
            # Try to locate in env
            if not spawn.find_executable("docker"):
                raise PcoccError("You did not specify a 'docker_path' in "
                                 "the 'containers.yaml' configuration file "
                                 "and 'docker' is not in your path."
                                 " Cannot pursue.")
        else:
            return self["docker_path"]

    @property
    def docker_pod(self):
        if self["docker_pod"] is None:
            raise PcoccError("Could not resolve the Docker pod, make sure"
                             " the 'docker_pod' variable is configured in"
                             " the containers.yaml file. Cannot pursue.")
        return self["docker_pod"]

    @property
    def docker_use_ip(self):
        return self["docker_use_ip_address"]

    def load_obj(self, config):
        # Validate its structure
        try:
            # Load and validate the configuration file
            schema = yaml.safe_load(self.pcocc_container_option_schema)
            jsonschema.validate(config,
                                schema)
        except jsonschema.exceptions.ValidationError as err:
            # Failed to parse and validate
            raise InvalidConfigurationError(str(err))

        # Load the config
        for k, v in config.items():
            self[k] = v


class PcoccContainerConf(object):

    pcocc_global_cont_schema = """
    type: object
    properties:
        containers:
            type: object
        modules:
            type: object
        config:
            type: object
    additionalProperties: false
    required:
        - containers
        - modules
        - config
    """

    def __init__(self):
        self._per_cont = ContainerConfig()
        self._module_cont = ContainerConfig()
        self._config = ContainerOptions()

    @property
    def per_cont(self):
        return self._per_cont

    @property
    def module_cont(self):
        return self._module_cont

    @property
    def config(self):
        return self._config

    def load(self, config_file, required=False):
        # Load the config object
        yaml_data = load_yaml(config_file, required=required)
        if yaml_data is None:
            # No config provided skip note that load_yaml
            # raises an Exception if it was required
            return

        # Validate its structure
        try:
            # Load and validate the configuration file
            schema = yaml.safe_load(self.pcocc_global_cont_schema)
            jsonschema.validate(yaml_data,
                                schema)
        except jsonschema.exceptions.ValidationError as err:
            # Failed to parse and validate
            raise InvalidConfigurationError(str(err))

        # At this point the config is valid now forward
        # to subparts of the config
        if "containers" in yaml_data:
            self._per_cont.load_obj(yaml_data["containers"])

        if "modules" in yaml_data:
            self._module_cont.load_obj(yaml_data["modules"])

        if "config" in yaml_data:
            self._config.load_obj(yaml_data["config"])


#
# We instanciate the container config locally
# as we may need to access it to apply modules
#
container_config = PcoccContainerConf()
