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
import subprocess
import pipes

from distutils import spawn
from copy import deepcopy


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


class OciRuntimeConfig(object):
    def __init__(self, rootless=True):
        self.rootless = rootless

        if rootless:
            self.config = json.loads(OCI_CONTAINER_ROOTLESS_CONFIG)
        else:
            self.config = json.loads(OCI_CONTAINER_ROOTLESS_CONFIG)

        self.transposed_mounts = []

    @property
    def mounts(self):
        return self.config["mounts"]

    def _check_ipc_mounts(self):
        ns = self.config["linux"]["namespaces"]

        nsl = [e["type"] for e in ns if "type" in e]

        mounts = self.config["mounts"]

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

    def save(self, path, transpose_prefix=None):
        #FIXME: This should be done earlier
        self._check_ipc_mounts()

        new_cmd = list(self.config["process"].get("args", []))
        if "entrypoint" in self.config["process"]:
            new_cmd = self.config["process"]["entrypoint"] + new_cmd

        final_config = deepcopy(self.config)
        final_config["process"]["args"] = new_cmd

        if transpose_prefix:
            for m in self.config["mounts"]:
                if m in self.transposed_mounts:
                    for nm in final_config["mounts"]:
                        if nm["source"] == m["source"] and nm["destination"] == m["destination"]:
                            nm["source"] = path_join("/rootfs", nm["source"])

        with open(path, 'w') as outfile:
            json.dump(final_config, outfile, indent=4)

    def readonly(self, value=True):
        self.config.setdefault("root", {})["readonly"] = value

    def set_gid(self, gid):
        self.config.setdefault("process", {})\
                   .setdefault("user", {})["gid"] = gid

    def set_uid(self, uid):
        self.config.setdefault("process", {})\
                   .setdefault("user", {})["uid"] = uid

    def set_additional_gids(self, gids):
        self.config.setdefault("process", {})\
                   .setdefault("user", {})["additionalGids"] = gids

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
        self.config.setdefault("linux", {})\
                   .setdefault("namespaces", {})\
                   .setdefault("uts", {})["hostname"] = hostname

    def env(self):
        proc = self.config.setdefault("process", {})
        return proc.setdefault("env", [])

    def quote_env(self):
        """Quota environment variables"""

        new_env = []
        for k, v  in self.get_env().items():
            new_env.append(k + "=" + pipes.quote(v))

        self.config["process"]["env"] = new_env

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
                                             list(current_keys.items())]
        else:
            # Env is a dict simply merge
            for k, v in list(env.items()):
                if filt:
                    if not k.startswith(filt):
                        continue
                self.config["process"]["env"].append(k + "=" + v )

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

    def merge_template(self, template):
        # Handle namespaces
        ns = template.ns_list()
        self.config["linux"]["namespaces"] = ns

        # Handle mounts
        for m in template.mount_list():
            self.add_mount(m['source'], m['destination'], m['type'],
                           m['transpose'], m['options'])

        # XXX: environment variables are handled separately

    def import_config(self, conf, field):
        if field in conf:
            self.config[field] = conf[field]

    @property
    def namespaces(self):
        r = []
        for n in self.config["linux"]["namespaces"]:
            r.append(n["type"])

        return r

    def is_mounted(self, dest):
        for m in self.mounts:
            mdest = m["destination"]
            if mdest[-1] != os.sep:
                mdest += os.sep

            if (dest + os.sep).startswith(mdest):
                return True
        return False

    def add_mount(self,
                  src,
                  dest=None,
                  mount_type='bind',
                  transpose=True,
                  options=None,
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
        # Normalize source path
        src = os.path.normpath(src)
        if mount_type == 'bind':
            # Only resolve bindmounts
            src = os.path.realpath(src)

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

        if transpose:
            self.transposed_mounts.append(new_mount)

    def mirror_mount(self, path, transpose=True):
        mounts = self.mounts[:]
        self.config["mounts"] = [m
                                 for m in mounts
                                 if (os.path.normpath(m["destination"]) !=
                                     os.path.normpath(path))]

        # As no path matching home was specified
        # in mounts we inject the User's one
        self.add_mount(path, path, transpose=transpose)


class ContainerTemplate(dict):
    """Holds all the settings for a single container template
    """

    def __init__(self, name, settings):
        self["name"] = name
        self.merge_settings(settings)

    def apply_generator_config(self, cmd, config_path=None, rootfs_path=None):
        logging.info("Running configuration generator %s", cmd)

        argv = shlex.split(cmd) + [config_path, rootfs_path]

        try:
            output = subprocess.check_output(argv)
        except (subprocess.CalledProcessError, OSError) as e:
            raise PcoccError("Could not run configuration "
                             "generator '{}': {}\n".format(" ".join(argv), e))

        output=output.decode()

        self._expand_command_based_mounts(output)
        self._expand_command_based_env(output)
        self._expand_command_based_modules(output)



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

        for p in mlist:
            sp = p.split(":")
            src = sp[0]
            dest = sp[-1]

            src = os.path.realpath(src)

            try:
                mode = os.stat(src).st_mode
            except os.error:
                logging.warning("Skipping mount command of non-existing path '%s' ", p)
                return

            if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                # Devices
                options=['dev']
            else:
                options=[]

            self["mounts"]['_gen_{}'.format(dest)]={"source": src, "destination": dest,
                                                    "options": options, "type": "bind",
                                                    "transpose": True}

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
        # FIXME: generators for such modules will not be applied
        for m in mlist:
            module_template = Config().containers.modules.get_template(m,
                                                                      required=True)
            self.merge_settings(module_template)

    def sanitize_mounts(self):
        for name, opt in list(self["mounts"].items()):
            if "source" not in opt:
                raise InvalidConfigurationError(
                    ("Container {} mountpoint {} should"
                     " have a least a 'source'").format(self["name"], name))

            if "type" not in opt:
                opt["type"] = "bind"
                logging.debug("Assuming 'bind' type for mountpoint %s", name)


            if not 'transpose' in opt:
                opt['transpose'] = True

            if "options" not in opt:
                if opt["type"] == "bind":
                    opt["options"] = ["rbind", "rw"]
                    logging.debug("Using default bind options for mountpoint %s", name)

            if "destination" not in opt:
                opt["destination"] = opt["source"]

    def instanciate(self, config_path=None, rootfs_path=None):
        """Polpulate dynamic configurations based on container instance and host node"""
        if "generator" in self:
            for cmd in self["generator"]:
                self.apply_generator_config(cmd, config_path, rootfs_path)

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

    def merge_settings(self, settings):
        if "inherits" in settings:
            self.setdefault("inherits", settings["inherits"])

        self.setdefault("mounts", {})

        if "mounts" in settings:
            new_mounts = deepcopy(settings["mounts"])
            new_mounts.update(deepcopy(self["mounts"]))
            self["mounts"] = new_mounts

        if "generator" in settings:
            generators = self.setdefault("generator", [])
            self["generator"] = settings["generator"] + generators

        if "pathprefix" in settings:
            self.setdefault("pathprefix", []).extend(settings["pathprefix"])

        if "pathsuffix" in settings:
            self.setdefault("pathsuffix", []).extend(settings["pathsuffix"])

        self._insert_unique_array("ns", settings)

        self._insert_unique_array("env", settings)

    def mount_list(self):
        ret = []
        self.setdefault("mounts", {})
        for _, v in list(self["mounts"].items()):
            tmp = dict(v)
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
            res_config = yaml.load(stream, Loader=yaml.CSafeLoader)
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


class ContainerTemplateConfig(dict):
    """Holds template configurations that can be applied to pcocc container images
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
        cont.merge_settings(current_cont)
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

    def load_obj(self, tpl_config):
        try:
            schema = yaml.load(self.container_config_schema, Loader=yaml.CSafeLoader)
            jsonschema.validate(tpl_config,
                                schema)
        except jsonschema.exceptions.ValidationError as err:
            raise InvalidConfigurationError(str(err))

        # Make sure inheritance configurations are defined as lists
        for _, res_attr in tpl_config.items():
            if "inherits" in res_attr:
                if isinstance(res_attr["inherits"], str):
                    res_attr["inherits"] = [res_attr["inherits"]]

        for name, tpl_attrs in tpl_config.items():
            # Update existing template or create a new one
            if name in self:
                self[name].merge_settings(tpl_attrs)
            else:
                self[name] = ContainerTemplate(name, tpl_attrs)

        # Resolve inheritance links after all template are loadeds
        self._apply_inheritance()

    def get_template(self, name, required=False, no_defaults=False):
        ret = ContainerTemplate(name, {})
        if no_defaults or not "default" in self:
            # We always need mount namespaces so include
            # them in the no-defaults mode
            ret.merge_settings({"ns": ["mount"]})
        else:
            ret.merge_settings(self["default"])

        # Override with the container specific conf
        if name in self:
            ret.merge_settings(self[name])
        else:
            if required:
                raise PcoccError("No such container "
                                 "configuration: {}".format(name))
        # Return the new container
        return ret


class ContainerRuntimeConfig(dict):
    """ Holds global runtime options for handling containers """
    pcocc_container_option_schema = """
    type: object
    properties:
        default_registry:
            type: string
        insecure_registries:
            type: array
            items:
                 type: string
        tmp_mem_path:
            type: string
        tmp_mem_limit:
            type: integer
        image_driver:
            enum:
                - flat
                - squashfs
        image_mountpoints:
            type: array
            items:
                type: string
        docker_path:
            type: string
        docker_resolve_address:
            type: boolean
        docker_template:
            type: string
        docker_mounts:
            type: array
            items:
                type: object
                properties:
                    source:
                        type: string
                    dest:
                        type: string
                required:
                    - source
    additionalProperties: false
    """

    def __init__(self):
        self["docker_path"] = None
        self["docker_resolve_address"] = False
        self["docker_template"] = None
        self["docker_mounts"] = []
        self["image_driver"] = "flat"
        self["image_mountpoints"] = []
        self["tmp_mem_path"] = "/dev/shm"
        self["tmp_mem_limit"] = 250
        self["default_registry"] = None
        self["insecure_registries"] = []


    @property
    def default_registry(self):
        return self["default_registry"]

    @property
    def insecure_registries(self):
        return self["insecure_registries"]

    @property
    def container_shm_work_path(self):
        return self["tmp_mem_path"]

    @property
    def container_shm_work_limit(self):
        return self["tmp_mem_limit"]

    @property
    def img_mountpoints(self):
        return set(self["image_mountpoints"] + ["/etc/resolv.conf",
                                                "/etc/group",
                                                "/etc/passwd"])

    @property
    def use_squashfs(self):
        return self["image_driver"] == "squashfs"

    @property
    def docker_test_path(self):
        return "/var/run/docker/metrics.sock"

    @property
    def docker_mounts(self):
        return self["docker_mounts"]

    @property
    def docker_path(self):
        if self["docker_path"] is None:
            # Try to locate in env
            if not spawn.find_executable("docker"):
                raise PcoccError("docker_path is not set in containers.yaml "
                                 "and 'docker' is not in your path.")
        else:
            return self["docker_path"]

    @property
    def docker_pod(self):
        if self["docker_template"] is None:
            raise PcoccError("docker_template is not defined in containers.yaml")
        return self["docker_template"]

    @property
    def docker_use_ip(self):
        return self["docker_resolve_address"]

    def load_obj(self, config):
        try:
            schema = yaml.load(self.pcocc_container_option_schema, Loader=yaml.CSafeLoader)
            jsonschema.validate(config,
                                schema)
        except jsonschema.exceptions.ValidationError as err:
            raise InvalidConfigurationError(str(err))

        for k, v in list(config.items()):
            self[k] = v


class ContainerConfig(object):
    pcocc_global_cont_schema = """
    type: object
    properties:
        containers:
            type: object
        modules:
            type: object
        runtime:
            type: object
    additionalProperties: false
    """

    def __init__(self):
        self._templates = ContainerTemplateConfig()
        self._modules = ContainerTemplateConfig()
        self._runtime_config = ContainerRuntimeConfig()

    @property
    def templates(self):
        return self._templates

    @property
    def modules(self):
        return self._modules

    @property
    def config(self):
        return self._runtime_config

    def get(self, image, modules, config_path, rootfs_path, no_defaults):
        tpl = self.templates.get_template(image, False, no_defaults)
        for m in modules:
            tpl.merge_settings(self.modules.get_template(m, required=True))

        tpl.instanciate(config_path, rootfs_path)

        return tpl

    def load(self, config_file, required=False):
        yaml_data = load_yaml(config_file, required=required)
        if yaml_data is None:
            return

        # Validate the top level schema
        try:
            schema = yaml.load(self.pcocc_global_cont_schema, Loader=yaml.CSafeLoader)
            jsonschema.validate(yaml_data,
                                schema)
        except jsonschema.exceptions.ValidationError as err:
            raise InvalidConfigurationError(str(err))

        # Load and validate sub schemas
        self._templates.load_obj(yaml_data.get("containers", {}))
        self._modules.load_obj(yaml_data.get("modules", {}))
        self._runtime_config.load_obj(yaml_data.get("runtime", {}))
