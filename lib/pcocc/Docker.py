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

import subprocess
import os
import tempfile
import shutil
import uuid
import socket
import logging
import shlex
from distutils import spawn


from pcocc import agent_pb2

from .Agent import AgentCommand
from .Error import PcoccError
from .Image import ContainerView
from .VMCerts import VMCerts
from .Config import Config
from .Misc import path_join


class PcoccDocker(object):
    def __init__(self, vm=None):
        self.docker_container_id = "docker"
        self.certs = VMCerts(vm.rank)
        self.vm = vm

    def cert_dir(self):
        return self.certs.client_cert_dir

    def get_docker_host(self, vm=None):
        if not vm:
            vm = self.vm

        docker_host, docker_port = self.certs.host(vm)
        if Config().containers.config.docker_use_ip:
            # We resolve the host to its IP
            data = socket.gethostbyname_ex(docker_host)
            docker_host = data[2][0]
        return "tcp://" + docker_host + ":" + str(docker_port)

    def assert_docker_shell(self):
        if "PCOCC_DOCKER" not in os.environ:
            raise PcoccError("This command is only available in a docker shell")

    def _delete_docker(self, obj_id, kind):
        rmcmd = ["docker",
                 kind,
                 "rm",
                 obj_id]
        docker_run = subprocess.Popen(rmcmd, env=os.environ)
        return docker_run.wait()

    def _delete_container(self, container_id):
        return self._delete_docker(container_id, "container")

    def _delete_image(self, image_id):
        return self._delete_docker(image_id, "image")

    def mount(self, cluster, rangeset, src_path, dest_path):
        enter_docker_cont = ["ctr",
                             "-n",
                             "services.linuxkit",
                             "tasks",
                             "exec",
                             "--exec-id",
                             "mount",
                             self.docker_container_id]

        if dest_path[-1] == "/":
            dest_path = dest_path[:-1]

        # Make sure that the path is not already a mount

        mount_was_found = False

        mount_cmd = ["mount"]
        mnt_ret = AgentCommand.exec_output(cluster,
                                           rangeset,
                                           enter_docker_cont + mount_cmd)
        for ret in mnt_ret:
            if isinstance(ret, agent_pb2.ExecOutputResult):
                if ret.retcode == 0:
                    if dest_path + " type 9p" in ret.output:
                        # The mountpoint is present
                        mount_was_found = True

        if mount_was_found:
            # Nothing to do
            return

        # Check that the path is not already present in original docker image
        stat_command = ["stat",
                        dest_path]
        st_ret = AgentCommand.exec_output(cluster,
                                          rangeset,
                                          enter_docker_cont + stat_command)
        for ret in st_ret:
            if isinstance(ret, agent_pb2.ExecOutputResult):
                if ret.retcode == 0:
                    raise PcoccError("{} appears to exist".format(dest_path) +
                                     " in Docker environment "
                                     "a new mount cannot be inserted")

        mkdirp_command = ["mkdir",
                          "-p",
                          dest_path]
        AgentCommand.exec_output(cluster,
                                 rangeset,
                                 enter_docker_cont + mkdirp_command)
        # Mount by symlinking
        mount_command = ["mount",
                         "--bind",
                         path_join("/.pcocc_rootfs/", src_path),
                         dest_path]
        AgentCommand.exec_output(cluster,
                                 rangeset,
                                 enter_docker_cont + mount_command)
        logging.info("DOCKER: done mouting %s on %s" % (src_path,
                                                        dest_path))

    def apply_mounts(self, cluster, rangeset):
        for mnt in Config().containers.config.docker_mounts:
            if "dest" not in mnt:
                mnt["dest"] = mnt["src"]
            self.mount(cluster, rangeset, mnt["src"], mnt["dest"])

    def wait_for_docker_start(self, cluster, rangeset, timeout=300):
        target_path = Config().containers.config.docker_test_path
        tcmd = ["/bin/sh",
                "-c",
                'while test ! -e {}; do sleep 0.1; done'.format(target_path)]

        try:
            AgentCommand.exec_output(cluster,
                                     rangeset,
                                     tcmd,
                                     timeout=int(timeout))
        except PcoccError:
            raise PcoccError("Timed out while waiting"
                             " for the docker daemon to start.\n"
                             "Make sure current VM is docker enabled")

    def build_image(self, cluster, vm_index, dest_image, path=None):
        cluster.wait_host_config()
        self.assert_docker_shell()
        Config().images.check_overwrite(dest_image)

        if path is None:
            path = os.getcwd()

        if not os.path.isfile(os.path.join(path, "Dockerfile")):
            raise PcoccError("Could not locate a Dockerfile"
                             " in target path '{}'".format(path))

        docker_image_name = uuid.uuid4().hex
        build_command = ["docker",
                         "build",
                         "-t", docker_image_name,
                         path]

        docker_run = subprocess.Popen(build_command, env=os.environ)
        ret = docker_run.wait()
        if ret != 0:
            raise PcoccError("Image build returned a non-null error code")

        # Copy back to pcocc
        self.get_image(cluster, vm_index, dest_image, docker_image_name)

        # Clean docker
        self._delete_image(docker_image_name)

    def _get_etc_passwd_path(self, src_image):
        """Get a path to bundle with focus on /etc/passwd

        Arguments:
            src_image {str} -- source image uri

        Returns:
            str -- path to bundle with /etc/passwd (None if not available)
            bool -- if the parent function has to handle delete
        """
        # Use a bundle
        bundle = Config().images.cache_get(src_image, "cached_bundle")

        if bundle:
            return bundle, False

        # Use a squashfs
        squashfs = Config().images.cache_get(src_image, "cached_squashfs")

        if squashfs:
            # It is now time to extract /etc/passwd from the FS
            if not spawn.find_executable("unsquashfs"):
                # We won't be able to extract
                return None, False

            tempdir = tempfile.mkdtemp()

            try:
                cmd = ["unsquashfs", "-f", "-d",
                       tempdir,
                       squashfs,
                       "/rootfs/etc/passwd"]

                with open("/dev/null", "w") as f:
                    subprocess.check_call(cmd, stdout=f, stderr=f)
            except (subprocess.CalledProcessError, OSError):
                return None, True

            return tempdir, True

    def _infer_rootfs_shell(self, src_image):
        bundle, do_delete_bundle = self._get_etc_passwd_path(src_image)

        ret = []

        if bundle:
            # Look in /etc/passwd
            rootfs = path_join(bundle, "rootfs")
            etc_pswd = path_join(rootfs, "/etc/passwd")
            if os.path.exists(etc_pswd):
                with open(etc_pswd, "r") as f:
                    data = f.read()
                root_line = [e for e in data.split("\n")
                             if e.startswith("root")]
                if root_line:
                    ret = root_line[0].split(":")[-1]

        if do_delete_bundle:
            shutil.rmtree(bundle)

        if ret:
            logging.info("Using %s as default shell" % ret)

        return ret

    def edit_image(self,
                   cluster,
                   vm_index,
                   src_image,
                   target_image,
                   cmd=None):
        cluster.wait_host_config()
        self.assert_docker_shell()
        Config().images.check_overwrite(target_image)
        # First send the image to docker
        docker_image_name = uuid.uuid4().hex
        self.send_image(cluster,
                        vm_index,
                        src_image,
                        docker_image_name,
                        silent=False)
        # Now run the edit commmand
        if (cmd is None) or (len(cmd) == 0):
            # If the command is not defined try to infer
            # a potential shell to run instead
            cmd = [self._infer_rootfs_shell(src_image)]

        docker_cont_name = uuid.uuid4().hex
        docker_command = ["docker",
                          "run",
                          "--name",
                          docker_cont_name,
                          "-ti", docker_image_name] + cmd
        print("###########################################")
        print("# You are now editing your image          #")
        print("# Hit CTRL + D to save your modifications #")
        print("###########################################")

        docker_run = subprocess.Popen(docker_command, env=os.environ)
        ret = docker_run.wait()
        if ret != 0:
            raise PcoccError("Image edit returned a non-null error code")

        print("\n###########################################")
        print("# Saving modified image ...               #")
        print("###########################################")

        # It is now time to commit the container
        docker_new_image_id = uuid.uuid4().hex
        commit_command = ["docker",
                          "commit",
                          docker_cont_name,
                          docker_new_image_id]
        docker_run = subprocess.Popen(commit_command, env=os.environ)
        ret = docker_run.wait()
        if ret != 0:
            raise PcoccError("Failed at saving the modified container image")

        # Import the new image back
        self.get_image(cluster, vm_index, target_image, docker_new_image_id)

        # Cleanup the temporaries
        self._delete_container(docker_cont_name)
        self._delete_image(docker_new_image_id)

    def send_image(self,
                   cluster,
                   vm_index,
                   src_image,
                   name,
                   tag="latest",
                   silent=False):
        cluster.wait_host_config()
        self.assert_docker_shell()

        with ContainerLayoutView(src_image, view_type="oci") as oci_view:
            vm = cluster.vms[vm_index]
            docker_host = self.get_docker_host(vm)

            cmd = ["skopeo",
                   "copy",
                   "--dest-tls-verify",
                   "--dest-daemon-host", docker_host,
                   "--dest-cert-dir", self.cert_dir(),
                   "oci:" + oci_view,
                   "docker-daemon:"+ name + ":" + tag ]

            try:
                skopeo = subprocess.check_call(cmd, env=os.environ)
            except Exception:
                raise PcoccError("Could not send image to docker daemon")
            finally:
                shutil.rmtree(oci_view)

    def get_image(self,
                  cluster,
                  vm_index,
                  dest_image,
                  src_image,
                  tag="latest"):
        cluster.wait_host_config()
        # Check that the image is not already in repo
        # we do it before exporting from Docker
        Config().images.check_overwrite(dest_image)
        Config().images.import_image("vm{}/{}:{}".format(vm_index, src_image, tag),
                                     dest_image, "pcocc-docker-daemon", docker=self)

    def _generate_docker_env(self,
                             cluster,
                             docker_path,
                             vm_index=0,
                             propagate=True):

        #RQ: Eviter d'en mettre trop bas dans la stack si pas necessaire
        cluster.wait_host_config()

        if propagate:
            shell_env = dict(os.environ)
        else:
            shell_env = {}

        vm = cluster.vms[vm_index]
        docker_host = self.get_docker_host(vm)

        if propagate:
            # Do not alter the prompt if the user just ask
            # for the docker related parameters only do
            # when starting a shell
            shell_env['PCOCC_DOCKER'] = "1"
            if "PROMPT_COMMAND" not in shell_env:
                shell_env['PROMPT_COMMAND'] = ('echo -n "(pcocc/%d) "'
                                               % (Config().batch.batchid))
        shell_env['DOCKER_CERT_PATH'] = self.cert_dir()
        shell_env['DOCKER_TLS_VERIFY'] = "1"
        shell_env['DOCKER_HOST'] = docker_host
        shell_env['PATH'] = docker_path + ":" + os.getenv('PATH')

        return shell_env

    def env(self, cluster, vm_index, docker_path):
        docker_env = self._generate_docker_env(cluster,
                                               docker_path,
                                               vm_index,
                                               propagate=False)
        for k, v in docker_env.items():
            print("export {}={}".format(k, v))

    def shell(self, cluster, docker_path, vm_index=0, script=None):
        shell_env = self._generate_docker_env(cluster,
                                              docker_path,
                                              int(vm_index))

        if "PCOCC_DOCKER" in os.environ:
            raise PcoccError("You cannot start a docker"
                             " shell in a docker shell")

        shell = os.getenv('SHELL', default='bash')

        if script:
            shell = shlex.split(script)

        return subprocess.Popen(shell, env=shell_env)
