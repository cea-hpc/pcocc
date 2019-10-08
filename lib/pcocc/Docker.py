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
import uuid
import socket
import logging
import shlex

from .Agent import AgentCommand
from .Error import PcoccError
from .Image import ContainerLayoutView
from .Config import Config
from .Misc import path_join
from .EthNetwork import VEthNetwork


def apply_mounts(cluster, rangeset):
    for mnt in Config().containers.config.docker_mounts:
        if "dest" not in mnt:
            mnt["dest"] = mnt["source"]
        _mount(cluster, rangeset, mnt["source"], mnt["dest"])

def wait_for_docker_start(cluster, rangeset, timeout=300):
    target_path = Config().containers.config.docker_test_path
    logging.info("Docker: waiting for daemon")
    tcmd = ["/bin/sh", "-c", 'while test ! -e {}; do sleep 1; done'.format(target_path)]
    try:
        AgentCommand.exec_output(cluster,
                                 rangeset,
                                 tcmd,
                                 timeout=int(timeout))
    except PcoccError:
        # FIXME: seulement en cas de timeout
        raise PcoccError("Timed out while waiting"
                         " for the docker daemon to start.\n"
                         "Make sure current VM is docker enabled")

    logging.info("Docker: daemon is started")

def build_image(vm, dest_image, path=None):
    env = os.environ.copy()
    _setup_docker_env(vm)

    docker_image_name = uuid.uuid4().hex
    build_command = ["docker", "build", "-t", docker_image_name, path]
    subprocess.check_call(build_command)

    try:
        get_image(vm, dest_image, docker_image_name)
    finally:
        _delete_image(docker_image_name)

    os.environ = env

def send_image(vm, src_image, dest_image, dest_tag="latest", silent=False):
    env = os.environ.copy()
    _setup_docker_env(vm)
    try:
        with ContainerLayoutView(src_image) as oci_view:
            cmd = ["skopeo",
                   "copy",
                   "--dest-tls-verify",
                   "--dest-daemon-host", get_docker_uri(vm),
                   "--dest-cert-dir", certs_dir("client"),
                   "oci:" + oci_view,
                   "docker-daemon:"+ dest_image + ":" + dest_tag ]

            subprocess.check_call(cmd)
    except subprocess.CalledProcessError:
        raise PcoccError("Could not send image to docker daemon")
    os.environ = env

def get_image(vm, dest_image, src_image, src_tag="latest"):
    env = os.environ.copy()
    _setup_docker_env(vm)
    Config().images.import_image("{}:{}".format(src_image, src_tag),
                                 dest_image, "pcocc-docker-daemon", vm=vm)
    os.environ = env

def env(vm):
    docker_env = _generate_docker_env(vm, propagate=False)
    for k, v in docker_env.items():
        print("export {}={}".format(k, v))

def shell(vm, script=None):
    shell_env = _generate_docker_env(vm)

    if script:
        shell = shlex.split(script)
    else:
        shell = os.getenv('SHELL', default='bash')

    return subprocess.Popen(shell, env=shell_env)

def _mount(cluster, rangeset, src_path, dest_path):
    enter_docker_ctr = ["ctr", "-n", "services.linuxkit", "tasks",
                        "exec", "--exec-id", "mount", "docker"]

    mkdirp_command = ["mkdir", "-p", dest_path]
    AgentCommand.exec_output(cluster,
                             rangeset,
                             enter_docker_ctr + mkdirp_command)

    mount_command = ["mount",
                     "--bind",
                     path_join("/.pcocc_rootfs/", src_path),
                     dest_path]
    AgentCommand.exec_output(cluster,
                             rangeset,
                             enter_docker_ctr + mount_command)

    logging.info("Docker: mounted host path: %s on docker-daemon path: %s", src_path, dest_path)



def get_docker_uri(vm, port=22):
    docker_port = VEthNetwork.get_rnat_host_port(vm.rank, port)
    docker_host = vm.get_host()

    if Config().containers.config.docker_use_ip:
        docker_host = _resolve(docker_host)

    return "tcp://" + docker_host + ":" + str(docker_port)


def _resolve(host):
    data = socket.gethostbyname_ex(host)
    logging.info("Resolved %s to %s", host, data[2][0])
    return data[2][0]


def _setup_docker_env(vm):
    env = _generate_docker_env(vm)
    os.environ.update(env)

def _delete_container(container_id):
    subprocess.check_call(["docker", "container", "rm", container_id])

def _delete_image(image_id):
    subprocess.check_call(["docker", "image", "rm", image_id])

def _generate_docker_env(vm,
                         propagate=True):

    if propagate:
        shell_env = dict(os.environ)
    else:
        shell_env = {}

    if propagate:
        if "PROMPT_COMMAND" not in shell_env:
            shell_env['PROMPT_COMMAND'] = ('echo -n "(pcocc/%d) "'
                                           % (Config().batch.batchid))

    shell_env['DOCKER_CERT_PATH'] = certs_dir("client")
    shell_env['DOCKER_TLS_VERIFY'] = "1"
    shell_env['DOCKER_HOST'] = get_docker_uri(vm)

    if Config().containers.config.docker_path:
        shell_env['PATH'] = Config().containers.config.docker_path + ":" + os.getenv('PATH')

    return shell_env


def _certs_base_dir():
    return os.path.join(Config().batch.cluster_state_dir,
                        "vmcerts")

def certs_dir(host):
    return os.path.join(_certs_base_dir(),
                        host)

def init_client_certs():
    os.makedirs(_certs_base_dir())
    os.chmod(_certs_base_dir(), 0o700)
    client_certs = _gen_client_certs()
    _write_certs(certs_dir("client"), client_certs)
    return certs_dir("client")

def _gen_client_certs():
    client_cert = Config().batch.ca_cert
    client_ca_cert = client_cert.ca_cert
    client_key = client_cert.key
    client_cert = client_cert.cert
    return {"cert": client_cert, "key": client_key, "ca": client_ca_cert}

def init_server_certs(vm):
    host = vm.get_host()
    altname = ["IP:" + _resolve(host)]
    server_cert = _gen_server_certs(host, altname)
    dest = certs_dir("vm{}".format(vm.rank))
    _write_certs(dest, server_cert)

    return dest

def _gen_server_certs(hostname, altname):
    server_cert = Config().batch.ca_cert.gen_cert(
        hostname,
        altname=altname)
    server_ca_cert = server_cert.ca_cert
    server_key = server_cert.key
    server_cert = server_cert.cert
    return {"cert": server_cert, "key": server_key, "ca": server_ca_cert}

def _write_certs(target_dir, cert_data):
    os.makedirs(target_dir)
    os.chmod(target_dir, 0o700)

    for key, value in cert_data.items():
        path = os.path.join(target_dir,
                            key + ".pem")
        _write_cert_file(path, value)

def _write_cert_file(path, data):
    with os.fdopen(os.open(path,
                           os.O_WRONLY | os.O_CREAT,
                           0o600), 'w') as f:
        f.write(data)

