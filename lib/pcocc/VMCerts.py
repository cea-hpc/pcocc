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
import socket

from .Config import Config
from pcocc.Error import PcoccError
from pcocc.EthNetwork import VEthNetwork
from .Misc import path_join


class VMCerts(object):
    def __init__(self, vm_rank=0):
        self.server_cert_dir = self._cert_dir(vm_rank)
        self._client_cert_dir = None

    @property
    def client_cert_dir(self):
        if self._client_cert_dir is None:
            self.deploy_client_cert()
        return self._client_cert_dir

    def deploy_server_cert(self):
        alt_name = ["IP:" + k for k in self._remote_vm_ip()]
        server_cert = self._server_certs(self._remote_vm_host(),
                                         altname=alt_name)
        self._safe_write_cert(self.server_cert_dir, server_cert)
        return self.server_cert_dir

    def deploy_client_cert(self):
        self._client_cert_dir = self._cert_dir()
        if os.path.isfile(path_join(self.client_cert_dir, "cert.pem")):
            # Already generated
            return self.client_cert_dir
        self.client_cert = self._client_certs()
        self._safe_write_cert(self.client_cert_dir, self.client_cert)
        return self.client_cert_dir

    def home(self):
        certs_home_dir = os.path.join(Config().batch.cluster_state_dir,
                                      "vmcerts")
        if not os.path.isdir(certs_home_dir):
            try:
                os.makedirs(certs_home_dir)
            except OSError as e:
                # Another VM may have created the dir
                if e.errno != os.errno.EEXIST:
                    raise e
        return certs_home_dir

    def _cert_dir(self, rank=None):
        cert_dir = self.home()
        rank = str(rank) if (rank is not None) else "client"
        cert_dir = os.path.join(cert_dir, rank)
        if not os.path.isdir(cert_dir):
            os.makedirs(cert_dir)
        # logging.error(cert_dir)
        return cert_dir

    def _remote_vm_ip(self, vm=None):
        host = self._remote_vm_host(vm)
        data = socket.gethostbyname_ex(host)
        return data[2]

    def _remote_vm_host(self, vm=None):
        if vm is None:
            return socket.gethostname()
        return Config().batch.get_rank_host(vm.rank)

    def _remote_vm_port(self, vm, port=22):
        host_port = VEthNetwork.get_rnat_host_port(vm.rank, port)
        if host_port:
            return host_port

        raise PcoccError("Could not resolve rnat port for ssh")

    def _server_certs(self, hostname="vm0", altname=None):
        server_cert = Config().batch.ca_cert.gen_cert(hostname,
                                                      altname=altname)
        server_ca_cert = server_cert.ca_cert
        server_key = server_cert.key
        server_cert = server_cert.cert
        return {"cert": server_cert, "key": server_key, "ca": server_ca_cert}

    def _client_certs(self):
        client_cert = Config().batch.ca_cert
        client_ca_cert = client_cert.ca_cert
        client_key = client_cert.key
        client_cert = client_cert.cert
        return {"cert": client_cert, "key": client_key, "ca": client_ca_cert}

    def _create_user_file(self, path, data):
        with os.fdopen(os.open(path,
                               os.O_WRONLY | os.O_CREAT,
                               0o600), 'w') as f:
            f.write(data)

    def _safe_write_cert(self, target_dir, cert_data):
        os.chmod(target_dir, 0o700)

        for key, value in cert_data.items():
            path = os.path.join(target_dir,
                                key + ".pem")
            self._create_user_file(path, value)

        return target_dir

    def host(self, vm, port=22):
        vm_port = self._remote_vm_port(vm, port=port)
        vm_host = self._remote_vm_host(vm)
        return vm_host, vm_port
