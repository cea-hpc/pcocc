#  Copyright (C) 2014-2018 CEA/DAM/DIF
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

import grpc
import pcocc_pb2
import pcocc_pb2_grpc
import os
import time
import tempfile
import socket
import json
import threading
import logging
import subprocess
import yaml

from OpenSSL import crypto
from concurrent import futures
from Queue import Queue
from Config import Config
from Error import PcoccError

#
# Helper functions from pyOpenSSL
#

def createKeyPair(type, bits):
    """
    Create a public/private key pair.
    Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
               bits - Number of bits to use in the key
    Returns:   The public/private key pair in a PKey object
    """
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey

def createCertRequest(pkey, digest="md5", **name):
    """
    Create a certificate request.
    Arguments: pkey   - The key to associate with the request
               digest - Digestion method to use for signing, default is md5
               **name - The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
    Returns:   The certificate request in an X509Req object
    """
    req = crypto.X509Req()
    subj = req.get_subject()

    for (key,value) in name.items():
        setattr(subj, key, value)

    req.set_pubkey(pkey)
    req.sign(pkey, digest)
    return req

def createCertificate(req, (issuerCert, issuerKey), serial, (notBefore, notAfter), digest="sha1"):
    """
    Generate a certificate given a certificate request.
    Arguments: req        - Certificate reqeust to use
               issuerCert - The certificate of the issuer
               issuerKey  - The private key of the issuer
               serial     - Serial number for the certificate
               notBefore  - Timestamp (relative to now) when the certificate
                            starts being valid
               notAfter   - Timestamp (relative to now) when the certificate
                            stops being valid
               digest     - Digest method to use for signing, default is sha1
    Returns:   The signed certificate in an X509 object
    """
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(issuerKey, digest)
    return cert


class Cert(object):
    def __init__(
            self,
            key_data,
            cert_data,
            ca_cert_data = None
    ):
        self._key_data = key_data
        self._cert_data = cert_data
        self._ca_cert_data = ca_cert_data

    def dump_yaml(self):
        cert = {"key_data": self._key_data,
                "cert_data": self._cert_data,
                "ca_cert_data": self._ca_cert_data}

        return yaml.dump(cert)

    @property
    def key(self):
        return self._key_data

    @property
    def cert(self):
        return self._cert_data

    @property
    def ca_cert(self):
        if self._ca_cert_data:
            return self._ca_cert_data
        else:
            return self._cert_data

    @classmethod
    def load_yaml(cls, yaml_data):
        cert = yaml.safe_load(yaml_data)
        try:
            key_data = cert["key_data"]
            cert_data = cert["cert_data"]
            ca_cert_data = cert["ca_cert_data"]

        except (KeyError, yaml.YAMLError) as err:
            raise PcoccError("Unable to load certificate: " + str(err))

        return cls(key_data, cert_data, ca_cert_data)


class UserCA(Cert):
    """This class represents the root certificate which signs client
    certificates authenticating communications between hypervisor
    agents of a given user

    """
    @classmethod
    def new(cls, key_size=2048, days=9999):
        logging.debug("Generating CA cert...")
        cakey = createKeyPair(crypto.TYPE_RSA, key_size)
        careq = createCertRequest(cakey, CN='PcoccUserCA')
        cacert = createCertificate(careq, (careq, cakey), 0, (0, 60*60*24*days))

        ca_key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, cakey)
        ca_cert_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cacert)
        logging.debug("Done generating CA cert")
        return cls(ca_key_data, ca_cert_data)

    def gen_cert(self, cn, key_size=2048, days=9999):
        logging.debug("Generating cert for " + cn)
        cacert = crypto.load_certificate(crypto.FILETYPE_PEM, self.cert)
        cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, self.key)

        pkey = createKeyPair(crypto.TYPE_RSA, key_size)
        req = createCertRequest(pkey, CN=cn)
        cert = createCertificate(req, (cacert, cakey), 1, (0, 60*60*24*days))

        key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
        cert_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

        return Cert(key_data, cert_data, self.cert)

#
# Multi-Threaded Generator Plumbing
#

def mt_tee(source_iterator):
    """
    Duplicate a generator function
    stream in a MT fashion 'tee'
    """
    q1 = Queue()
    q2 = Queue()
    is_running = [1]

    def queue_gen(q, run):
        while True:
            ret = q.get()
            if ret is None:
                return
            else:
                yield ret

    iter1 = queue_gen(q1, is_running)
    iter2 = queue_gen(q2, is_running)

    def tee_th(run):
        try:
            for d in source_iterator:
                q1.put(d)
                q2.put(d)
        except:
            pass

        q1.put(None)
        q2.put(None)

    # Start the TEE th
    th = threading.Thread(target=tee_th, args=(is_running, ))
    th.setDaemon(True)
    th.start()

    return iter1, iter2


def mt_chain(*iterators):
    """
    Chain two generators in a MT
    fashion (as 'chain')
    """
    active = len(iterators)
    queue = Queue()

    def iterator_progress(it):
        for n in it:
            queue.put(n)
        queue.put(None)

    workers = []
    for i in range(0, len(iterators)):
        workers.append(threading.Thread(
            target=iterator_progress,
            args=(iterators[i], )))

        workers[i].start()

    while active:
        data = queue.get()
        if data is None:
            active = active - 1
        else:
            yield data

    for i in range(0, len(iterators)):
        workers[i].join()

class TreeNodeClient(object):
    """
    TreeNode is a node in the TBON
    tree as a consequence it is connected
    in a BTREE fashion
    """
    def __init__(self,
                 vmid=0,
                 enable_ssl=True,
                 enable_client_auth=False):

        if enable_client_auth and not enable_ssl:
            raise PcoccError("Client auth is only avalaible with SSL")

        self._endpoints = {}
        self._endpoints_lock = threading.Lock()
        self._vmid = vmid
        self._enable_ssl = enable_ssl
        self._enable_client_auth = enable_client_auth

        self._tree_size = Config().batch.vm_count()

        self._pc = None
        self._lc = None
        self._rc = None

        self._ps = None
        self._ls = None
        self._rs = None

        self._pid = -1
        self._lid = -1
        self._rid = -1

        self._routes = {}

        self._gen_children_list()
        self._connect()

    def __del__(self):
        del self._ps
        del self._ls
        del self._rs
        del self._pc
        del self._rc
        del self._lc

    class Target(object):
        NotSet, Parent, Left, Right = range(4)

    def route(self, command):
        try:
            route = self._routes[command.destination]
        except KeyError:
            route = self.Target.Parent

        ret = self._send_cmd(route, command)

        return ret

    def exec_stream(self, input_iterator, req_array=None):
        try:
            children_it = self._send_exec(input_iterator, req_array)
            for e in children_it:
                yield e
        except:
            # We failed
            return

    def _send_cmd(self, target, command):
        stub = None
        if target == self.Target.Left:
            stub = self._ls
        elif target == self.Target.Right:
            stub = self._rs
        elif target == self.Target.Parent:
            stub = self._ps

        return stub.route_command(command)

    def _send_exec(self, request_stream, req_array=None):
        if (self._ls is None) and (self._rs is None):
            return

        if self._ls and self._rs:
            left_dup, right_dup = mt_tee(request_stream)
            lreq = self._ls.exec_stream(left_dup)
            rreq = self._rs.exec_stream(right_dup)

            if req_array:
                req_array.push(lreq)
                req_array.push(rreq)

            for e in mt_chain(lreq, rreq):
                yield e

        else:
            target = self._rs
            if self._ls:
                target = self._ls
            req = target.exec_stream(request_stream)
            if req_array:
                req_array.push(req)
            for e in req:
                yield e

    def _gen_children_list(self):
        me = self._vmid
        self._recurse_children_list(me, self._tree_size,
                                    self.Target.NotSet)

    def _recurse_children_list(self, current, bound, choice):
        # Recursive scan on childs
        left = (current + 1) * 2 - 1
        right = (current + 1) * 2
        route = choice
        if left < bound:
            if choice == self.Target.NotSet:
                route = self.Target.Left

            self._routes[left] = route
            self._recurse_children_list(left, bound, route)
        if right < bound:
            if choice == self.Target.NotSet:
                route = self.Target.Right
            self._routes[right] = route
            self._recurse_children_list(right, bound, route)

    def _get_endpoint(self, target):
        self._endpoints_lock.acquire()
        if not target in self._endpoints:
            endp = Config().batch.read_key(
                "cluster/user",
                "hostagent/vms/{0}".format(target),
                blocking=True)
            self._endpoints[target]= endp.split(":")
        self._endpoints_lock.release()
        return self._endpoints[target]

    def _connect(self):
        me = self._vmid
        parent = (me + 1) // 2 - 1
        leftc = (me + 1) * 2 - 1
        rightc = (me + 1) * 2
        if me == 0:
            parent = -1

        if self._tree_size <= leftc:
            leftc = -1

        if self._tree_size <= rightc:
            rightc = -1

        self._pid = parent
        self._lid = leftc
        self._rid = rightc

        if self._enable_ssl is False:
            if 0 <= parent:
                pinfo = self._get_endpoint(parent)
                self._pc = grpc.insecure_channel(pinfo[1] + ":" + pinfo[2])
            if 0 <= leftc:
                pinfo = self._get_endpoint(leftc)
                self._lc = grpc.insecure_channel(pinfo[1] + ":" + pinfo[2])
            if 0 <= rightc:
                pinfo = self._get_endpoint(rightc)
                self._rc = grpc.insecure_channel(pinfo[1] + ":" + pinfo[2])
        else:
            client_cert = Config().batch.ca_cert
            if self._enable_client_auth:
                credential = grpc.ssl_channel_credentials(
                    root_certificates=client_cert.ca_cert,
                    private_key=client_cert.key,
                    certificate_chain=client_cert.cert
                )
            else:
                credential = grpc.ssl_channel_credentials(
                    root_certificates=keys[2])
            if 0 <= parent:
                pinfo = self._get_endpoint(parent)
                self._pc = grpc.secure_channel(pinfo[1]
                                              + ":" + pinfo[2], credential)
            if 0 <= leftc:
                pinfo = self._get_endpoint(leftc)
                self._lc = grpc.secure_channel(pinfo[1]
                                              + ":" + pinfo[2], credential)
            if 0 <= rightc:
                pinfo = self._get_endpoint(rightc)
                self._rc = grpc.secure_channel(pinfo[1]
                                              + ":" + pinfo[2], credential)

        if 0 <= parent:
            self._ps = pcocc_pb2_grpc.pcoccNodeStub(self._pc)
        if 0 <= leftc:
            self._ls = pcocc_pb2_grpc.pcoccNodeStub(self._lc)
        if 0 <= rightc:
            self._rs = pcocc_pb2_grpc.pcoccNodeStub(self._rc)


class TreeNode(pcocc_pb2_grpc.pcoccNodeServicer):
    """
    This class defines a TBON node it mostly
    contains server side code the client
    side code is in the TreeNodeClient
    """
    def __init__(self,
                 vmid=0,
                 port="50051",
                 handler=None,
                 enable_ssl=True,
                 client_ssl_auth=True,
                 exec_input_handler=None,
                 exec_output_handler=None,
                 exec_input_eof_notifier=None):

        self._relay = None
        self._vmid = int(vmid)
        self._port = port
        self._handler = handler
        self._exec_output_handler = exec_output_handler
        self._exec_input_handler = exec_input_handler
        self._exec_input_eof_notifier = exec_input_eof_notifier
        self._server = grpc.server(futures.ThreadPoolExecutor(max_workers=25))

        pcocc_pb2_grpc.add_pcoccNodeServicer_to_server(self, self._server)

        if enable_ssl is False:
            self._port = self._server.add_insecure_port("[::]:{0}".format(port))
        else:
            server_cert = Config().batch.ca_cert.gen_cert(socket.gethostname())
            credential = grpc.ssl_server_credentials(
                ((server_cert.key, server_cert.cert), ),
                server_cert.ca_cert,
                client_ssl_auth
            )
            self._port = self._server.add_secure_port(
                "[::]:{0}".format(port),
                credential
            )

        logging.debug("CommandServer Now Listening on %s:%s",
                      socket.gethostname(),
                      self._port)

        self._server.start()
        self._register()
        # Server is ON now start the relay
        self._relay = TreeNodeClient(self._vmid,
                                    enable_ssl,
                                    client_ssl_auth)


    def command(self, dest, cmd, data):
        json_dat = json.dumpsxo(data)
        docommand = pcocc_pb2.Command(source=self._vmid,
                                      destination=dest,
                                      cmd=cmd,
                                      data=json_dat)
        return self._route_command(docommand)

    def exec_stream(self, request_iterator, context):
        local_iter, forward_iter = mt_tee(request_iterator)

        next_req_array = []

        # FIXME: Pourquoi ? Semble inutile de cancel une RPC qui se
        # termine
        # context.add_callback(context.cancel)

        def send_output():
            if self._exec_output_handler:
                for output in self._exec_output_handler(context.is_active):
                    yield output

        def send_input():
            for inpu in local_iter:
                if inpu.eof is True:
                    break
                if self._exec_input_handler:
                    self._exec_input_handler(inpu)

        thread = threading.Thread(target=send_input)
        thread.start()

        for e in mt_chain(
                send_output(),
                self._relay.exec_stream(
                    forward_iter,
                    next_req_array)):
            yield e

    def _register(self):
        logging.debug("Registering hostagent/vms/%s", self._vmid)
        Config().batch.write_key('cluster/user',
                                 "hostagent/vms/{0}".format(self._vmid),
                                 "{0}:{1}:{2}".format(
                                     self._vmid,
                                     socket.gethostname(),
                                     self._port))


    def _process_local(self, command):
        # print("SRC:" + str(command.source))
        # print("DEST:" + str(command.destination))
        # logging.info("PL CMD:" + command.cmd)
        # print("DATA:" + command.data)
        # resp = "RET : " + command.data
        if self._handler:
            cmd, data = self._handler(command)
        sdata = json.dumps(data)
        # logging.info("RESP" + sdata)
        return pcocc_pb2.Response(cmd=cmd, data=sdata)


    def route_command(self, request, context=None):
        resp = None

        cnt = 0
        # Give us some time to start
        # There is a race between the listening server
        # and the start of the relay our solution
        # is then to wait a little to do the __init__
        while self._relay is None:
            cnt = cnt + 1
            time.sleep(1)
            if cnt == 60:
                logging.error("TBON relay was not up after %s seconds", cnt)
                return pcocc_pb2.Command(source=-1,
                                         destination=request.source,
                                         cmd="error",
                                         data=json.dumps(
                                             "VM TBON start timemout"))

        if request.destination == self._vmid:
            # Local Command
            resp = self._process_local(request)
        else:
            resp = self._relay.route(request)

        return resp


#
# TBON Client Code
#


class TreeClient(object):
    """
    An instance of this class is used to
    communicate as client over the TBON
    """
    def __init__(
            self,
            connect_info,
            enable_ssl=True,
            enable_client_auth=True
    ):
        self._vmid = connect_info[0]
        self._host = connect_info[1]
        self._port = connect_info[2]
        self._stub = None
        self._channel = None

        if enable_ssl is False:
            if enable_client_auth:
                raise PcoccError("Client Auth requires SSL support")
            self._channel = grpc.insecure_channel(self._host + ":" + self._port)
        else:
            client_cert = Config().batch.client_cert
            if enable_client_auth:
                credential = grpc.ssl_channel_credentials(
                    root_certificates=client_cert.ca_cert,
                    private_key=client_cert.key,
                    certificate_chain=client_cert.cert
                )
            else:
                credential = grpc.ssl_channel_credentials(
                    root_certificates=client_cert.ca_cert
                )
            self._channel = grpc.secure_channel(
                self._host
                + ":"
                + self._port, credential)

        self._stub = pcocc_pb2_grpc.pcoccNodeStub(self._channel)

    def __del__(self):
        del self._stub
        del self._channel

    def command(self, dest, cmd, data):
        json_dat = json.dumps(data)
        grpc_command = pcocc_pb2.Command(source=-1,
                                         destination=dest,
                                         cmd=cmd,
                                         data=json_dat)
        return self._stub.route_command(grpc_command)

    def exec_stream(self, input_iterator):
        return self._stub.exec_stream(input_iterator)
