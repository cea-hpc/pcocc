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

    @property
    def cert_chain(self):
        return self.key, self.cert, self.ca_cert

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
            if not q.empty():
                yield q.get()
            elif run[0] == 0:
                break
        return

    ret1 = queue_gen(q1, is_running)
    ret2 = queue_gen(q2, is_running)

    def tee_th(run):
        try:
            for d in source_iterator:
                q1.put(d)
                q2.put(d)
            # I'm done
            run[0] = 0
        except:
            run[0] = 0

    # Start the TEE th
    th = threading.Thread(target=tee_th, args=(is_running, ))
    th.setDaemon(True)
    th.start()

    return ret1, ret2


def mt_chain(*iterators):
    """
    Chain two generators in a MT
    fashion (as 'chain')
    """
    active = [None] * len(iterators)
    for i in range(0, len(iterators)):
        active[i] = 1

    queue = Queue()

    def iterator_progress(it, ident):
        while True:
            try:
                n = next(it)
                queue.put(n)
            except:
                active[ident] = 0
                break

    workers = [None] * len(iterators)

    for i in range(0, len(iterators)):
        workers[i] = threading.Thread(
            target=iterator_progress,
            args=(iterators[i], i, ))
        workers[i].setDaemon(True)
        workers[i].start()

    while True:
        all_inactive = 1

        for k in range(0, len(iterators)):
            if active[k]:
                all_inactive = 0
                break
        if all_inactive and queue.empty():
            return

        try:
            data = queue.get(False)
            yield data
        except:
            pass
#
# TBON TreeNode Definition
#


class DiscoverMode(object):
    NotSet, Etcd = range(2)


class TreeNodeClient(object):
    """
    TreeNode is a node in the TBON
    tree as a consequence it is connected
    in a BTREE fashion
    """
    def __init__(self,
                 vmid=0,
                 discover=DiscoverMode.NotSet,
                 enable_ssl=True,
                 enable_client_auth=False):
        # List of VM endpoints
        self.endpoints = []
        self.vmid = vmid
        self.enable_ssl = enable_ssl
        self.enable_client_auth = enable_client_auth

        # These are the Client channels
        # to be used in the tree
        self.pc = None
        self.lc = None
        self.rc = None

        self.ps = None
        self.ls = None
        self.rs = None

        self.pid = -1
        self.lid = -1
        self.rid = -1

        if not self.enable_ssl:
            if self.enable_client_auth:
                raise PcoccError("Client auth is only avalaible with SSL")


        self.child_list = []
        self.child_routes = []
        self.route_lock = threading.Lock()
        # Start the Server
        self.discover_mode = discover
        self.discover()
        self.gen_child_list()
        self.connect()

    def __del__(self):
        del self.ps
        del self.ls
        del self.rs
        del self.pc
        del self.rc
        del self.lc

    class Target(object):
        NotSet, Parent, Left, Right = range(4)

    #
    # This is the Command Interface
    #
    def send_cmd(self, target, command):
        stub = None
        if target == self.Target.Left:
            stub = self.ls
        elif target == self.Target.Right:
            stub = self.rs
        elif target == self.Target.Parent:
            stub = self.ps
        if stub is None:
            raise SystemExit("Error could not Route Command")
        return stub.route_command(command)

    def send_exec(self, request_stream, req_array=None):
        if (self.ls is None) and (self.rs is None):
            return
        if self.ls and self.rs:
            left_dup, right_dup = mt_tee(request_stream)
            lreq = self.ls.exec_stream(left_dup)
            rreq = self.rs.exec_stream(right_dup)

            if req_array:
                req_array.push(lreq)
                req_array.push(rreq)

            for e in mt_chain(lreq, rreq):
                yield e

            lreq.cancel()
            rreq.cancel()
        else:
            target = self.rs
            if self.ls:
                target = self.ls
            req = target.exec_stream(request_stream)
            if req_array:
                req_array.push(req)
            for e in req:
                yield e
            req.cancel()

    #
    # This is the Discover Interface Definition
    #

    def split_vm_list(self, vm_list):
        endpoints = []
        for i in range(len(vm_list)):
            ent = vm_list[i].replace("\n", "").split(":")
            if len(ent) != 3:
                continue
            endpoints.insert(int(ent[0]), ent)
        return endpoints

    def discover_etcd(self):
        count = Config().batch.vm_count()
        vm_list = []
        for vm in range(0, count):
            ent = Config().batch.read_key(
                "cluster/user",
                "hostagent/vms/{0}".format(vm),
                blocking=True
            )
            vm_list.append(ent)
        return self.split_vm_list(vm_list)

    def discover(self):
        ret = []
        if self.discover_mode == DiscoverMode.Etcd:
            ret = self.discover_etcd()
        if ret == []:
            raise PcoccError("ERROR : Failed to discover tree")
        self.endpoints = ret

    def __gen_child_list(self, current, bound, choice):
        # Recursive scan on childs
        left = (current + 1) * 2 - 1
        right = (current + 1) * 2
        route = choice
        if left < bound:
            if choice == self.Target.NotSet:
                route = self.Target.Left
            self.child_list.append(left)
            self.child_routes.append(route)
            self.__gen_child_list(left, bound, route)
        if right < bound:
            if choice == self.Target.NotSet:
                route = self.Target.Right
            self.child_list.append(right)
            self.child_routes.append(route)
            self.__gen_child_list(right, bound, route)

    def gen_child_list(self):
        me = self.vmid
        count = len(self.endpoints)
        self.__gen_child_list(me, count, self.Target.NotSet)

    def connect(self):
        count = len(self.endpoints)
        if count == 0:
            return
        me = self.vmid
        parent = (me + 1)//2 - 1
        leftc = (me + 1)*2 - 1
        rightc = (me + 1) * 2
        if me == 0:
            parent = -1
        if count <= leftc:
            leftc = -1
        if count <= rightc:
            rightc = -1

        self.pid = parent
        self.lid = leftc
        self.rid = rightc

        if self.enable_ssl is False:
            if 0 <= parent:
                pinfo = self.endpoints[parent]
                self.pc = grpc.insecure_channel(pinfo[1] + ":" + pinfo[2])
            if 0 <= leftc:
                pinfo = self.endpoints[leftc]
                self.lc = grpc.insecure_channel(pinfo[1] + ":" + pinfo[2])
            if 0 <= rightc:
                pinfo = self.endpoints[rightc]
                self.rc = grpc.insecure_channel(pinfo[1] + ":" + pinfo[2])
        else:
            client_cert = Config().batch.ca_cert
            if self.enable_client_auth:
                credential = grpc.ssl_channel_credentials(
                    root_certificates=client_cert.ca_cert,
                    private_key=client_cert.key,
                    certificate_chain=client_cert.cert
                )
            else:
                credential = grpc.ssl_channel_credentials(
                    root_certificates=keys[2])
            if 0 <= parent:
                pinfo = self.endpoints[parent]
                self.pc = grpc.secure_channel(pinfo[1]
                                              + ":" + pinfo[2], credential)
            if 0 <= leftc:
                pinfo = self.endpoints[leftc]
                self.lc = grpc.secure_channel(pinfo[1]
                                              + ":" + pinfo[2], credential)
            if 0 <= rightc:
                pinfo = self.endpoints[rightc]
                self.rc = grpc.secure_channel(pinfo[1]
                                              + ":" + pinfo[2], credential)
        # Start Stubs
        if 0 <= parent:
            self.ps = pcocc_pb2_grpc.pcoccNodeStub(self.pc)
        if 0 <= leftc:
            self.ls = pcocc_pb2_grpc.pcoccNodeStub(self.lc)
        if 0 <= rightc:
            self.rs = pcocc_pb2_grpc.pcoccNodeStub(self.rc)

    def route(self, command):
        try:
            idx = self.child_list.index(command.destination)
            route = self.child_routes[idx]
            if route == self.Target.Left:
                ret = self.send_cmd(self.Target.Left, command)
            elif route == self.Target.Right:
                ret = self.send_cmd(self.Target.Right, command)
            else:
                logging.error("No such route type " + str(route))
        except:
            ret = self.send_cmd(self.Target.Parent, command)
        return ret

    def exec_stream(self, input_iterator, req_array=None):
        try:
            children_it = self.send_exec(input_iterator, req_array)
            for e in children_it:
                yield e
        except:
            # We failed
            return


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
                 discover=DiscoverMode.Etcd,
                 enable_ssl=True,
                 client_ssl_auth=True,
                 exec_input_handler=None,
                 exec_output_handler=None,
                 exec_input_eof_notifier=None):
        self.relay = None
        self.vmid = int(vmid)
        self.port = port
        self.handler = handler
        self.exec_output_handler = exec_output_handler
        self.exec_input_handler = exec_input_handler
        self.exec_input_eof_notifier = exec_input_eof_notifier
        self.discover = discover
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=25))
        pcocc_pb2_grpc.add_pcoccNodeServicer_to_server(self, self.server)
        if enable_ssl is False:
            self.port = self.server.add_insecure_port("[::]:{0}".format(port))
        else:
            server_cert = Config().batch.ca_cert.gen_cert(socket.gethostname())
            credential = grpc.ssl_server_credentials(
                ((server_cert.key, server_cert.cert), ),
                server_cert.ca_cert,
                client_ssl_auth
            )
            self.port = self.server.add_secure_port(
                "[::]:{0}".format(port),
                credential
            )
        logging.debug("CommandServer Now Listening on %s:%s",
                      socket.gethostname(),
                      self.port)
        self.server.start()
        self.register()
        # Server is ON now start the relay
        self.relay = TreeNodeClient(self.vmid,
                                    self.discover,
                                    enable_ssl,
                                    client_ssl_auth)

    #
    # This is the register Interface definition
    # Where servers announce themselves
    #


    def register_etcd(self):
        logging.debug("Registering hostagent/vms/%s", self.vmid)
        Config().batch.write_key('cluster/user',
                                 "hostagent/vms/{0}".format(self.vmid),
                                 "{0}:{1}:{2}".format(
                                     self.vmid,
                                     socket.gethostname(),
                                     self.port
                                 )
                                 )

    def register(self):
        if self.discover == DiscoverMode.Etcd:
            self.register_etcd()

    #
    # This is the command interface
    #

    def process_local(self, command):
        # print("SRC:" + str(command.source))
        # print("DEST:" + str(command.destination))
        # logging.info("PL CMD:" + command.cmd)
        # print("DATA:" + command.data)
        # resp = "RET : " + command.data
        if self.handler:
            cmd, data = self.handler(command)
        sdata = json.dumps(data)
        # logging.info("RESP" + sdata)
        return pcocc_pb2.Response(cmd=cmd, data=sdata)

    # This is Called for all incoming commands

    def route_command(self, request, context=None):
        resp = None

        cnt = 0
        # Give us some time to start
        # There is a race between the listening server
        # and the start of the relay our solution
        # is then to wait a little to do the __init__
        while self.relay is None:
            cnt = cnt + 1
            time.sleep(1)
            if cnt == 60:
                logging.error("TBON relay was not up after %s seconds", cnt)
                return pcocc_pb2.Command(source=-1,
                                         destination=request.source,
                                         cmd="error",
                                         data=json.dumps(
                                             "VM TBON start timemout"))

        if request.destination == self.vmid:
            # Local Command
            resp = self.process_local(request)
        else:
            resp = self.relay.route(request)
        return resp

    def command(self, dest, cmd, data):
        json_dat = json.dumps(data)
        docommand = pcocc_pb2.Command(source=self.vmid,
                                      destination=dest,
                                      cmd=cmd,
                                      data=json_dat)
        return self.route_command(docommand)

    def exec_stream(self, request_iterator, context):
        local_iter, forward_iter = mt_tee(request_iterator)

        next_req_array = []

        context.add_callback(context.cancel)

        def send_output():
            if self.exec_output_handler:
                for output in self.exec_output_handler(context.is_active):
                    yield output

        def send_input():
            for inpu in local_iter:
                if inpu.eof is True:
                    break
                if self.exec_input_handler:
                    self.exec_input_handler(inpu)
            context.cancel()

        thread = threading.Thread(target=send_input)
        thread.start()

        for e in mt_chain(
                send_output(),
                self.relay.exec_stream(
                    forward_iter,
                    next_req_array)):
            yield e

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
        self.vmid = connect_info[0]
        self.host = connect_info[1]
        self.port = connect_info[2]
        self.stub = None
        self.channel = None

        if enable_ssl is False:
            if enable_client_auth:
                raise PcoccError("Client Auth requires SSL support")
            self.channel = grpc.insecure_channel(self.host + ":" + self.port)
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
            self.channel = grpc.secure_channel(
                self.host
                + ":"
                + self.port, credential)
        self.stub = pcocc_pb2_grpc.pcoccNodeStub(self.channel)

    def __del__(self):
        del self.stub
        del self.channel

    def command(self, dest, cmd, data):
        json_dat = json.dumps(data)
        grpc_command = pcocc_pb2.Command(source=-1,
                                         destination=dest,
                                         cmd=cmd,
                                         data=json_dat)
        return self.stub.route_command(grpc_command)

    def exec_stream(self, input_iterator):
        return self.stub.exec_stream(input_iterator)
