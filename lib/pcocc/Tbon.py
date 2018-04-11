import grpc
import time
from concurrent import futures
from Queue import Queue
import pcocc_pb2
import pcocc_pb2_grpc
import os
import tempfile
import socket
import json
import threading
import logging
from Config import Config
from Error import PcoccError
import subprocess

#
# Helper functions
#


def secure_tempfile():
    """
    Helper function creating a temporary
    file with rights solely for current user
    """
    temp = tempfile.NamedTemporaryFile(delete=False)
    temp.close()
    os.chmod(temp.name, int('600', 8))
    return temp.name


def load_file_content(path):
    """
    Helper function to read a file content
    """
    try:
        with open(path, "r") as f:
            return f.read()
    except IOError:
        raise PcoccError("An error was encountered when"
                         "reading %s" % path)


class UserRootCert(object):
    """
    This class is used to create the ROOT
    certificate used by a pcocc instance
    """
    def __init__(
            self,
            rkey=None,
            rcrt=None,
            key_size=2048
    ):

        # Initial DAT
        self.root_key_data = rkey
        self.root_cert_data = rcrt
        self.key_size = key_size

    def gen_user_root_cert(self):
        root_key = secure_tempfile()
        root_crt = secure_tempfile()
        host = socket.gethostname()
        try:
            with open(os.devnull, 'w') as devnull:
                # Generate Key
                command = ["openssl", "genrsa", "-out",
                           root_key, str(self.key_size)]
                subprocess.call(command,
                                stdout=devnull,
                                stderr=devnull)
                # Generate Root Cert
                command = ["openssl", "req", "-new", "-x509",
                           "-days", "1826", "-key", root_key,
                           "-out", root_crt,
                           "-subj",
                           "/C=FR/ST=Paris/L=Paris/O=Etcd/CN=" + host]
                subprocess.call(command,
                                stdout=devnull,
                                stderr=devnull)
        except OSError:
            raise PcoccError("An error was encountered when"
                             "generating root certificate")
        logging.debug("Generated root key in %s" % (root_key))
        logging.debug("Generated root cert in %s for %s" % (root_crt, host))
        self.root_key_data = load_file_content(root_key)
        if self.root_key_data == "":
            raise PcoccError("Generated SSL Key appeared empty please check parameters")
        self.root_cert_data = load_file_content(root_crt)
        if self.root_cert_data == "":
            raise PcoccError("Generated SSL certificate appeared empty"\
                             "please check parameters (you may increase key size)")
        os.unlink(root_key)
        os.unlink(root_crt)

    @property
    def key(self):
        if self.root_key_data is None:
            self.gen_user_root_cert()
        return self.root_key_data.encode("ascii")

    @property
    def crt(self):
        if self.root_cert_data is None:
            self.gen_user_root_cert()
        return self.root_cert_data.encode("ascii")


class ClientCert(object):
    """
    This class is used to store a client
    keychain to be able to connect to gRPC
    """
    def __init__(
            self,
            ckey=None,
            ccert=None,
            key_size=2048
    ):
        self.ckey = ckey
        self.ccert = ccert
        self.size = key_size

    def gen_client_cert(self, rkey, rcert):
        dat = Cert.gen_user_key_cert(rkey, rcert, key_size=self.size)
        self.ckey = dat[0].encode("ascii")
        self.ccert = dat[1].encode("ascii")

    @property
    def key(self):
        if self.ckey is None:
            raise PcoccError("Client cert was not generated")
        return self.ckey.encode("ascii")

    @property
    def crt(self):
        if self.ccert is None:
            raise PcoccError("Client cert was not generated")
        return self.ccert.encode("ascii")


class Cert(object):
    """
    This class is responsible for generating
    all the certificates needed by gRPC
    it is also providing storage paths
    """
    @staticmethod
    def root_key_path(rkey=None):
        if Config().batch is None:
            if rkey is None:
                raise PcoccError("Could not resolve root key")

        key_data = None
        if rkey is None:
            key_data = Config().batch.root_cert.root_key_data
        else:
            key_data = rkey

        rkp = secure_tempfile()
        f = open(rkp, "w")
        f.write(key_data)
        f.close()
        return rkp

    @staticmethod
    def root_cert_path(rcert=None):
        if Config().batch is None:
            if rcert is None:
                raise PcoccError("Could not resolve root cert")

        crt_data = None
        if rcert is None:
            crt_data = Config().batch.root_cert.root_cert_data
        else:
            crt_data = rcert

        rcp = secure_tempfile()
        f = open(rcp, "w")
        f.write(crt_data)
        f.close()
        return rcp

    @staticmethod
    def gen_user_key_cert(rkey=None, rcert=None, key_size=2048):
        host = socket.gethostname()
        # Create TMP key
        key_file = secure_tempfile()
        # Create TMP cert
        crt_file = secure_tempfile()
        # Create TMP cert req
        crt_req_file = secure_tempfile()
        # Generate Paths
        root_key = Cert.root_key_path(rkey)
        root_crt = Cert.root_cert_path(rcert)

        try:
            with open(os.devnull, 'w') as devnull:
                # Generate Key
                command = ["openssl", "genrsa", "-out",
                           key_file, str(key_size)]
                subprocess.call(command,
                                stdout=devnull,
                                stderr=devnull)
                # Generate Root Cert
                command = ["openssl", "req", "-new", "-x509",
                           "-days", "1826", "-key", key_file,
                           "-out", crt_file,
                           "-subj",
                           "/C=FR/ST=Paris/L=Paris/O=Pcocc/CN=" + host]
                subprocess.call(command,
                                stdout=devnull,
                                stderr=devnull)
                command = ["openssl", "x509", "-x509toreq", "-in",
                           crt_file, "-signkey", key_file,
                           "-out", crt_req_file]
                subprocess.call(command,
                        stdout=devnull,
                        stderr=devnull)
                command = ["openssl", "x509", "-req", "-days", "730", "-in",
                           crt_req_file, "-CA", root_crt,
                           "-CAkey", root_key, "-CAcreateserial", "-out", crt_file]
                subprocess.call(command,
                        stdout=devnull,
                        stderr=devnull)
        except OSError:
            raise PcoccError("An error was encountered when"
                             "generating root certificate")

        # We should be all set with our certs now
        # time to load them to memory and delete them
        key = load_file_content(key_file)
        if key is None:
            raise PcoccError("Error retrieving KEY file")
        crt = load_file_content(crt_file)
        if crt is None:
            raise PcoccError("Error retrieving CRT file")
        # Delete TMP files
        os.unlink(key_file)
        os.unlink(crt_file)
        os.unlink(crt_req_file)
        os.unlink(root_key)
        os.unlink(root_crt)
        # Info
        logging.debug("Generated cert for %s" % host)
        # Return Certs
        return [key, crt, Cert.load_root_cert(rcert)]

    @staticmethod
    def load_root_cert(rcert=None):
        if Config().batch is None:
            if rcert is None:
                raise PcoccError("Could not load Root Cert")
        if rcert is None:
            return Config().batch.root_cert.root_cert_data.encode("ascii")
        else:
            return rcert.encode("ascii")

    @staticmethod
    def load_client_chain():
        if Config().batch is None:
            raise PcoccError("Could not load client keychain")
        cc = Config().batch.client_cert
        return [cc.key, cc.crt, Cert.load_root_cert()]

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
            keys = Cert.load_client_chain()
            if self.enable_client_auth:
                credential = grpc.ssl_channel_credentials(
                    root_certificates=keys[2],
                    private_key=keys[0],
                    certificate_chain=keys[1]
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
            crt = Cert.gen_user_key_cert()
            credential = grpc.ssl_server_credentials(
                ((crt[0], crt[1]), ),
                crt[2],
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
            keys = Cert.load_client_chain()
            if enable_client_auth:
                credential = grpc.ssl_channel_credentials(
                    root_certificates=keys[2],
                    private_key=keys[0],
                    certificate_chain=keys[1]
                )
            else:
                credential = grpc.ssl_channel_credentials(
                    root_certificates=keys[2]
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
