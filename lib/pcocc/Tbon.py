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
import agent_pb2
import agent_pb2_grpc
import socket
import threading
import logging
import yaml

from OpenSSL import crypto
from concurrent import futures
from Queue import Queue
from Config import Config
from Error import PcoccError, AgentTransportError, AgentCommandError
from ClusterShell.NodeSet import RangeSet



#
# Helper functions from pyOpenSSL
#

def createKeyPair(key_type, bits):
    """
    Create a public/private key pair.
    Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
               bits - Number of bits to use in the key
    Returns:   The public/private key pair in a PKey object
    """
    pkey = crypto.PKey()
    pkey.generate_key(key_type, bits)
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

def mt_tee(source_iterator, count=2):
    """Multi-threaded duplication of a blocking generator (similar to the tee command)

    Resulting generators can be read concurrently.
    """

    # TODO: should we limit the queue size in case one of the sink
    # generators are not beeing read fast enough ?
    queues = [Queue() for _ in range(count)]

    def queue_gen(q):
        while True:
            ret = q.get()
            if ret is None:
                return
            else:
                yield ret

    iters = [queue_gen(q) for q in queues]

    def tee_th():
        try:
            for d in source_iterator:
                for q in queues:
                    q.put(d)
        except Exception as e:
            #FIXME: Clarify how to properly handle this error
            logging.error("Exception while duplicating request for tee: %s", str(e))

        for q in queues:
            logging.debug("mt_tee: source ended, terminating all sinks")
            q.put(None)

    th = threading.Thread(target=tee_th)
    th.setDaemon(True)
    th.start()

    return iters

def mt_chain(iterators):
    """Multi-threaded gathering of multiple blocking generators into a single one

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
            logging.debug("mt_chain: source stream completed, %d sources remaining", active)
        else:
            logging.debug("mt_chain: got data from a sink: %s", data)
            yield data

    for i in range(0, len(iterators)):
        workers[i].join()

    logging.debug("mt_chain: all srouce streams completed and joined")

class TreeNode(agent_pb2_grpc.pcoccNodeServicer):
    """Services RPC request to a node in the tree.

    When RPCs have to be routed to other tree nodes, it defers work to
    a TreeNodeRelay which establishes connections to adjacent tree
    nodes and knows the correct route.
    """
    def __init__(self,
                 vmid,
                 handler,
                 stream_init_handler,
                 port=0):

        self._relay = None
        self._vmid = int(vmid)
        self._port = port
        self._handler = handler
        self._stream_init_handler = stream_init_handler
        self._server = grpc.server(futures.ThreadPoolExecutor(max_workers=25))
        self._ready = threading.Event()

        agent_pb2_grpc.add_pcoccNodeServicer_to_server(self, self._server)

        server_cert = Config().batch.ca_cert.gen_cert(socket.gethostname())
        credential = grpc.ssl_server_credentials(
            ((server_cert.key, server_cert.cert), ),
            server_cert.ca_cert,
            True
        )
        self._port = self._server.add_secure_port(
            "[::]:{0}".format(port),
            credential
        )
        self._server.start()

        logging.debug("Tree node listening on port %s", self._port)

        Config().batch.write_key('cluster/user',
                                 "hostagent/vms/{0}".format(self._vmid),
                                 "{0}:{1}:{2}".format(
                                     self._vmid,
                                     socket.gethostname(),
                                     self._port))


        # Establish connections to adjacent nodes in the tree for relaying
        # messages
        self._relay = TreeNodeRelay(self._vmid)

        self._ready.set()

    def route_stream(self, request_iterator, context):
        #FIXME: Refactor this
        #First, see from the header message if we are part of the recipients
        init_msg = next(request_iterator)
        stream_local = False

        if self._vmid in RangeSet(init_msg.destinations.encode('ascii', 'ignore')):
            # If we are part of the recipients, use a tee to get a
            # local copy of the stream while forwarding it
            local_iter, forward_iter = mt_tee(request_iterator)

            # Unpack the header message to initialize the stream and
            # find out how to handle the next messages
            req = getattr(agent_pb2, init_msg.args.TypeName())()
            init_msg.args.Unpack(req)
            input_handler, output_handler, ret = self._stream_init_handler(init_msg.name,
                                                                           req, context)

            if isinstance(ret, agent_pb2.GenericError):
                ret_msg = agent_pb2.RouteMessageResult(source=self._vmid,
                                                       error=ret)
                # If the header handling resulted in error, we stop
                # the stream handling on this node
                stream_local = False
            else:
                stream_local = True
                ret_msg = agent_pb2.RouteMessageResult(source=self._vmid)
                ret_msg.result.Pack(ret)

            logging.debug("Tbon: %d returning first reply for stream", self._vmid)
            yield ret_msg

        if stream_local:
            # Build input and output handlers for the following
            # messages based on the callbacks received from handling
            # the header message
            logging.debug("Tbon: %d continuing in local+relay mode", self._vmid)

            def get_output():
                # Get messages from the generator for this stream
                for output_msg in output_handler(context):
                    if isinstance(output_msg, agent_pb2.GenericError):
                        ret_msg = agent_pb2.RouteMessageResult(source=self._vmid,
                                                               error=output_msg)
                    else:
                        ret_msg = agent_pb2.RouteMessageResult(source=self._vmid)
                        ret_msg.result.Pack(output_msg)
                    yield ret_msg

            def send_input():
                # Push everything from the local iter to the handler
                # for this stream
                for input_msg in local_iter:
                    req = getattr(agent_pb2, input_msg.args.TypeName())()
                    input_msg.args.Unpack(req)
                    input_handler(input_msg.name, req, context)

            #Create a dedicated thread to block and push on the local iterator
            thread = threading.Thread(target=send_input)
            thread.start()

            # Forward the header message + following messages to the
            # next hops and yield everything they send us + what we
            # produce locally
            def new_iterin():
                yield init_msg
                for i in forward_iter:
                    yield i

            for e in mt_chain([
                    get_output(),
                    self._relay.route_stream(new_iterin())]):
                yield e
        else:
            # We are not part of the recipients so just forward the
            # whole stream to the next hops and yield everything they
            # send us
            def new_iterin():
                yield init_msg
                for i in request_iterator:
                    yield i

            logging.debug("Tbon: %d continuing stream in relay mode", self._vmid)

            for e in self._relay.route_stream(new_iterin()):
                logging.debug("Node %d ouputing message %s from children rpcs", self._vmid, e)
                yield e

            logging.debug("Tbon: %d finished with stream", self._vmid)


    def _process_local(self, command, context):
        req = getattr(agent_pb2, command.args.TypeName())()
        command.args.Unpack(req)

        result = self._handler(command.name, req, context)

        if isinstance(result, agent_pb2.GenericError):
            msg = agent_pb2.RouteMessageResult(source=self._vmid,
                                               error=result)
        else:
            msg = agent_pb2.RouteMessageResult(source=self._vmid)
            msg.result.Pack(result)

        return msg

    def route_command(self, request, context):
        if not self._ready.wait(60):
            logging.error("Timeout while establishing tree relay")
            return agent_pb2.RouteMessageResult(error = agent_pb2.GenericError(
                kind=agent_pb2.GenericError.TimeoutError,
                description="Timeout while establishing tree relay"))

        if request.destination == self._vmid:
            resp = self._process_local(request, context)
        else:
            resp = self._relay.route_cmd(request,  context)

        return resp


class TreeNodeRelay(object):
    """Manages connections between adjacent nodes in the tree.

    Used by TreeNode to route messages.
    """
    def __init__(self, vmid=0, tree_width=16):

        self._vmid = vmid
        self._tree_width = tree_width
        self._tree_size = Config().batch.vm_count()

        self._parent_id = -1
        self._children_ids = []

        self._parent_chan = None
        self._children_chans = {}

        self._parent_stub = None
        self._children_stubs =  {}

        self._routes = {}
        self._endpoints = {}
        self._endpoints_lock = threading.Lock()

        self._gen_children_list()
        self._connect()
        logging.debug("Rank %d: routes: %s",self._vmid, str(self._routes))

    def route_cmd(self, command, context):
        stub = None

        try:
            route = self._routes[command.destination]
            stub = self._children_stubs[route]
            logging.debug("Routing for node %d through child %d", command.destination,
                          route)

        except KeyError:
            logging.debug("Routing for node %d through parent", command.destination)
            stub = self._parent_stub


        if stub is None:
            logging.info("Bad stub for %d from %d", command.destination, self._vmid)
            return agent_pb2.RouteMessageResult(source=command.destination,
                                                error=agent_pb2.GenericError(
                                                    kind=agent_pb2.GenericError.GenericError,
                                                    description='No route for vm{}'.format(
                                                        command.destination)))

        try:
            # Route the command by executing a RPC on the next
            # hop. Cancel that RPC if the Route RPC from our client is
            # cancelled or timeouts
            future = stub.route_command.future(command, context.time_remaining())
            context.add_callback(future.cancel)
            return future.result()
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
                # Timeouts should be coherent along a route so the parent should timeout
                # concurrently but we still return something just in case
                return agent_pb2.RouteMessageResult(source=command.destination,
                                                    error=agent_pb2.GenericError(
                    kind=agent_pb2.GenericError.Timeout,
                    description="Agent did not answer before time limit"))
            else:
                return agent_pb2.RouteMessageResult(source=command.destination,
                                                    error=agent_pb2.GenericError(
                    kind=agent_pb2.GenericError.GenericError,
                    description=str(e)))
        except grpc.FutureCancelledError as e:
            # Again should not be necessary as the parent should be
            # cancelled too but just in case
            return agent_pb2.RouteMessageResult(source=command.destination,
                                                error=agent_pb2.GenericError(
                    kind=agent_pb2.GenericError.Cancelled,
                    description="Route request cancelled"))

    def route_stream(self, input_iterator):
        children_dups = mt_tee(input_iterator, len(self._children_ids))
        children_rpcs = []

        for stub, dup in zip(self._children_stubs.itervalues(), children_dups):
            logging.debug("Relay %d intiating child stream rpc", self._vmid)
            children_rpcs.append(stub.route_stream(dup))

        for e in mt_chain(children_rpcs):
            logging.debug("Relay %d relaying msg %s from children rpc", self._vmid, e)
            yield e

    def _gen_children_list(self):
        self._recurse_children_list(self._vmid, -1)

    def _recurse_children_list(self, current, route):
        for i in range (self._tree_width):
            child = current * self._tree_width + i + 1
            if child < self._tree_size:
                if route == -1:
                    newroute = child
                else:
                    newroute = route

                self._routes[child] = newroute
                self._recurse_children_list(child, newroute)

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

        parent_id = (me + self._tree_width - 1) // self._tree_width - 1

        children_ids = []
        for i in range(self._tree_width):
            child = me  * self._tree_width  + i + 1
            if child < self._tree_size:
                children_ids.append(child)

        self._parent_id = parent_id
        self._children_ids = children_ids

        client_cert = Config().batch.ca_cert
        credential = grpc.ssl_channel_credentials(
            root_certificates=client_cert.ca_cert,
            private_key=client_cert.key,
            certificate_chain=client_cert.cert
        )

        if parent_id >= 0:
            pinfo = self._get_endpoint(parent_id)
            self._parent_chan = grpc.secure_channel(pinfo[1] + ":" + pinfo[2], credential)
            self._parent_stub = agent_pb2_grpc.pcoccNodeStub(self._parent_chan)

        for child in children_ids:
            pinfo = self._get_endpoint(child)
            self._children_chans[child] = grpc.secure_channel(pinfo[1] + ":" + pinfo[2], credential)
            self._children_stubs[child] = agent_pb2_grpc.pcoccNodeStub(self._children_chans[child])

class TreeClient(object):
    """
    An instance of this class is used to
    communicate as client over the TBON
    """
    def __init__(self, connect_info):

        self._vmid = connect_info[0]
        self._host = connect_info[1]
        self._port = connect_info[2]
        self._stub = None
        self._channel = None

        client_cert = Config().batch.client_cert
        credential = grpc.ssl_channel_credentials(
            root_certificates=client_cert.ca_cert,
            private_key=client_cert.key,
            certificate_chain=client_cert.cert
        )
        self._channel = grpc.secure_channel(
            self._host + ":" + self._port, credential)

        self._stub = agent_pb2_grpc.pcoccNodeStub(self._channel)

    @staticmethod
    def _handle_route_result(cmd, res):
        if res.HasField("error"):
            if res.error.kind == agent_pb2.GenericError.AgentError:
                logging.info("Agent returned error: %s", res.error.description)
                raise AgentCommandError(cmd,
                                        res.error.description,
                                        res.error.details)
            else:
                raise AgentTransportError(res.error.kind,
                                          res.error.description)

        ret = getattr(agent_pb2, res.result.TypeName())()
        res.result.Unpack(ret)

        return ret


    @staticmethod
    def _handle_grpc_error(e, source):
        if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
            ex = agent_pb2.RouteMessageResult(source=source,
                                              error=agent_pb2.GenericError(
                    kind=agent_pb2.GenericError.Timeout,
                    description="Timeout while waiting for agent to answer"))
        elif e.code() == grpc.StatusCode.CANCELLED:
            ex = agent_pb2.RouteMessageResult(source=source,
                                              error=agent_pb2.GenericError(
                    kind=agent_pb2.GenericError.Cancelled,
                    description="RPC was cancelled"))
        else:
            logging.warning("RPC request failed with: %s", e.details())
            ex = agent_pb2.RouteMessageResult(source=source,
                                              error=agent_pb2.GenericError(
                    kind=agent_pb2.GenericError.GenericError,
                    description="Transport error while "
                    "relaying command: {}".format(e.details())))

        return ex
    def command(self, dest, cmd, data, timeout):
        logging.info("sending %s to %d", cmd, dest)
        try:
            grpc_message = agent_pb2.RouteMessage(destination=dest, name=cmd)
            grpc_message.args.Pack(data)

        except Exception as e:
            return self._handle_route_result(cmd,
                                agent_pb2.RouteMessageResult(
                                    source=dest,
                                    error=agent_pb2.GenericError(
                                        kind=agent_pb2.GenericError.PayloadError,
                                        description="Unable to create message "
                                        "with payload: {}".format(e))))

        try:
            res = self._stub.route_command(grpc_message, timeout=timeout)
        except grpc.RpcError as e:
            res = self._handle_grpc_error(e, dest)
        return self._handle_route_result(cmd, res)

    def route_stream(self, rng, init_cmd, stream_cmd, msg_iterator, cancel_cb=None):
        def route_iterator():
            cmd = init_cmd
            for msg in msg_iterator:
                grpc_message = agent_pb2.McastMessage(destinations=str(rng),
                                                      name=cmd)
                grpc_message.args.Pack(msg)
                yield grpc_message
                cmd = stream_cmd
        try:
            res =  self._stub.route_stream(route_iterator())
            if cancel_cb:
                res.add_callback(cancel_cb)

            def result_unpacker():
                try:
                    for r in res:
                        try:
                            logging.debug("Stream client: unpacking a result %s", r)
                            yield r.source, self._handle_route_result(
                                init_cmd, r)
                        except PcoccError as e:
                            yield r.source, e
                except grpc.RpcError as e:
                    logging.error("Stream client interrupted due to GRPC error")
                    yield -1, self._handle_route_result(
                        init_cmd, self._handle_grpc_error(e, -1))

                logging.debug("Stream client: No more results to unpack")

            return result_unpacker(), res
        except Exception as e:
            #FIXME: we should probably generate a more informative error
            return [self._handle_route_result(
                    init_cmd,
                    agent_pb2.RouteMessageResult(
                        source=-1,
                        error=agent_pb2.GenericError(
                            kind=agent_pb2.GenericError.GenericError,
                            description="Unable to establish stream: {}".format(e))))]
