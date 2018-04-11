import pytest
import os
import subprocess
from mock import patch

from conftest import myInputOutput

from pcocc.Tbon import UserRootCert, ClientCert, Cert, mt_tee, mt_chain
from pcocc.Tbon import TreeNodeClient, DiscoverMode, TreeNode, TreeClient
from pcocc.Error import PcoccError
import pcocc.pcocc_pb2


try:
    with open(os.devnull, 'w') as devnull:
        subprocess.call(["openssl", "version"],
                        stdout=devnull,
                        stderr=devnull)
except OSError:
    pytest.skip("This test module needs openssl in the environment",
                allow_module_level=True)


def test_root_cert():
        # Empty
    root = UserRootCert()

    # Should trigger gen
    key = root.key
    cert = root.crt
    root2 = UserRootCert(key, cert)

    assert key == root2.key
    assert cert == root2.crt

    # Gen with size
    root = UserRootCert(key_size=512)

    # Should trigger gen
    cert = root.crt
    key = root.key


rkey = """-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEA/rZS4LrkZ695FguYqrwV1GulzdjfrC186cRLrSyB/sKD2v5l
tyL8kHPo/1KTshVM2/+ffX0ilmP6gpa/fnoEZ2/3RMoBEmWhUbz8fxiHs9dI2jlN
eurYcAUFshJjrHvmM7PefIZ9XIm5F7OwGyzCSfmGu6On7RBbAmRhI4E+mXlPxECr
/TNwKHBP7k8Beq4wLsDsgRhsX3FLj/il/Mj+S/G3En7JJKydbMLbFCyK4RHq+Mh3
zpbKUnHchEDiNkI4IHZfaZvy0KPIpvSrBlbw4eQgaYFq3eIQLuqHqbcuDxkQGrcv
JTpXYj3Z9PAKIfaExtB/Jct1XhkGj9xU7TAO9wIDAQABAoIBAQDIxljf0hG2dUfC
C9QESQwAC/Z/IwN0icqbzeJFF/9EHHmpBryQtiBVkThJAgNv7YBPLdi/JwM7foV5
qHA7ttx/2G8VpxFfOgMGFi0F1gUpynofoemkCTggXKUXr40n6eYUPSUUDUMFzX27
5CTd1tMzUmBUyfTVVf4XDZ7QSNFaUQXwgCzCIT6NE+nGEeNWseTSsedp4/rjfCBj
hCn3YvJrjrgM2wMs5kXO7Prn5vexcC7lzJGJMS5mYS2ADGbFwthRUTOiDl8q4D3A
+7YmokEO8VFyWhvbU2uI7i9IfcxT0KDT3Pqdje7t4njAvzG5z/RhmcEuQgiGY3+X
22uJ34UJAoGBAP98sUnTNWMRMQyuvoPz6Li2AAGK5rdJzNS69ARGhkdzBDDz2vhf
SGrlyd6GaT5jqjJHSoEFDP7wcA1ClvlyjKdKEfw/QwETXzfHjXoVLlv8pDYV6PnM
E7IgzkVuhSEvV79qdoiRA+qG3k551b9mCALHC1iU+p/nnl9qVTHhhRtzAoGBAP85
O6NO+c+NB2Y0ewA936tQYcKmLLA+32vY7OCSGGJ7Lrs1+vgS+8oyUUz36/xuOM4t
AysODOvFCpYluD8hIjTYqgc+QkgGSUQALUyr9PX/vsk4UTbUWcX6CqzfMJ54gYdg
MjpEbNXEb9SmGjwt90nCr+Hlb6Ljmw64ph3/1WVtAoGBAKpWyaFuF2cwvCI3k8BI
a/5TIhflM0Q7CT1AVJdRKhATKFU3EOSOKqtS/8/EkADP1FbnX048PtjvF9ZPcndo
H00ePnWO/C6IavC2tKYT3y/ndti0rPt3TB50bvKt6Eci2H9ADT2qahEA0NFDu/Z7
oZWwfekWky7v75CwRZMXSHbvAoGBAPbC20p2HUnyzOigbRw6tnroaNzN1f9Birq3
La+jETiGaRRQiKo5kIBaTgjg26Vg3ENbeeiy2QNLq4SoS4+d9Xiq0xnVtDf2+/dn
RGURDPKbplbewIcGoRWtP40M7fEKChJdi7KSXbgBCS7MuijdOG50caEzN9CBx3Vg
ShxPMn+xAoGBAKOsRlRNnqwc/ivHEEJKualz4bJ/i1Pc8GonsEobei7Al5SufO3N
cXyKztVAeCiFix7FiJAIri4anAHfn8cWYUJnwXWgJH8yw2EiqihZT1VcWEpHsDId
twX5IjC42BE2hXho264mA2CUHvHP2Oj1QYgXPEO26jpupPg4MtQG9i7b
-----END RSA PRIVATE KEY-----"""

rcert = """-----BEGIN CERTIFICATE-----
MIIDbTCCAlWgAwIBAgIJANAMcJOx6q53MA0GCSqGSIb3DQEBCwUAME0xCzAJBgNV
BAYTAkZSMQ4wDAYDVQQIDAVQYXJpczEOMAwGA1UEBwwFUGFyaXMxDTALBgNVBAoM
BEV0Y2QxDzANBgNVBAMMBmhlbGlvczAeFw0xODAzMjExNDQ5MThaFw0yMzAzMjEx
NDQ5MThaME0xCzAJBgNVBAYTAkZSMQ4wDAYDVQQIDAVQYXJpczEOMAwGA1UEBwwF
UGFyaXMxDTALBgNVBAoMBEV0Y2QxDzANBgNVBAMMBmhlbGlvczCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAP62UuC65GeveRYLmKq8FdRrpc3Y36wtfOnE
S60sgf7Cg9r+Zbci/JBz6P9Sk7IVTNv/n319IpZj+oKWv356BGdv90TKARJloVG8
/H8Yh7PXSNo5TXrq2HAFBbISY6x75jOz3nyGfVyJuRezsBsswkn5hrujp+0QWwJk
YSOBPpl5T8RAq/0zcChwT+5PAXquMC7A7IEYbF9xS4/4pfzI/kvxtxJ+ySSsnWzC
2xQsiuER6vjId86WylJx3IRA4jZCOCB2X2mb8tCjyKb0qwZW8OHkIGmBat3iEC7q
h6m3Lg8ZEBq3LyU6V2I92fTwCiH2hMbQfyXLdV4ZBo/cVO0wDvcCAwEAAaNQME4w
HQYDVR0OBBYEFEjF8bJLm6swm6/PqGulvQhJmwO0MB8GA1UdIwQYMBaAFEjF8bJL
m6swm6/PqGulvQhJmwO0MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
AF0yciEo8kNMhhdscTPsdhey2SdhDsA4QSRmZqE5Ye5yGFIPb3TdFwEsrpxXrMiU
N/sfN09RleBOV/bHiA7y8UZMZQKsqKlxyo792vou4aWz8RfeoqrzPB2v6TmtBedj
CSQH1He+jOERvPBkcfmD7suC4Pu8ONzvmWyi8U74hYz7RdxolpnhNK/XR6yIjf2t
RVWQXYgDEsYAO5Mn3XvorKLyCyx/iqwvvk0UWRgdNfn2wFh/N1G1PFYkPIlNuCMG
RXGHX6OyDudGDMnqw0EqBrAZ1kjvd4ii5CSz9oS8zbHdgosKGPBnL7zzXTUJUx8G
Rr0xnOHOyb7fhQ1jlNefczg=
-----END CERTIFICATE-----"""


def test_client_cert():
    client = ClientCert()

    # Generate
    client.gen_client_cert(rkey, rcert)

    assert client.key
    assert client.crt

    # Inherit
    client2 = ClientCert(client.key, client.crt)

    assert client.key == client2.key
    assert client.crt == client.crt

    # Gen with size
    client = ClientCert(key_size=512)

    # Generate
    client.gen_client_cert(rkey, rcert)

    assert client.crt
    assert client.key

    # Error case
    client = ClientCert()

    with pytest.raises(PcoccError):
        key = client.key

    client = ClientCert()

    with pytest.raises(PcoccError):
        crt = client.crt


class myBatch(object):
    def __init__(self):
        self.root_cert = UserRootCert(rkey, rcert)
        self.client_cert = ClientCert(rkey, rcert)

    def vm_count(self):
        return 5

    def write_key(self, path, key, value):
        pass

    def read_key(self, path, key, blocking):
        assert path == "cluster/user"
        if key.endswith("0"):
            return "0:127.0.0.1:1230"
        elif key.endswith("1"):
            return "1:127.0.0.1:1231"
        elif key.endswith("2"):
            return "2:127.0.0.1:1232"
        elif key.endswith("3"):
            return "3:127.0.0.1:1233"
        elif key.endswith("4"):
            return "4:127.0.0.1:1234"
        else:
            return None


class myConfig(object):
    def __init__(self):
        self.batch = myBatch()


@patch("pcocc.Tbon.Config", myConfig)
def test_cert_from_conf():
    cert = Cert()

    # Data from config
    dat = cert.gen_user_key_cert()

    assert dat[0]
    assert dat[1]
    assert dat[2] == rcert

    lrct = cert.load_root_cert()
    assert lrct == rcert

    chain = cert.load_client_chain()

    assert chain[0]
    assert chain[1]
    assert chain[2] == lrct
    assert chain[2] == rcert


@patch("pcocc.Tbon.Config", myConfig)
def test_cert_no_file():
    cert = Cert()
    no_file_content_trig = [0]

    def no_file_content(path):
        no_file_content_trig[0] = no_file_content_trig[0] - 1
        if no_file_content_trig[0] <= 0:
            return None
        return "DATA" + path

    with patch("pcocc.Tbon.load_file_content", no_file_content):
        no_file_content_trig = [1]
        with pytest.raises(PcoccError):
            cert.gen_user_key_cert()
        no_file_content_trig = [2]
        with pytest.raises(PcoccError):
            cert.gen_user_key_cert()


class myConfigNoBatch(object):
    def __init__(self):
        self.batch = None


@patch("pcocc.Tbon.Config", myConfigNoBatch)
def test_cert():
    cert = Cert()

    # Test Error
    with pytest.raises(PcoccError):
        cert.gen_user_key_cert(None, rcert)
    with pytest.raises(PcoccError):
        cert.gen_user_key_cert(rkey, None)
    with pytest.raises(PcoccError):
        cert.gen_user_key_cert(None, None)

    # Data from param
    dat = cert.gen_user_key_cert(rkey, rcert)

    assert dat[0]
    assert dat[1]
    assert dat[2] == rcert

    lrct = cert.load_root_cert(rcert)
    assert lrct == rcert

    with pytest.raises(PcoccError):
        cert.load_client_chain()


def test_mt_tee():
    source = {i for i in range(0, 8192)}
    a, b = mt_tee(range(0, 8192))

    aa = set()
    ab = set()

    for e in a:
        aa.add(e)

    for e in b:
        ab.add(e)

    assert aa == source
    assert ab == source
    assert aa == ab


def test_mt_chain():
    source_odd = {i for i in range(1, 8192, 2)}
    source_even = {i for i in range(0, 8192, 2)}

    def gen(set_to_gen):
        for e in set_to_gen:
            yield e

    c = mt_chain(gen(source_odd), gen(source_even))

    target = {i for i in range(0, 8192)}

    out = set()

    for e in c:
        out.add(e)

    assert out == target


@patch("pcocc.Tbon.Config", myConfig)
def test_tree_client():
    cli = TreeNodeClient(1, DiscoverMode.Etcd,
                         enable_ssl=False, enable_client_auth=False)
    cli = TreeNodeClient(1, DiscoverMode.Etcd,
                         enable_ssl=True, enable_client_auth=True)
    with pytest.raises(PcoccError):
        cli = TreeNodeClient(1, DiscoverMode.Etcd,
                             enable_ssl=False, enable_client_auth=True)
    with pytest.raises(PcoccError):
        cli = TreeNodeClient(1)

    cli = TreeNodeClient(1, DiscoverMode.Etcd,
                         enable_ssl=True, enable_client_auth=True)

    assert cli.pid == 0
    assert cli.lid == 3
    assert cli.rid == 4

    cli = TreeNodeClient(0, DiscoverMode.Etcd,
                         enable_ssl=True, enable_client_auth=True)

    assert cli.pid == -1
    assert cli.lid == 1
    assert cli.rid == 2

    cli = TreeNodeClient(4, DiscoverMode.Etcd,
                         enable_ssl=True, enable_client_auth=True)

    assert cli.pid == 1
    assert cli.lid == -1
    assert cli.rid == -1


class fakeServer(object):

    def __init__(self, foo):
        pass

    def add_generic_rpc_handlers(self, bar):
        pass

    def add_secure_port(self, port, cred):
        assert port == "[::]:50051"

    def add_insecure_port(self, port):
        assert port == "[::]:50051"

    def start(self):
        pass


@patch("pcocc.Tbon.Config", myConfig)
@patch("pcocc.Tbon.grpc.server", fakeServer)
def test_tree_node():
    node = TreeNode(vmid=0, port=50051, enable_ssl=True)
    assert node.relay

    node = TreeNode(vmid=0, port=50051, enable_ssl=False,
                    client_ssl_auth=False)
    assert node.relay

    with pytest.raises(PcoccError):
        node = TreeNode(vmid=0, port=50051, enable_ssl=False,
                        client_ssl_auth=True)


class fake_ctx(object):
    def cancel(self):
        pass

    def add_callback(self, cb):
        pass



class my_secure_channel(object):
    def __init__(self, path, cred):
        pass
    
    def unary_unary(self, name, request_serializer, response_deserializer):
        pass

    def stream_stream(self, name, request_serializer, response_deserializer):
        
        def stream(stream):
            for e in stream:
                yield e
        
        return stream


@patch("pcocc.Tbon.Config", myConfig)
@patch("pcocc.Tbon.grpc.server", fakeServer)
def test_process_local_and_route():

    data = [0]

    def process_local(cmd):
        data[0] = 1
        assert cmd.source == 0
        assert cmd.destination == 0
        assert cmd.cmd == "test"
        assert cmd.data == '"TEST"'
        return "resp", "yes"

    node = TreeNode(vmid=0, port=50051, handler=process_local)

    cmd = pcocc.pcocc_pb2.Command(source=0,
                                  destination=0,
                                  cmd="test",
                                  data='"TEST"')

    ret = node.process_local(cmd)

    assert data[0] == 1
    assert ret.cmd == "resp"
    assert ret.data == '"yes"'

    # Route local
    data[0] = 0
    ret = node.route_command(cmd, None)

    assert data[0] == 1
    assert ret.cmd == "resp"
    assert ret.data == '"yes"'

    def fake_send_cmd(self, target, cmd):
        assert cmd.source == 0
        assert cmd.cmd == "test"
        assert cmd.data == '"TEST"'
        return pcocc.pcocc_pb2.Response(cmd="resp", data='"yes"')

    # Test routings
    with patch("pcocc.Tbon.TreeNodeClient.send_cmd", fake_send_cmd):
        for i in range(0, 4):
            cmd = pcocc.pcocc_pb2.Command(source=0,
                                          destination=i,
                                          cmd="test",
                                          data='"TEST"')
            ret = None
            ret = node.route_command(cmd, None)
            assert ret.cmd == "resp"
            assert ret.data == '"yes"'

            ret = None
            ret = node.command(i, "test", "TEST")
            assert ret.cmd == "resp"
            assert ret.data == '"yes"'
    
    # Test output generation

    def gen():
        inpt = [ str(i) for i in range(0,100) ]
        for e in inpt:
            yield myInputOutput(e)
        yield myInputOutput("last",eof=1)

    
    with patch("pcocc.Tbon.grpc.secure_channel", my_secure_channel):
        node = TreeNode(vmid=0, port=50051, handler=process_local)
        out = node.exec_stream(gen(), fake_ctx())
        sdata = set()
        for e in out:
            sdata.add(e.stdin)
        
        comp = { str(i) for i in range(0,100) }
        comp.add("last")

        assert sdata == comp


@patch("pcocc.Tbon.Config", myConfig)
def test_tree_client():

    TreeClient(["0", "127.0.0.1", "4567"])
    TreeClient(["0", "127.0.0.1", "4567"],
                        enable_ssl=False, enable_client_auth=False)
    TreeClient(["0", "127.0.0.1", "4567"],
                        enable_ssl=True, enable_client_auth=False)
    with pytest.raises(PcoccError):
        TreeClient(["0", "127.0.0.1", "4567"],
                   enable_ssl=False, enable_client_auth=True)
