import pytest
import pcocc
import os

from pcocc.Batch import KeyTimeoutError
from distutils import dir_util

kvstore = {}
def kv_atom_update_mock(*args, **kwargs):
    key = os.path.join(args[0], args[1])
    nargs = args[3:] + (kvstore.get(key, None),)
    nval, ret = args[2](*nargs, **kwargs)
    kvstore[key] = nval

    return ret

def kv_write_mock(*args):
    key = os.path.join(args[0], args[1])
    kvstore[key] = args[2]


def kv_read_mock(*args, **kwargs):
    key = os.path.join(args[0], args[1])
    val =  kvstore.get(key, None)
    if not val and kwargs.get('blocking', False):
        raise KeyTimeoutError('')

    return val


@pytest.fixture
def config(mocker):
    config = pcocc.Config()
    mocker.patch.object(config, 'batch')
    config.batch.atom_update_key.side_effect = kv_atom_update_mock
    config.batch.write_key.side_effect = kv_write_mock
    config.batch.read_key.side_effect = kv_read_mock
    return config


@pytest.fixture
def datadir(tmpdir, request):
    '''
    Fixture responsible for searching a folder with the same name of test
    module and, if available, moving all contents to a temporary directory so
    tests can use them freely.
    '''
    filename = request.module.__file__
    test_dir, _ = os.path.splitext(filename)

    if os.path.isdir(test_dir):
        dir_util.copy_tree(test_dir, str(tmpdir))

    return tmpdir


class Command(object):
    """Mock of a pcocc command object
    """
    def __init__(self, t, data):
        self.cmd = t
        self.data = data


class my_cluster(object):
    """Mock of a pcocc cluster object
    """
    def check_command_client(self):
        pass

    def tbon_disconnect(self):
        pass

    def vm_count(self):
        return 8

    def exec_stream(self, inputs):
        inp = inputs()
        for v in inp:
            yield v

    def check_agent(self, rank):
        return 1

    def command(self, index, cmd, data, direct):
        if cmd == "exec":
            assert "exe" in data
            assert data["exe"] == "ls"
            assert "args" in data
            assert "alloc_id" in data
            assert data["alloc_id"] == "1"
            assert "uid" in data
            assert data["uid"] == "16"
            assert "gid" in data
            assert data["gid"] == "32"
            return Command("success", "{}")
        elif cmd == "alloc_new":
            assert "size" in data
            assert data["size"] == "16"
            assert "desc" in data
            assert data["desc"] == "test"
            assert "global_alloc_id" in data
            assert data["global_alloc_id"] == "123"
            return Command("success", '{"alloc_id":8}')
        elif cmd == "alloc_get_res":
            return Command("success", '{"ressource_left":8}')
        elif cmd == "alloc_free":
            assert "alloc_id" in data
            assert data["alloc_id"] == "99"
            return Command("success", '{}')
        elif cmd == "hello":
            return Command("success", '{"time":"123"}')
        elif cmd == "hostname":
            return Command("success", '{"hostname":"here"}')
        elif cmd == "mkdir" or cmd == "chmod":
            assert "path" in data
            assert data["path"] == "/here"
            assert "mode" in data
            assert data["mode"] == "777"
            return Command("success", '{}')
        elif cmd == "unsetenv":
            assert "key" in data
            assert data["key"] == "thekey"
            return Command("success", '{}')
        elif cmd == "setenv":
            assert "key" in data
            assert data["key"] == "thekey"
            assert "value" in data
            assert data["value"] == "test"
            return Command("success", '{}')
        elif cmd == "getenv":
            assert "key" in data
            assert data["key"] == "thekey"
            return Command("success", '{"value":"test"}')
        elif cmd == "truncate":
            assert "path" in data
            assert data["path"] == "/here"
            assert "size" in data
            assert data["size"] == "1234"
            return Command("success", '{}')
        elif cmd == "lookup":
            assert "host" in data
            assert data["host"] == "vm0"
            return Command("success", '{"ips":"10.19.213.1"}')
        elif cmd == "getip":
            assert "iface" in data
            assert data["iface"] == "eth0"
            return Command("success", '{"ip":"10.19.213.1"}')
        elif cmd == "userinfo":
            assert "login" in data
            assert data["login"] == "bob"
            return Command("success", '{"uid":"1000"}')
        elif cmd == "readfile":
            assert "path" in data
            assert data["path"] == "/here"
            assert "base64" in data
            if data["base64"] == "True":
                return Command("success", '{"content":"dGVzdA=="}')
            elif data["base64"] == "False":
                return Command("success", '{"content":"test"}')
            else:
                raise Exception("No such base64 value {0}".format(
                                data["base64"]))
        elif cmd == "stat" or cmd == "rm":
            assert "path" in data
            assert data["path"] == "/here"
            return Command("success", '{}')
        elif cmd == "vmstat":
            assert "interupt" in data
            assert (data["interupt"] == "True")
            return Command("success", '{"cpu":"50"}')
        elif cmd == "writefile":
            assert "path" in data
            assert data["path"] == "/here"
            assert "base64" in data
            if data["base64"] == "True":
                    assert "content64" in data
                    assert data["content64"] == "dGVzdA=="
            elif data["base64"] == "False":
                    assert "content" in data
                    assert data["content"] == "test"
            else:
                raise Exception("No such base64 value {0}".format(
                                data["base64"]))
            assert "append" in data
            assert data["append"] == "true"
            return Command("success", '{}')
        elif cmd == "ln" or cmd == "mv":
            assert "src" in data
            assert data["src"] == "/from"
            assert "dest" in data
            assert data["dest"] == "/to"
            return Command("success", '{}')
        elif cmd == "chown":
            assert "path" in data
            assert data["path"] == "/here"
            assert "uid" in data
            assert data["uid"] == "123"
            assert "gid" in data
            assert data["gid"] == "456"
            return Command("success", '{}')
        elif(cmd == "freeze"
             or cmd == "thaw"
             or cmd == "exec_attach"
             or cmd == "exec_detach"
             or cmd == "exec_stdin_eof"):
            return Command("success", '{}')
        else:
            return Command("error", '{"error":"Not supported"}')

class fail_cluster(my_cluster):
    """Mock of a pcocc cluster object failing all commands
    """
    def check_agent(self,vm):
        return 1

    def command(self, index, cmd, data, direct):
        return Command("error", '{"error":"You must FAIL!"}')

class myInputOutput(object):
    def __init__(self, data, is_stderr=0, eof=0):
        self.stdin = data
        self.stderr = is_stderr
        self.eof = eof
