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
        dir_util.copy_tree(test_dir, bytes(tmpdir))

    return tmpdir
