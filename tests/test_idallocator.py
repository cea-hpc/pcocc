import pcocc
import os
import pytest

from pcocc.Misc import IDAllocator
from pcocc.Error import PcoccError
from pcocc.Batch import KeyTimeoutError

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

def test_range_alloc(config):
    config.batch.list_all_jobs.return_value = [100, 101]

    ida = IDAllocator('test/single', 100)
    ids_100 = []
    ids_101 = []

    # Allocate 50 ids per job
    config.batch.batchid = 100
    for i in xrange(0, 5):
        ids_100 += ida.alloc(10)

    config.batch.batchid = 101
    for i in xrange(0, 5):
        ids_101 += ida.alloc(10)

    assert len(ids_100) == 50
    assert len(ids_101) == 50
    assert len(set(ids_100 + ids_101)) == 100

    # No more availble ids
    with pytest.raises(PcoccError):
        ids_101 += ida.alloc(1)

    # free 40 ids from job 100
    config.batch.batchid = 100
    ida.free(ids_100[5:45])

    # free ids from wrong job
    config.batch.batchid = 101
    ida.free(ids_100)

    # unable to allocate 50 ids
    with pytest.raises(PcoccError):
        ids_101 += ida.alloc(50)

    # 40 ids available
    ids_101 += ida.alloc(40)
    assert len(ids_101) == 90
    assert len(set(ids_100[0:5] + ids_100[45:50]  + ids_101)) == 100
    
    # make job 100 inactive
    config.batch.list_all_jobs.return_value = [101]

    # 10 more ids available for job 101
    ids_101 += ida.alloc(10)
    assert len(ids_101) ==100
    assert len(set(ids_101)) == 100

    ida.free(ids_101)

def test_single_alloc(config):
    config.batch.list_all_jobs.return_value = [100]
    config.batch.batchid = 100

    ida = IDAllocator('test/single', 2)    

    id1 = ida.alloc_one()
    id2 = ida.alloc_one()

    assert id1 != id2

    # unable to allocate 3 ids
    with pytest.raises(PcoccError):
        ida.alloc_one()

    ida.free_one(id1)
    id1 = ida.alloc_one()
    assert id1 != id2

    ida.free([id1, id2])


def test_coll_alloc(config):
    config.batch.list_all_jobs.return_value = [100]
    config.batch.batchid = 100
    config.batch.node_rank = 0

    ida = IDAllocator('test/single', 1)    

    id1_a = ida.coll_alloc_one(0, 'test1')

    # wrong key
    config.batch.node_rank = 1
    with pytest.raises(KeyTimeoutError):
        ida.coll_alloc_one(0, 'badkey')

    id1_b = ida.coll_alloc_one(0, 'test1')
    assert id1_a == id1_b

    # unable to allocate 2 ids
    config.batch.node_rank = 0
    with pytest.raises(PcoccError):
        ida.coll_alloc_one(0, 'test2')
    config.batch.node_rank = 1
    with pytest.raises(KeyTimeoutError):
        ida.coll_alloc_one(0, 'test2')

    ida.free_one(id1_a)    


