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

import pytest

import pcocc.Image as Image
import tempfile
import os
import shutil
from pcocc.Error import PcoccError
from pcocc.Cache import Cache

def test_init(datadir):
    mgr = Image.ImageMgr()
    mgr.load_repos(str(datadir.join('repos1.yaml')),  'system')

    with pytest.raises(PcoccError):
        mgr.load_repos(str(datadir.join('repos_inval.yaml')),  'test')

def _get_clean_cache(size=128):
    tmp = tempfile.mkdtemp()
    return Cache(tmp, size)

def _check_blob(path):
    blob_content = "THIS IS MY BLOB"
    with open(path,"r") as f:
        d = f.read()
        assert(d == blob_content)

def test_push_get(datadir):
    blob_loc = str(datadir.join('BLOB'))
    cache = _get_clean_cache()

    cache["LOL"] = blob_loc

    assert("LOL" in cache)

    p = cache["LOL"]
    _check_blob(p.path)

def test_load_cache(datadir):
    cache_loc = str(datadir.join('sample_cache'))

    cache = Cache(cache_loc, 128)

    assert("LOL" in cache)

    p = cache["LOL"]
    _check_blob(p.path)

def test_load_deleted(datadir):
    cache_loc = str(datadir.join('sample_cache'))

    cache = Cache(cache_loc, 128)

    assert("LOL" in cache)
    assert("TOTO" not in cache)
    assert( len(cache) == 1 )


def test_clear(datadir):
    cache_loc = str(datadir.join('sample_cache'))

    cache = Cache(cache_loc, 128)

    cache.clear()

    dirs = os.listdir(cache_loc)
    assert(len(dirs) == 0)

def test_delete(datadir):
    blob_loc = str(datadir.join('BLOB'))
    cache = _get_clean_cache()

    cache["test"] = blob_loc

    assert("test" in cache)
    assert(len(cache) == 1)

    _check_blob(cache["test"].path)

    del cache["test"]

    assert(len(cache) == 0)

def test_overflow(datadir):

    blob_loc = str(datadir.join('BLOB'))
    cache = _get_clean_cache(size=16)

    for i in range(1,32):
        cache[str(i)] = blob_loc

    assert(len(cache) == 16)

    # Now check the LRU policy (last items are here)
    for i in range(25,32):
        assert(str(i) in cache)

def test_decimate(datadir):
    blob_loc = str(datadir.join('BLOB'))
    cache = _get_clean_cache(size=16)

    for i in range(1,32):
        cache[str(i)] = blob_loc

    beef = len(cache)

    # Default decimate remove half of the cache
    cache.decimate()

    assert(len(cache) == (beef//2))

def test_add_dir(datadir):
    dir_loc = str(datadir.join('adir'))
    cache = _get_clean_cache(size=16)

    cache["LOL"] = dir_loc

    assert("LOL" in cache)

    b = cache["LOL"]

    _check_blob(b.path + "/BLOB")

def test_del_dir(datadir):
    dir_loc = str(datadir.join('adir'))
    cache = _get_clean_cache(size=16)

    cache["LOL"] = dir_loc

    del cache["LOL"]


def test_insert_dir(datadir):
    blob_loc = str(datadir.join('BLOB'))
    cache = _get_clean_cache(size=16)

    with cache.directory("TOTO") as b:
        shutil.copy(blob_loc, b.path + "/file")

    b = cache["TOTO"]
    _check_blob(b.path + "/file")


def test_open_dir():
    cache = _get_clean_cache(size=16)

    with cache.directory("TOTO") as b:
        with pytest.raises(PcoccError):
            b.open()

def test_bad_dir():
    if os.access('/', os.W_OK):
        # This tests run in an environment where /
        # is writable it will fail
        return
    with pytest.raises(PcoccError):
        Cache("/toto", 16)

def test_bad_content():
    cache = _get_clean_cache(size=16)
    with pytest.raises(PcoccError):
       cache["toto"] = "/dev/null"

def test_no_write():
    if os.access('/etc', os.W_OK):
        # This tests run in an environment where /etc
        # is writable it will fail
        return
    with pytest.raises(PcoccError):
        Cache("/etc", 16)


def test_insert_file(datadir):
    cache = _get_clean_cache(size=16)

    with cache.blob("TOTO") as b:
        with b.open() as f:
            f.write("THIS IS MY BLOB")

    b = cache["TOTO"]
    _check_blob(b.path)

def test_bad_commit():
    cache = _get_clean_cache(size=16)
    with pytest.raises(PcoccError):
        cache.commit("TOTO")

def test_remove_no_rights(datadir):
    blob_loc = str(datadir.join('BLOB'))
    cache = _get_clean_cache(size=16)

    with cache.directory("TOTO") as b:
        shutil.copy(blob_loc, b.path + "/file")

    b = cache["TOTO"]
    _check_blob(b.path + "/file")

    os.chmod(b.path + "/file", 0o0)

    cache.clear()

def test_double_insert(datadir):
    blob_loc = str(datadir.join('BLOB'))
    cache = _get_clean_cache(size=16)
    cache["a"] = blob_loc
    with pytest.raises(PcoccError):
        cache["a"] = blob_loc