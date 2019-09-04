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
import glob
import hashlib
import shutil
import subprocess
import sys

from .scripts import click
from .Config import Config
from .Error import PcoccError


def _chmod_whole_dir_for_rm(path):
    # Sometimes containers rootfs have rights
    # preventing a direct RM
    cmd = ["chmod", "-R", "700", "--", path]
    subprocess.check_call(cmd)


def chmod_rm(path):
    if os.path.isfile(path):
        return os.unlink(path)
    _chmod_whole_dir_for_rm(path)
    shutil.rmtree(path)


class CacheBlob(object):

    def __init__(self, cache, path, h, key=None, is_dir=False, create=True):
        self.cache = cache
        self.key = key
        self.hash = h
        self.is_dir = is_dir
        # make sure we do not end with / or dirname will
        # actually create the dir
        self._path = path.rstrip("/")
        Cache.try_create_cache_dir(os.path.dirname(self._path))

        if create:
            self.create()

    @property
    def path(self):
        return self._path

    @property
    def time(self):
        ret = 0
        try:
            st = os.stat(self._path)
            ret = st.st_mtime
        except os.error:
            pass
        return ret

    def create(self):
        # Start with invalid blobs to handle CTRL + C
        # during the cache insert
        self._path = self._path
        if self.is_dir:
            Cache.try_create_cache_dir(self._path)
        else:
            with open(self._path, 'w'):
                pass

    def touch(self, times=None):
        if os.path.exists(self._path):
            os.utime(self._path, times)

    def validate(self):
        # Only validate if we need to (if we created ourselves)
        if self._path.endswith(".deleted"):
            clean_path = self._path.replace(".deleted", "")
            os.rename(self._path, clean_path)
            self._path = clean_path

    def invalidate(self):
        # We need this to handle CTRL + C during cleanup
        if os.path.exists(self._path):
            new_path = self._path + ".deleted"
            # Is there already a leftover delete ?
            if os.path.exists(new_path):
                chmod_rm(new_path)
            os.rename(self._path, new_path)
            self._path = new_path

    def remove(self):
        if not os.path.exists(self._path):
            return
        is_dir = Cache.is_dir(self._path)

        self.invalidate()

        if not is_dir:
            os.unlink(self._path)
        else:
            chmod_rm(self._path)

    def open(self, mode='w'):
        if self.is_dir:
            raise PcoccError("Only file blobs can be openned")
        return open(self._path, mode=mode)

    def __enter__(self):
        self.invalidate()
        return self

    def __exit__(self, typ, value, tb):
        if (typ is None and
                value is None and
                tb is None):
            self.cache.commit(self)
        else:
            # Someting went wrong delete the item
            self.remove()


class Cache(dict):

    @staticmethod
    def try_create_cache_dir(path):
        if not os.path.isdir(path):
            try:
                os.makedirs(path)
            except os.error:
                raise PcoccError("Could not create cache dir")

    @staticmethod
    def is_dir(path):
        if os.path.isfile(path):
            is_dir = False
        elif os.path.isdir(path):
            is_dir = True
        else:
            raise PcoccError("Only file and directories can be added in Cache")
        return is_dir

    def clean_empty_dirs(self):
        # Remove deleted files first as they may empty dirs
        blob_list = glob.glob(os.path.join(self.path, '*/*'))
        for bpath in blob_list:
            h = os.path.basename(bpath)
            if h.endswith(".deleted"):
                chmod_rm(bpath)

        dir_list = filter(os.path.isdir,
                          [os.path.join(self.path, p)
                           for p in os.listdir(self.path)])
        empty_dirs = filter(lambda d: len(os.listdir(d)) == 0, dir_list)
        map(os.rmdir, empty_dirs)

    def _check_overall_cache_size(self, count=1):
        if self._max_entry and len(self) >= self._max_entry:
            click.secho("Cache is too big ({} / {}), "
                        "cleaning up ...".format(len(self),
                                                 self._max_entry),
                        nl=False)
            sys.stdout.flush()
            self.decimate(count=count)
            click.secho("DONE")

    def __init__(self, cache_path, max_entry=0):
        self.path = Config().resolve_path(cache_path)
        self._max_entry = max_entry
        Cache.try_create_cache_dir(self.path)
        if not os.access(self.path, os.W_OK):
            raise PcoccError("Cache should be writable"
                             " in {}".format(self.path))
        super(Cache, self).__init__()
        self._load()
        self._check_overall_cache_size()

    def _load(self):
        blob_list = glob.glob(os.path.join(self.path, '*/*'))
        for bpath in blob_list:
            is_dir = Cache.is_dir(bpath)
            h = os.path.basename(bpath)
            if h.endswith(".deleted"):
                # It seems the user was not patient during
                # the last delete skip this blob
                continue
            blob = CacheBlob(self, bpath, h, is_dir=is_dir, create=False)
            super(Cache, self).__setitem__(blob.hash, blob)

    def hash_key(self, key):
        d = hashlib.sha512()
        d.update(key)
        return d.hexdigest()

    def _hash_dir(self, h):
        return self.path + "/" + h[:2]

    def _get_path(self, key):
        h = self.hash_key(key)
        blob_dir = self._hash_dir(h)
        self.try_create_cache_dir(blob_dir)
        return blob_dir + "/" + h

    def clear(self):
        map(lambda b: b.remove(), self.values())
        self.clean_empty_dirs()

    def get_sorted_blob_list(self):
        return sorted(self.values(), key=lambda b: b.time)

    def decimate(self, count=None):
        blobs = self.get_sorted_blob_list()

        # Remove half of the cache
        if count is None:
            count = len(blobs) // 2

        # Calculate how many to delete to respect count
        cnt = len(blobs) - count
        to_keep = cnt if 0 < cnt else 0

        def delblob(b):
            self.delete_hash(b.hash)

        map(delblob, blobs[:to_keep])

        self.clean_empty_dirs()

    def commit(self, blob):
        if not isinstance(blob, CacheBlob):
            raise PcoccError("Only CacheBlob can be committed")
        blob.validate()
        super(Cache, self).__setitem__(blob.hash, blob)

    def _entry(self, key, is_dir, create=True):
        self._check_overall_cache_size(count=1)
        if key in self:
            raise PcoccError("Key is already in cache")
        h = self.hash_key(key)
        path_in_cache = self._get_path(key)
        blob = CacheBlob(self, path_in_cache, h, key, is_dir, create=create)
        return blob

    def blob(self, key, create=True):
        return self._entry(key, is_dir=False, create=create)

    def directory(self, key, create=True):
        return self._entry(key, is_dir=True, create=create)

    def __contains__(self, key):
        h = self.hash_key(key)
        return super(Cache, self).__contains__(h)

    def __getitem__(self, key):
        h = self.hash_key(key)
        b = super(Cache, self).__getitem__(h)
        # Update modification time for GC
        b.touch()
        return b

    def delete_hash(self, h):
        if super(Cache, self).__contains__(h):
            b = super(Cache, self).__getitem__(h)
            b.remove()
            super(Cache, self).__delitem__(h)

    def __delitem__(self, key):
        h = self.hash_key(key)
        self.delete_hash(h)

    def rename(self, src, dest):
        if src not in self:
            raise PcoccError("rename: cannot find src in cache")
        if dest == src:
            raise PcoccError("rename: cannot move item on itself")
        sblob = self[src]
        # Put item allowing to move the data
        self.putitem(dest, sblob.path, can_move=True)
        # Remove reference to old item
        del self[src]

    def putitem(self, key, path, can_move=False):
        is_dir = Cache.is_dir(path)
        with self._entry(key, is_dir, create=False) as b:

            if can_move:
                if path.startswith(self.path):
                    shutil.move(path, b.path)
                    return

            if is_dir:
                shutil.copytree(path, b.path)
            else:
                shutil.copy(path, b.path)

    def __setitem__(self, key, path):
        self.putitem(key, path)
