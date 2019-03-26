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

import logging
import os
import subprocess
import json
import re

import ObjectStore

from .Error import PcoccError
from .scripts import click

class ImageMgr(object):
    def __init__(self):
        self.object_store = ObjectStore.HierarchObjectStore()

    def load_repos(self, conf, tag):
        self.object_store.load_repos(conf, tag)

    def list_repos(self, tag=None):
        return self.object_store.list_repos(tag=None)

    def parse_image_uri(self, image_uri):
        s = image_uri.split("@")
        if len(s) == 1:
            revision = None
        else:
            image_uri = '@'.join(s[:-1])
            try:
                revision = int(s[-1])
            except ValueError:
                raise PcoccError('Bad revision: {0}'.format(s[-1]))

        s = image_uri.split(":")
        if len(s) == 1:
            repo = None
            image_name = image_uri
        else:
            repo = s[0]
            image_name = s[1]

        return image_name, repo, revision

    def garbage_collect(self, repo):
        self.object_store.get_repo(repo).garbage_collect()

    def find(self, regex=None, repo=None):
        meta = self.object_store.load_meta(repo)

        if not regex:
            return meta

        try:
            search = re.compile(regex)
        except re.error as e:
            raise PcoccError("Could not parse regular expression :%s" % str(e))

        return { key: value  for key, value in meta.iteritems()
                 if search.search(key) }

    def get_image(self, image_uri, image_revision=None):
        image_name, repo, revision = self.parse_image_uri(image_uri)

        if image_revision is not None:
            revision=image_revision

        logging.info("pcocc repo : Locating %s in %s" % (image_name, repo))

        meta = self.object_store.get_meta(image_name, revision=revision, repo=repo)

        return meta, self.object_store.get_repo(meta['repo']).get_obj_path(
            'data',
            meta['data_blobs'][-1])

    def image_revisions(self, uri):
        image_name, repo_name, _ = self.parse_image_uri(uri)
        return self.object_store.get_revisions(image_name, repo_name)

    def delete_image(self, uri):
        name, repo, revision = self.parse_image_uri(uri)
        dest_store = self.object_store.get_repo(repo)

        dest_store.delete(name, revision)

    def prepare_vm_import(self, dst_uri):
        _, dst_repo, _ = self.parse_image_uri(dst_uri)
        dst_store = self.object_store.get_repo(dst_repo)

        return dst_store.tmp_file(ext=".qcow2")

    def add_revision_layer(self, dst_uri, path):
        _, dst_repo, _ = self.parse_image_uri(dst_uri)
        dst_store = self.object_store.get_repo(dst_repo)


        _, tgt_backing_file = self.get_image(dst_uri)
        tgt_backing_blob = os.path.basename(tgt_backing_file)


        cur_backing_file = self.read_vm_image_backing_file(path,
                                                           full=True)

        if not os.path.samefile(cur_backing_file, tgt_backing_file):
            print 'Rebasing snapshot to preserve chaining...'
            self.rebase(path, tgt_backing_file, False)

        rel_backing_file = dst_store.get_obj_path('data',
                                                  tgt_backing_blob,
                                                  True,
                                                  True)

        self.rebase(path, rel_backing_file, True)

        meta, _ = self.get_image(dst_uri)
        h = dst_store.put_data_blob(path)
        meta['data_blobs'].append(h)

        return dst_store.put_meta(meta['name'], meta['revision'] + 1,
                                  meta['kind'], meta['data_blobs'],
                                  meta['custom_meta'])

    def add_revision_full(self, kind, dst_uri, path):
        dst_name, dst_repo, _ = self.parse_image_uri(dst_uri)
        dst_store = self.object_store.get_repo(dst_repo)

        if self.read_vm_image_backing_file(path):
            raise PcoccError("Tried to make a full revision with an image "
                             "that has a backing file")

        try:
            meta, _ = self.get_image(dst_uri)
        except ObjectStore.ObjectNotFound:
            meta = None
            revision = 0

        if meta:
            revision = meta['revision'] + 1
            if kind != meta['kind']:
                raise PcoccError(
                    "Unable to mix {0} and {1} image kinds".format(
                        kind,
                        meta['kind']))

        h = dst_store.put_data_blob(path)
        return dst_store.put_meta(dst_name, revision, kind, [h], {})

    def import_image(self, kind, src_path, dst_uri, src_fmt=None):
        dst_name, dst_repo, _ = self.parse_image_uri(dst_uri)
        dst_store = self.object_store.get_repo(dst_repo)

        src_path, src_fmt = self._guess_format(src_path, kind, src_fmt)
        if not os.path.isfile(src_path):
            raise PcoccError("{0} is not an image file".format(src_path))

        self._check_supported_format(kind, src_fmt)

        self.check_overwrite(dst_uri)

        if kind == "vm":
            tmp_path = dst_store.tmp_file(ext=".qcow2")
            if src_fmt != "qcow2":
                print("Converting image...")
            else:
                print("Copying image...")

            try:
                convert(src_path, tmp_path, src_fmt, "qcow2")
            except PcoccError as e:
                os.unlink(tmp_path)
                raise PcoccError("Failed to import {0} : {1}".format(src_path,
                                                                     str(e)))

        print("Storing image in repository '{0}' as '{1}' ... ".format(dst_store.name,
                                                                       dst_name))
        h = dst_store.put_data_blob(tmp_path)
        return dst_store.put_meta(dst_name, 0, kind, [h], {})

    def export_image(self, src_uri, dst, dst_fmt):
        meta, _ = self.get_image(src_uri)
        kind = meta['kind']
        dst_path, dst_fmt = self._guess_format(dst, kind, dst_fmt)
        if os.path.exists(dst_path):
            raise PcoccError('File {0} already exists'.format(dst_path))

        self._check_supported_format(kind, dst_fmt)

        if kind == "vm":
            src_store = self.object_store.get_repo(meta["repo"])
            convert(src_store.get_obj_path('data', meta['data_blobs'][-1]),
                    dst_path, "qcow2", dst_fmt)

    def copy_image(self, src_uri, dst_uri):
        dst_name, dst_repo, _ = self.parse_image_uri(dst_uri)
        src_meta, _ = self.get_image(src_uri)

        self.check_overwrite(dst_uri)

        src_store = self.object_store.get_repo(src_meta["repo"])
        dst_store = self.object_store.get_repo(dst_repo)

        for b in src_meta['data_blobs']:
            path = src_store.get_obj_path('data', b)
            dst_store.put_data_blob(path, b)

        return dst_store.put_meta(dst_name, 0, src_meta["kind"],
                                  src_meta["data_blobs"],
                                  src_meta["custom_meta"])


    def resize_image(self, uri, new_size):
        meta, src_path = self.get_image(uri)
        repo = self.object_store.get_repo(meta['repo'])

        tmp_path = repo.tmp_file(ext=".qcow2")

        create(tmp_path, new_size, "qcow2", src_path)

        self.add_revision_layer(uri, tmp_path)

    def check_overwrite(self, dst_uri):
        dst_name, dst_repo, _ = self.parse_image_uri(dst_uri)
        # Check if we would overwrite or shadow an other image

        try:
            dst_meta = self.object_store.get_repo(dst_repo).get_meta(dst_name)
        except ObjectStore.ObjectNotFound:
            dst_meta = None

        if dst_meta:
            raise PcoccError("Image {0} already exists in repo {1}".format(
                                 dst_name, dst_meta['repo']))

        try:
            dst_meta = self.object_store.get_meta(dst_name)
        except ObjectStore.ObjectNotFound:
            dst_meta = None

        if dst_meta:
            click.secho("Warning: an image with name {0} "
                        "already exists in another repo ({1})".format(
                            dst_name, dst_meta["repo"]), fg="magenta")

    @staticmethod
    def _check_supported_format(kind, fmt):
        if kind == "vm":
            check_qemu_image_fmt(fmt)

    def _guess_format(self, path, kind, fmt):
        if fmt:
            fmt = fmt.lower()

        #Check if the format was prefixed
        if not fmt:
            spl = path.split(":")
            if len(spl) >= 2:
                fmt = spl[0].lower()
                path = ":".join(spl[1:])

        #Check if the format was suffixed
        if not fmt:
            fmt = self.extract_extension(path, kind)

        # For VMs we can detect the input file type
        if kind == "vm" and os.path.exists(path):
            detect = self.read_vm_image_type(path)
            if fmt and fmt != detect:
                raise PcoccError("Mismatch between specified format {} "
                                 "and detected format {}".format(fmt, detect))
            fmt = detect

        # Default type
        if not fmt:
            if kind == "vm":
                fmt = "raw"

        return path, fmt

    @staticmethod
    def read_vm_image_type(path):
        if not os.path.isfile(path):
            raise PcoccError("{} is not an image file".format(path))
        if not os.access(path, os.R_OK):
            raise PcoccError("{} is not readable".format(path))

        try:
            jsdata = subprocess.check_output(["qemu-img", "info","--output=json", path])
        except subprocess.CalledProcessError:
            return None

        try:
            data = json.loads(jsdata)
        except Exception:
            return None

        return data.get("format", None)

    @staticmethod
    def read_vm_image_backing_file(path, full=False):
        if not os.path.isfile(path):
            raise PcoccError("{} is not an image file".format(path))
        if not os.access(path, os.R_OK):
            raise PcoccError("{} is not readable".format(path))

        try:
            jsdata = subprocess.check_output(["qemu-img", "info","--output=json", path])
        except subprocess.CalledProcessError:
            return None

        try:
            data = json.loads(jsdata)
        except Exception:
            return None

        res = None
        if full:
            res = data.get("full-backing-filename", None)

        if not res:
            res = data.get("backing-filename", None)

        return res

    def extract_extension(self, in_path, kind):
        suffix = os.path.splitext(in_path)[-1].lower().replace(".", "")
        if kind == "vm":
            if suffix and suffix in known_vm_image_formats:
                return suffix

        return None

    @classmethod
    def rebase(cls, image, backing_file="", unsafe=False):
        try:
            cur_backing_file = cls.read_vm_image_backing_file(image)
            if bool(cur_backing_file) == bool(backing_file):
                if not backing_file:
                    return
                if cur_backing_file == backing_file:
                    return

            unsafe_arg = []
            if unsafe:
                unsafe_arg = ["-u"]

            subprocess.check_output(["qemu-img", "rebase"] + unsafe_arg +
                                     ["-b", backing_file,
                                     image])
        except subprocess.CalledProcessError as e:
            raise PcoccError("Unable to rebase image. "
                             "The qemu-img command failed with: " + e.output)

known_vm_image_formats = ["raw", "qcow2", "qed", "vdi", "vpc", "vmdk"]

def check_qemu_image_fmt(ext):
    if ext not in known_vm_image_formats:
        raise PcoccError("VM image format {} not supported".format(ext))

def convert(src, dst, src_format, dst_format):
    try:
        subprocess.check_output(
            ["qemu-img", "convert", "-f", src_format, "-O", dst_format, src, dst])
    except subprocess.CalledProcessError as e:
        raise PcoccError("Unable to convert image. "
                         "The qemu-img command failed with: " +e.output)

def create(path, size, fmt, backing_path=None):
    check_qemu_image_fmt(fmt)

    backing_opt = []
    if backing_path:
        backing_opt = ['-b', backing_path]

    try:
        subprocess.check_output(
            ["qemu-img", "create", "-f", fmt] + backing_opt + [path, size])
    except subprocess.CalledProcessError, e:
        raise PcoccError("Unable to create image. "
                         "The qemu-img command failed with: " + e.output)
