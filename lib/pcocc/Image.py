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

"""pcocc image management interface for containers and VM images."""

import logging
import os
import subprocess
import json
import re
import sys
import shutil
import tempfile
import time
import hashlib
import click
from . import ObjectStore
from . import Docker

from enum import Enum
from os.path import expanduser
from distutils import spawn

from .Config import Config
from .Cache import chmod_rm
from .Error import PcoccError

from .Oci import OciImage, OciRepoBlobs
from .Misc import path_join, pcocc_at_exit

class ImageType(Enum):
    """Enum describing a type of Image (CTR or VM)."""

    none = 1
    vm = 2
    ctr = 3

    @classmethod
    def from_str(cls, texttype):
        """Convert a str description of a type to an enum of this type.

        Arguments:
            texttype {str} -- "vm" or "ctr" depending on type

        Raises:
            PcoccError -- Could not parse input type

        Returns:
            Enum ImageType -- The corresponding internal type

        """
        if texttype.lower() == cls.vm.name.lower():
            return cls.vm

        if texttype.lower() == cls.ctr.name.lower() or texttype.lower() == "cont"  :
            return cls.ctr

        raise PcoccError("No such image type {}".format(texttype))

    @classmethod
    def default_format(cls, kind):
        """Retrieve default image format for a given ImageType.

        Arguments:
            kind {Enum ImageType} -- the kind of image

        Returns:
            str -- the default image type for this kind

        """
        if kind == cls.vm:
            return "raw"

        if kind == cls.ctr:
            return "docker-archive"

        return None

    @classmethod
    def infer_from_format(cls, fmt):
        """Infer image kind from input format.

        Arguments:
            fmt {str} -- the input format to check

        Raises:
            PcoccError -- this format was unknown

        Returns:
            Enum Imagetype -- the corresponding image kind

        """
        if fmt in ContImage.known_img_formats:
            return cls.ctr

        if fmt in VMImage.known_img_formats:
            return cls.vm

        raise PcoccError('{} is not a valid image format'.format(fmt))


class VMImage(object):
    """VMImage manipulation routines."""

    known_img_formats = ["raw", "qcow2", "qed", "vdi", "vpc", "vmdk"]

    @staticmethod
    def image_type(path):
        """Use 'qemu-img info' to inspect an image to get its type.

        Arguments:
            path {str} -- path to the image to be checked

        Raises:
            PcoccError -- An error occured while calling qemu-ime

        Returns:
            str -- the type of the VM image

        """
        if not os.path.isfile(path):
            raise PcoccError("{} is not an image file".format(path))
        if not os.access(path, os.R_OK):
            raise PcoccError("{} is not readable".format(path))

        try:
            jsdata = subprocess.check_output(["qemu-img",
                                              "info",
                                              "-U",
                                              "--output=json",
                                              path])
        except subprocess.CalledProcessError:
            return None

        try:
            data = json.loads(jsdata)
        except Exception:
            return None

        return data.get("format", None)

    @staticmethod
    def backing_file(path, full=False):
        """Resolve backing file for a VM file.

        Arguments:
            path {str} -- path to VM image to inspect

        Raises:
            PcoccError -- An error occured when calling 'qemu-img'

        Returns:
            str -- path to the VM image backing file

        """
        if not os.path.isfile(path):
            raise PcoccError("{} is not an image file".format(path))
        if not os.access(path, os.R_OK):
            raise PcoccError("{} is not readable".format(path))

        try:
            jsdata = subprocess.check_output(["qemu-img", "info", "-U",
                                              "--output=json", path]).decode()
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

    @staticmethod
    def rebase(image, backing_file="", unsafe=False):
        """Rebase a VM image onto another one.

        Arguments:
            image {str} -- image to be rebased

        Keyword Arguments:
            backing_file {str} -- image to rebase onto (default: {""})
            unsafe {bool} -- do not check file content (-u) (default: {False})

        Raises:
            PcoccError -- an error occured during rebase

        """
        try:
            cur_backing_file = VMImage.backing_file(image)
            if bool(cur_backing_file) == bool(backing_file):
                if not backing_file:
                    return
                if cur_backing_file == backing_file:
                    return

            unsafe_arg = []
            if unsafe:
                unsafe_arg = ["-u"]

            subprocess.check_output(["qemu-img", "rebase"] + unsafe_arg +
                                    ["-b",
                                     backing_file,
                                     "-F",
                                     "qcow2",
                                     "-f",
                                     "qcow2",
                                     image])
        except subprocess.CalledProcessError as e:
            raise PcoccError("Unable to rebase image. "
                             "The qemu-img command failed with: " + e.output)

    @classmethod
    def known_format(cls, ext):
        """Check if an image format is a VM format.

        Arguments:
            ext {str} -- image type

        Raises:
            PcoccError -- ext is not a VM image format

        """
        if ext not in cls.known_img_formats:
            raise PcoccError("VM image format {} not supported".format(ext))

    @staticmethod
    def export(source_path, dst_fmt, dst_path):
        """Export a VM image (from objectstore).

        Arguments:
            source_path {str} -- source path in objectstore
            dst_fmt {str} -- destination image format
            dst_path {str} -- destination image path

        """
        # Internally PCOCC stores VMs as
        # qcow 2 images
        src_format = "qcow2"
        VMImage.convert(source_path,
                        dst_path,
                        src_format,
                        dst_fmt,
                        operation="Exporting")

    @staticmethod
    def convert(source_path, dst_path,
                src_format, dst_format="qcow2",
                operation="Importing"):
        """Convert a VM image from one type to the other.

        Arguments:
            source_path {str} -- input image path
            dst_path {str} -- output image path
            src_format {str} -- input image type

        Keyword Arguments:
            dst_format {str} -- output image type  (default: {"qcow2"})
            operation {str} -- for logging (default: {"Importing"})

        """
        if not os.path.isfile(source_path):
            raise PcoccError("not an image file")

        if src_format != dst_format:
            print("Converting image...")
        else:
            print("Copying image...")

        try:
            subprocess.check_output(
                ["qemu-img", "convert",
                 "-f", src_format,
                 "-O", dst_format,
                 source_path, dst_path], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise PcoccError("Unable to convert image. "
                             "The qemu-img command failed with: " +
                             e.output)

        return dst_format

    @staticmethod
    def create(path, size, fmt, backing_path=None):
        """Create a VM image file.

        Arguments:
            path {str} -- output image path
            size {str} -- output image size (1MB for ex.)
            fmt {str} -- output image format
            backing_path {str} -- existing base image

        Raises:
            PcoccError -- failed to create image

        """
        ImageMgr.check_supported_format(ImageType.vm, fmt)

        backing_opt = []
        if backing_path:
            backing_opt = ['-F', fmt, '-b', backing_path]

        try:
            subprocess.check_output(
                ["qemu-img", "create", "-f", fmt] + backing_opt + [path, size])
        except subprocess.CalledProcessError as e:
            raise PcoccError("Unable to create image. "
                             "The qemu-img command failed with: " + e.output)


def _layout_size(path):
    ret = 0
    for e in os.listdir(path):
        targ = path_join(path, e)
        if os.path.isdir(targ):
            ret += _layout_size(targ)
        else:
            if os.path.islink(targ):
                targ = os.readlink(targ)

            ret += os.stat(targ).st_size
    return ret


def _cont_get_tmp_directory(layout_path):
    if "PCOCC_CTR_WORK_DIR" in os.environ:
        tmp_cont = os.environ["PCOCC_CTR_WORK_DIR"]
        logging.info("Using PCOCC_CTR_WORK_DIR=%s as temporary extraction directory", tmp_cont)
        return tempfile.mkdtemp(dir=tmp_cont)

    size = _layout_size(layout_path)

    if size <= Config().containers.config.container_shm_work_limit * 1024 * 1024:
        logging.info("Container fits under memory extraction threshold (%d MB)",
                     size // (1024 * 1024))
        return tempfile.mkdtemp(dir=Config().containers.config.container_shm_work_path)
    else:
        logging.info("Container exceeds memory extraction threshold  (%d MB)",
                     size // (1024 * 1024))
        return tempfile.mkdtemp()


class ContainerView(object):
    def __init__(self, image_uri):
        self.image_uri = image_uri
        self.meta, _ = Config().images.get_image(image_uri)
        kind = ImageType.from_str(self.meta['kind'])
        if kind != ImageType.ctr:
            raise PcoccError("{} is not a container image".format(image_uri))

        self.src_store = Config().images.object_store.get_repo(self.meta["repo"])
        self.atexit_func = None

    def prepare_cache(self):
        pass

    def get(self):
        pass

    def __enter__(self):
        return self.get()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self):
        self._call_cleanup_func()

    def _register_cleanup_func(self, func):
        self.atexit_func = func
        pcocc_at_exit.register(self._call_cleanup_func)

    def _call_cleanup_func(self):
        if self.atexit_func is not None:
            self.atexit_func()
            pcocc_at_exit.deregister(self._call_cleanup_func)
            self.atexit_func = None


class ContainerLayoutView(ContainerView):
    def __init__(self, image):
        ContainerView.__init__(self, image)

    def get(self):
        self.path = tempfile.mkdtemp()
        self._register_cleanup_func(lambda : chmod_rm(self.path))

        repos_blobs = OciRepoBlobs(self.src_store, self.meta)
        image = OciImage(oci_blobs_iface=repos_blobs)

        image.load()
        image.mirror(self.path)

        return self.path

class ContainerBundleView(ContainerView):
    def __init__(self, image):
        ContainerView.__init__(self, image)
        self.bundle_path = None

    def prepare_cache(self):
        self.bundle_path = self._get_bundle_from_cache()

    def get(self):
        if not self.bundle_path:
            self.prepare_cache()

        if Config().containers.config.use_squashfs:
            self.path = self._mount_squashfs()
        else:
            self.path = self.bundle_path

        return self.path

    def _get_bundle_from_cache(self):
        if Config().containers.config.use_squashfs:
            path = Config().images.cache_get(self.image_uri, "cached_squashfs")

        else:
            path = Config().images.cache_get(self.image_uri, "cached_bundle")

        if not path:
            path = self._cont_add_to_cache()

        return path

    def _run_with_patience(self, func, trials=20, wait=0.1):
        while trials:
            trials = trials - 1
            if trials == 0:
                return False
            try:
                func()
                break
            except Exception:
                time.sleep(wait)
                logging.debug('Retrying %s', func.__name__)
        return True

    def _check_mounted(self, directory):
        with open("/proc/mounts", "r") as f:
            mounts = f.read()
            return re.search(r'[ \t]{0}[ \t]'.format(directory), mounts) != None

    def _umount_squashfs(self, directory):
        try:
            logging.debug("unmounting squashfs image"
                          " at %s", directory)

            with open("/dev/null", "w") as devnull:
                subprocess.check_call(["fusermount",
                                       "-u",
                                       directory],
                                      stdout=devnull,
                                      stderr=devnull)

        except subprocess.CalledProcessError:
            raise PcoccError("Failed to unmount {}".format(directory))

    def _mount_squashfs(self):
        target_dir = tempfile.mkdtemp()
        if spawn.find_executable("squashfuse"):
            try:
                subprocess.check_call(["squashfuse",
                                       self.bundle_path,
                                       target_dir])
            except subprocess.CalledProcessError:
                raise PcoccError("Failed to mount squashfs image")

            # Wait for the mount to be complete by checking the directory
            # and contents as squashfuse may return early
            def local_check_mounted():
                if not self._check_mounted(target_dir):
                    raise PcoccError("Not mounted yet")
                if not os.listdir(target_dir):
                    raise PcoccError("Not mounted yet")

            if self._run_with_patience(local_check_mounted, wait=0.5):
                logging.debug("squashfs image"
                              " for %s mounted at %s", self.image_uri , target_dir)
            else:
                raise PcoccError("Squashfs mount did not complete properly")

            # If mount succeeded register unmount atexit
            self._register_cleanup_func(lambda : self._squashfs_cleanup(target_dir))
        else:
            raise PcoccError("Could not locate the 'squashfuse' binary which is required"
                             " when the squashfs container format is enabled")

        return target_dir

    def _squashfs_cleanup(self, target_dir):
        # Wait for a previous mount or the unmount to be complete as
        # squashfuse may return early
        if not self._run_with_patience(lambda: self._umount_squashfs(target_dir)):
            logging.warning("Failed to unmount squashfs on %s", target_dir)

        if not self._run_with_patience(lambda: shutil.rmtree(target_dir)):
            logging.warning("Failed to remove squashfs mount directory %s", self.path)

    def _cont_add_to_cache(self):
        # Prepare to save inside image cache
        oci_bundle_dir = None

        img = Config().images

        with ContainerLayoutView(self.image_uri) as oci_image:
            # Make sure to delete a previously failed image
            if Config().containers.config.use_squashfs:
                cache_key = "cached_squashfs"
            else:
                cache_key = "cached_bundle"

            img.cache_delete(self.image_uri, cache_key + "_tmp")

            if Config().containers.config.use_squashfs:
                img.cache_delete(self.image_uri, cache_key + "_tmp")
                cache_file = img.cache_new_blob(self.image_uri, cache_key + "_tmp")
                self._generate_squashfs_image(self.image_uri, oci_image, cache_file)
            else:
                with img.cache_add_dir(self.image_uri, cache_key + "_tmp") as cache_dir:
                    ContImage.extract_oci_bundle(oci_image, cache_dir.path)

            # If we are done we can rename the resulting blob
            # Make sure we have no conflict
            img.cache_delete(self.image_uri, cache_key)
            img.cache_rename(self.image_uri, cache_key + "_tmp", cache_key)

            oci_bundle_dir = img.cache_get(self.image_uri, cache_key)

            # Return where the bundle is instanciated
            return oci_bundle_dir

    def _cont_squashfs_populate_systematic_mounts(self, rootfs):
        mountpoints = Config().containers.config.img_mountpoints
        mountpoints = set(mountpoints)
        for m in mountpoints:
            target = path_join(rootfs, m)
            if not os.path.exists(target):
                try:
                    if m.endswith("/"):
                        os.makedirs(target)
                    else:
                        parentd = os.path.dirname(target)
                        if not os.path.exists(parentd):
                            os.makedirs(parentd)
                        open(target, "a").close()
                except OSError:
                    pass

    def _mksquashfs_has_progess(self):
        help_output = ""
        try:
            # First check if mksquashfs has the -quiet option
            # by reading the help message
            help_proc = subprocess.Popen(["mksquashfs", "--help"],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
            stdout, stderr = help_proc.communicate()
            help_output = (stdout + stderr).decode()
        except (subprocess.CalledProcessError, OSError):
            # Do not crash for reading the help
            pass
        return "-quiet" in help_output

    def _generate_squashfs_image(self, image, oci_image, cache_file):
        # Create a TMP directory in /dev/shm
        tmp_bundle = _cont_get_tmp_directory(oci_image)
        cleanup_func = lambda: chmod_rm(tmp_bundle)
        pcocc_at_exit.register(cleanup_func)

        try:
            ContImage.extract_oci_bundle(oci_image, tmp_bundle)

            if not spawn.find_executable("mksquashfs"):
                raise PcoccError("Could not locate 'mksquashfs'"
                                 " to extract the container")

            print("Generating squashfs image ...")

            rootfs = path_join(tmp_bundle, "rootfs")
            self._cont_squashfs_populate_systematic_mounts(rootfs)

            base_cmd = ["mksquashfs",
                        tmp_bundle,
                        cache_file.path,
                        "-noappend",
                        "-all-root",
                        # Disable compression for faster creation
                        "-noDataCompression",
                        "-noInodeCompression",
                        "-noFragmentCompression",
                        "-noXattrCompression"]

            try:
                if self._mksquashfs_has_progess():
                    # We can show a progress bar do a check_call
                    subprocess.check_call(base_cmd + ["-quiet"])
                else:
                    # We prefer to hide the output run in background
                    # and how output only in case of error
                    mksh = subprocess.Popen(base_cmd,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
                    stdout, stderr = mksh.communicate()
                    ret = mksh.returncode
                    if ret != 0:
                        sys.stdout.write(stdout.decode())
                        sys.stderr.write(stderr.decode())
                        raise subprocess.CalledProcessError(ret, base_cmd)
            except (subprocess.CalledProcessError, OSError):
                raise PcoccError("Failed to generate squashfs image")
        finally:
            cleanup_func()
            pcocc_at_exit.deregister(cleanup_func)

class ContImage(object):
    """Container Images manipulation routines."""

    known_img_formats = ["containers-storage", "dir", "docker",
                         "docker-archive", "docker-daemon", "oci",
                         "ostree", "pcocc-docker-daemon", "sif"]

    @classmethod
    def known_format(cls, ext):
        """Check if the image type is a container type.

        Arguments:
            ext {str} -- image type to be checked

        Raises:
            PcoccError -- image type is not a container type

        """
        if ext not in cls.known_img_formats:
            raise PcoccError("Container Image format not supported: " + ext)

    @staticmethod
    def extract_oci_bundle(oci_image_dir, destination_dir):
        oci = OciImage(oci_image_dir)
        oci.load()
        oci.extract_bundle(destination_dir)

    @classmethod
    def export(cls, source_path, dst_fmt, dst_path, src_fmt="oci"):
        """Export a container image (from objectstore).

        Arguments:
            source_path {str} -- path in objectstore
            dst_fmt {str} -- output image format
            dst_path {str} -- output image file
            src_format {str} -- output image format (optionnal)

        """
        cls.convert(source_path,
                    dst_path,
                    src_fmt,
                    dst_fmt)

    @staticmethod
    def skopeo_parse(path, fmt, vm, prefix='src-'):
        args = []
        if fmt == "pcocc-docker-daemon":
            args += ["--{}daemon-host".format(prefix), Docker.get_docker_uri(vm),
                     "--{}cert-dir".format(prefix), Docker.certs_dir("client")]
            fmt = "docker-daemon"

        if fmt == "docker":
            components = path[2:].split("/")
            if Config().containers.config.default_registry and (
                    not '.' in components[0] or ':' in components[0]
            ):
                if not '/' in path[2:]:
                    path='//library/' + path[2:]

                try:
                    path = '//' + Config().containers.config.default_registry + '/' + path[2:]
                except Exception:
                    pass

            if path.split('/')[2] in Config().containers.config.insecure_registries:
                args += ['|insecure_arg|']

        return path, fmt, args

    @classmethod
    def _skopeo_insecure_arg(cls,
                             args,
                             tls_type):
        try:
            i = args.index('|insecure_arg|')
            args[i] = "--{}-verify=false".format(tls_type)
        except ValueError:
            pass

    @classmethod
    def skopeo_convert(cls,
                       src_path,
                       dest_path,
                       src_fmt,
                       dst_format,
                       vm=None):

        src_path, src_fmt, args = cls.skopeo_parse(src_path, src_fmt, vm, 'src-')

        cls._skopeo_insecure_arg(args, "src-tls")

        cmd = (["skopeo", "copy" ] + args +
               [":".join([src_fmt, src_path]) ] +
               [":".join([dst_format, dest_path, "latest"])])

        try:
            subprocess.call(cmd)
        except subprocess.CalledProcessError:
            os.unlink(dest_path)
            raise PcoccError("An error occured during container conversion")

    @classmethod
    def prepare_skopeo_cache(cls,
                             src_path,
                             src_fmt,
                             dst_path,
                             dst_store,
                             vm=None
                         ):

        src_path, src_fmt, args = cls.skopeo_parse(src_path, src_fmt, vm, '')
        cls._skopeo_insecure_arg(args, "tls")

        cmd = ["skopeo", "inspect" ] + args + [src_fmt + ":" + src_path]

        try:
            skopeo_out = subprocess.check_output(cmd)
        except subprocess.CalledProcessError:
            raise PcoccError("Unable to inspect container layers")

        try:
            layers = json.loads(skopeo_out)['Layers']
        except Exception:
            raise PcoccError("Failed to parse skopeo output")

        blobs_path = os.path.join(dst_path, 'blobs')

        algorithms = []
        for l in layers:
            try:
                p = dst_store.get_obj_path('data', l, check_exists=True)
            except PcoccError:
                continue

            algorithm, enc = l.split(":")
            if algorithm not in algorithms:
                os.makedirs(os.path.join(blobs_path, algorithm))
                algorithms.append(algorithm)

            os.link(p, os.path.join(blobs_path, algorithm, enc))

    @classmethod
    def convert(cls,
                src_path,
                dst_path,
                src_fmt,
                dst_format="oci",
                dst_store=None,
                vm=None):
        """Convert a container image from one type to the other.

        Arguments:
            src_path {str} -- input image path
            dst_path {str} -- output image path
            src_fmt {str} -- input image format

        Keyword Arguments:
            dst_format {str} -- output format (default: {"oci"})
            dst_store {ObjectStore} -- object store which can provide blobs)

        Raises:
            PcoccError -- image conversion failed

        Returns:
            str -- output image format

        """
        if dst_store:
            cls.prepare_skopeo_cache(src_path,
                                     src_fmt,
                                     dst_path,
                                     dst_store,
                                     vm)

        cls.skopeo_convert(src_path,
                           dst_path,
                           src_fmt,
                           dst_format,
                           vm)

        return dst_format

    @staticmethod
    def add_oci_image_to_repo(image_name,
                              dst_store,
                              oci_image):
        oci = OciImage(oci_image)
        oci.load(check_digest=True)

        oci_index = oci.index
        all_blobs = oci.blobs_resolve(add_path=True)

        for h, infos in list(all_blobs.items()):
            dst_store.put_data_blob(infos["path"], known_hash=h)

        return oci_index, all_blobs


class ImageMgr(object):
    """Manager for pcocc images."""

    def __init__(self):
        """Intialization of the image manager."""
        self.object_store = ObjectStore.HierarchObjectStore()

    def load_repos(self, conf, tag):
        """Load Objectstore repositories from config.

        Arguments:
            conf {str} -- path to configuration file
            tag {str} -- attribute to attach to the repo

        """
        self.object_store.load_repos(conf, tag)

    def list_repos(self, tag=None):
        """Retrieve a list of repositories.

        Keyword Arguments:
            tag {str} -- filter list by tag (default: {None})

        Returns:
            array -- repository list

        """
        return self.object_store.list_repos(tag)

    def parse_image_uri(self, image_uri):
        """Split an image URI in its components.

        Arguments:
            image_uri {str} -- Input URI [REPO]:IMAGE[@version]

        Raises:
            PcoccError -- Revision is not an integer

        Returns:
            str -- image name
            str -- repository name (default: {None})
            int -- revision number (default: {None})

        """
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
        """Trigger garbage collection on a given repo.

        Arguments:
            repo {str} -- repository name

        """
        self.object_store.get_repo(repo).garbage_collect()

    def find(self, regex=None, repo=None, shallow=False):
        """Search for an image in repositor(y/ies).

        Keyword Arguments:
            regex {str} -- regxexpr for search (default: {None})
            repo {str} -- repository name (default: {None})
            shallow {bool} -- skip fetching full metadata details (default: {False})

        Raises:
            PcoccError -- Failed to parse the regular expression

        Returns:
            dict -- dictionnary with matching items

        """
        meta = self.object_store.load_meta(repo, shallow=shallow)

        if not regex:
            return meta

        try:
            search = re.compile(regex)
        except re.error as e:
            raise PcoccError("Could not parse regular expression :%s" % str(e))

        return {key: value for key, value in meta.items()
                if search.search(key)}

    def get_image(self,
                  image_uri,
                  image_revision=None):
        """Retrieve information for a given image.

        Arguments:
            image_uri {str} -- image URI

        Keyword Arguments:
            image_revision {int} -- image revision (default: {None})

        Returns:
            dict -- image meta-data
            str -- image path

        """
        image_name, repo, revision = self.parse_image_uri(image_uri)

        if image_revision is not None:
            revision = image_revision

        logging.info("pcocc repo : locating %s in %s" % (image_name, repo))

        meta = self.object_store.get_meta(image_name,
                                          revision=revision,
                                          repo=repo)

        return meta, self.object_store.get_repo(meta['repo']).get_obj_path(
            'data',
            meta['data_blobs'][-1])

    def image_revisions(self, uri):
        """List revisions for a given image.

        Arguments:
            uri {str} -- image URI

        Returns:
            array -- list of revisions

        """
        image_name, repo_name, _ = self.parse_image_uri(uri)
        return self.object_store.get_revisions(image_name, repo_name)

    def delete_image(self, uri):
        """Delete an image from objectstore.

        Arguments:
            uri {str} -- image URI
        """
        # Remove the associated cached objects
        for possibly_cached in ["cached_bundle", "cached_squashfs"]:
            self.cache_delete(uri, possibly_cached)

        name, repo, revision = self.parse_image_uri(uri)
        dest_store = self.object_store.get_repo(repo)

        dest_store.delete(name, revision)

    def prepare_vm_import(self, dst_uri):
        """Create a temporary file for a VM image (in qcow2).

        Arguments:
            dst_uri {str} -- expected URI for the new image

        Returns:
            str -- path to the new image

        """
        _, dst_repo, _ = self.parse_image_uri(dst_uri)
        dst_store = self.object_store.get_repo(dst_repo)

        return dst_store.tmp_file(ext=".qcow2")

    def add_revision_layer(self, dst_uri, path):
        """Save a VM onto its previous version (rebase).

        Arguments:
            dst_uri {str} -- destination URI
            path {str} -- path to the image to append

        Returns:
            dict -- meta-data for new entry

        """
        _, dst_repo, _ = self.parse_image_uri(dst_uri)
        dst_store = self.object_store.get_repo(dst_repo)

        _, tgt_backing_file = self.get_image(dst_uri)
        tgt_backing_blob = os.path.basename(tgt_backing_file)

        cur_backing_file = VMImage.backing_file(path,
                                                full=True)

        if not os.path.samefile(cur_backing_file, tgt_backing_file):
            print('Rebasing snapshot to preserve chaining...')
            VMImage.rebase(path, tgt_backing_file, False)

        rel_backing_file = dst_store.get_obj_path('data',
                                                  tgt_backing_blob,
                                                  True,
                                                  True)

        VMImage.rebase(path, rel_backing_file, True)
        meta, _ = self.get_image(dst_uri)
        h = dst_store.put_data_blob(path)
        meta['data_blobs'].append(h)

        return dst_store.put_meta(meta['name'], meta['revision'] + 1,
                                  meta['kind'], meta['data_blobs'],
                                  meta['custom_meta'])

    def cache_key(self, image_uri, key):
        meta, _ = self.get_image(image_uri)
        # Here we fully hash the meta in order to be
        # content adressing. Indeed, if the image changes
        # the index.json changes and so does the meta
        # This way the cache is directly invalidated
        h = hashlib.sha256()
        h.update('{0}\n{1}'.format(json.dumps(meta), key).encode('ascii',
                                                                 'ignore'))
        return h.hexdigest()

    @property
    def cache(self):
        return self.object_store.cache

    def cache_rename(self, image_uri, src_key, dest_key):
        src_desc = self.cache_key(image_uri, src_key)
        dest_desc = self.cache_key(image_uri, dest_key)
        self.object_store.cache.rename(src_desc, dest_desc)

    def cache_add_dir(self, image_uri, key):
        """Attach a directory inside repo for a given image.

        Arguments:
            image_uri {str} -- URI to the target image
            key {str} -- identifier of the attached directory

        Returns:
            str -- path to directory (not created)
            dict -- updated meta-data for the image

        """
        object_desc = self.cache_key(image_uri, key)
        return self.object_store.cache.directory(object_desc)

    def cache_new_blob(self, image_uri, key):
        object_desc = self.cache_key(image_uri, key)
        ret = self.object_store.cache.blob(object_desc)
        self.object_store.cache.commit(ret)
        return ret

    def cache_add_blob(self, image_uri, file_path, key):
        object_desc = self.cache_key(image_uri, key)
        self.object_store.cache[object_desc] = file_path
        return self.object_store.cache[object_desc].path

    def cache_get(self, image_uri, key):
        """Return directory path for attached directory.

        Arguments:
            image {str} -- target image URI
            key {str} -- key of the directory to retrieve

        Returns:
            str -- path to asssociated directory (or None)
            str -- type of object either "blob" or "dir"

        """
        object_desc = self.cache_key(image_uri, key)
        if object_desc not in self.object_store.cache:
            return None
        return self.object_store.cache[object_desc].path

    def cache_delete(self, image_uri, key):
        if not self.object_store.has_cache:
            # No cache configured nothing to do
            return
        object_desc = self.cache_key(image_uri, key)
        del self.object_store.cache[object_desc]

    def add_revision_full(self, kind, dst_uri, path):
        """Save image as a new full revision.

        Arguments:
            kind {ImageType enum} -- type of image to append a rev to
            dst_uri {str} -- URI on which to add a rev.
            path {str} -- path of the image to append

        Raises:
            PcoccError -- Failed to retrieve backing file
            PcoccError -- Image types are mismatching

        Returns:
            dict -- meta-data for new entry

        """
        dst_name, dst_repo, _ = self.parse_image_uri(dst_uri)
        dst_store = self.object_store.get_repo(dst_repo)

        if kind == ImageType.vm:
            if VMImage.backing_file(path):
                raise PcoccError("Tried to make a full revision with an image "
                                 "that has a backing file")

        try:
            meta, _ = self.get_image(dst_uri)
        except ObjectStore.ObjectNotFound:
            meta = None
            revision = 0

        if meta:
            revision = meta['revision'] + 1
            if kind != ImageType.from_str(meta['kind']):
                raise PcoccError(
                    "Unable to mix {0} and {1} image kinds".format(
                        kind,
                        meta['kind']))

        h = dst_store.put_data_blob(path)
        return dst_store.put_meta(dst_name, revision, kind.name, [h], {})

    def import_image(self, src_path, dst_uri, src_fmt=None, vm=None):
        """Import an image in the objectstore.

        Arguments:
            src_path {str} -- path to input image
            dst_uri {str} -- destination URI

        Keyword Arguments:
            src_fmt {str} -- source format (default: {None})

        Raises:
            PcoccError -- failed to import the image

        Returns:
            dict -- meta-data for new entry

        """
        dst_name, dst_repo, _ = self.parse_image_uri(dst_uri)
        dst_store = self.object_store.get_repo(dst_repo)

        src_path, src_fmt, kind = self.guess_format(src_path,
                                                    src_fmt)

        self.check_overwrite(dst_uri)

        image_blobs = []
        image_custom_meta = {}

        click.secho("Storing image in repository '{0}' as '{1}' ... "
                    .format(dst_store.name,
                            dst_name))

        if kind == ImageType.vm:
            tmp_path = dst_store.tmp_file(ext=".qcow2")
            try:
                VMImage.convert(src_path, tmp_path, src_fmt)
            except PcoccError as e:
                os.unlink(tmp_path)
                raise PcoccError("Failed to import {0} : {1}".format(src_path,
                                                                     str(e)))
            h = dst_store.put_data_blob(tmp_path)
            image_blobs = [h]
        elif kind == ImageType.ctr:
            tmp_oci = dst_store.tmp_dir()
            def remove_tmp_oci():
                shutil.rmtree(tmp_oci)
            pcocc_at_exit.register(remove_tmp_oci)
            try:
                ContImage.convert(src_path,
                                  tmp_oci,
                                  src_fmt,
                                  "oci",
                                  dst_store,
                                  vm=vm)

                # At this point tmp_oci contains an OCI image
                index, blobs = ContImage.add_oci_image_to_repo(dst_name,
                                                               dst_store,
                                                               tmp_oci)
                # At this points all blobs are saved
                image_blobs = [b["digest"] for b in list(blobs.values())]
                image_custom_meta["oci_index"] = index

            except PcoccError as e:
                raise PcoccError("Failed to import {0} : {1}".format(src_path,
                                                                     str(e)))
            finally:
                remove_tmp_oci()
                pcocc_at_exit.deregister(remove_tmp_oci)

        meta = dst_store.put_meta(dst_name, 0, kind.name, image_blobs,
                                  image_custom_meta)

        if kind == ImageType.ctr:
            # We prepare a bundle view that we don't use now to make
            # sure the bundle cache is populated at import time
            dst_uri = '{}:{}'.format(dst_store.name, dst_name)
            ContainerBundleView(dst_uri).prepare_cache()
            ContainerBundleView(dst_uri).cleanup()

        return meta

    def export_image(self, src_uri, dst, dst_fmt):
        """Export an image from the objectstore.

        Arguments:
            src_uri {str} -- source URI
            dst {str} -- destination path
            dst_fmt {str} -- destination format

        Raises:
            PcoccError -- Failed to export the image

        """
        meta, _ = self.get_image(src_uri)
        kind = ImageType.from_str(meta['kind'])

        dst_path, dst_fmt, _ = self.guess_format(dst,
                                                 dst_fmt,
                                                 kind)

        src_store = self.object_store.get_repo(meta["repo"])

        if kind == ImageType.vm:
            source_path = src_store.get_obj_path('data',
                                                 meta['data_blobs'][-1])
            VMImage.export(source_path, dst_fmt, dst_path)
        elif kind == ImageType.ctr:
            with ContainerLayoutView(src_uri) as source_path:
                ContImage.export(source_path,
                                 dst_fmt,
                                 dst_path,
                                 src_fmt='oci')

    def copy_image(self, src_uri, dst_uri):
        """Copy an image from a repository to another.

        Arguments:
            src_uri {str} -- source URI
            dst_uri {str} -- destination URI

        Returns:
            dict -- meta-data for new entry

        """
        dst_name, dst_repo, _ = self.parse_image_uri(dst_uri)
        src_meta, _ = self.get_image(src_uri)

        self.check_overwrite(dst_uri)

        src_store = self.object_store.get_repo(src_meta["repo"])
        dst_store = self.object_store.get_repo(dst_repo)

        for b in src_meta['data_blobs']:
            path = src_store.get_obj_path('data', b)
            dst_store.put_data_blob(path, b)

        return dst_store.put_meta(dst_name, 0, ImageType.from_str(src_meta["kind"]).name,
                                  src_meta["data_blobs"],
                                  src_meta["custom_meta"])

    def resize_image(self, uri, new_size):
        meta, src_path = self.get_image(uri)
        repo = self.object_store.get_repo(meta['repo'])

        tmp_path = repo.tmp_file(ext=".qcow2")

        VMImage.create(tmp_path, new_size, "qcow2", src_path)

        self.add_revision_layer(uri, tmp_path)

    def check_overwrite(self, dst_uri):
        """Check if adding an image at this URI would overwrite or shadow.

        Arguments:
            dst_uri {str} -- URI to test

        Raises:
            PcoccError -- same URI is already present in objectstore

        """
        dst_name, dst_repo, _ = self.parse_image_uri(dst_uri)
        # Check if we would overwrite or shadow an other image

        try:
            dst_meta = self.object_store.get_repo(dst_repo).get_meta(dst_name)
        except ObjectStore.ObjectNotFound:
            dst_meta = None

        if dst_meta:
            raise PcoccError("Image {0} already exists in repo {1}"
                             .format(dst_name, dst_meta['repo']))

        try:
            dst_meta = self.object_store.get_meta(dst_name)
        except ObjectStore.ObjectNotFound:
            dst_meta = None

        if dst_meta:
            click.secho("Warning: an image with name {0} "
                        "already exists in another repo ({1})".format(
                            dst_name, dst_meta["repo"]), fg="magenta")

    @staticmethod
    def check_supported_format(kind, fmt):
        """Check if the format is supported for the given image kind.

        Arguments:
            kind {ImageType enum} -- kind of image to check
            fmt {str} -- format to check

        Raises:
            PcoccError -- Image format not supported for this kind

        """
        if kind == ImageType.vm:
            VMImage.known_format(fmt)
        elif kind == ImageType.ctr:
            ContImage.known_format(fmt)
        else:
            raise PcoccError("Container Image format not supported: " + fmt)

    def guess_format(self, path, fmt=None, kind=None):
        """Guess format from filename and arguments.

        Arguments:
            path {str} -- path to image [fmt:]path[.fmt]
            fmt {str} -- format from args (default: {None})

        Keyword Arguments:
            allow_default {bool} -- export choice by default (default: {False})

        Raises:
            PcoccError -- For VM import mismatch between argument and file type
            PcoccError -- The image type could not be infered (need for arg -t)

        Returns:
            str -- corrected path to image (case of TYPE:PATH )
            str -- format of the image
            ImageType enum -- infered kind of the image

        """

        if fmt:
            fmt = fmt.lower()

        # Parse prefixes such as oci:path
        # If we recognize a prefix we update the path to remove it
        spl = path.split(":")
        if len(spl) >= 2:
            prefix = spl[0].lower()
            if (prefix in ContImage.known_img_formats or
                prefix in VMImage.known_img_formats):
                if fmt and prefix != fmt:
                    raise PcoccError("Mismatch between specified image "
                                     "format {} and import URI prefix {}".format(fmt, prefix))
                else:
                    fmt = prefix
                    path = ':'.join(spl[1:])

        path = expanduser(path)

        # Parse file extensions such as .qcow2
        # If we already have a format we ignore the suffix
        if not fmt:
            suffix = os.path.basename(path).split('.')[-1]
            if (suffix in VMImage.known_img_formats or
                suffix in ContImage.known_img_formats):
                fmt = suffix

        # Check if we can guess a format from the file content
        detect_fmt = None
        if os.path.exists(path) and os.path.isfile(path):
            try:
                detect_fmt = VMImage.image_type(path)
            except PcoccError:
                detect_fmt = None

            if detect_fmt == 'raw':
                detect_fmt = None

        elif (os.path.isdir(path) and
              os.path.isfile(os.path.join(path, 'oci-layout'))):
            detect_fmt = 'oci'

        # Check overall coherency between format and image kind
        if fmt:
            if detect_fmt and fmt != detect_fmt:
                raise PcoccError("Mismatch between specified format {} and "
                                 "detected image type {}".format(fmt, detect_fmt))
        else:
            if detect_fmt:
                fmt = detect_fmt
            elif kind:
                fmt = ImageType.default_format(kind)
            elif os.path.isfile(path):
                logging.warning("Could not detect image format, assuming raw VM")
                fmt = "raw"
            else:
                raise PcoccError("Could not detect image format")

        if kind and kind != ImageType.infer_from_format(fmt):
            raise PcoccError("{} is not a valid {} format".format(fmt, kind.name))
        else:
            kind = ImageType.infer_from_format(fmt)

        return path, fmt, kind
