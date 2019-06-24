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
from __future__ import division
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
import ObjectStore

from enum import Enum
from os.path import expanduser
from distutils import spawn

from .Config import Config
from .Cache import chmod_rm
from .Error import PcoccError
from .scripts import click
from .Oci import OciImage, OciRepoBlobs
from .Misc import path_join, pcocc_at_exit

class ImageType(Enum):
    """Enum describing a type of Image (CONT or VM)."""

    none = 1
    vm = 2
    cont = 3

    @classmethod
    def from_str(cls, texttype):
        """Convert a str description of a type to an enum of this type.

        Arguments:
            texttype {str} -- "vm" or "cont" depending on type

        Raises:
            PcoccError -- Could not parse input type

        Returns:
            Enum ImageType -- The corresponding internal type

        """
        if texttype.lower() == cls.vm.name.lower():
            return cls.vm

        if texttype.lower() == cls.cont.name.lower():
            return cls.cont

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

        if kind == cls.cont:
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
        if not fmt:
            return cls.none

        if fmt in ContImage.known_container_image_formats:
            return cls.cont

        if fmt in VMImage.known_vm_image_formats:
            return cls.vm

        if fmt:
            raise PcoccError("Could not infer image kind "
                             "from '{}' image format".format(fmt))
        else:
            raise PcoccError("Failed to detect image kind "
                             "you may provide it with the -t option")


class VMImage(object):
    """VMImage manipulation routines."""

    known_vm_image_formats = ["raw", "qcow2", "qed", "vdi", "vpc", "vmdk"]

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
            jsdata = subprocess.check_output(["qemu-img", "info",
                                              "--output=json", path])
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
        if ext not in cls.known_vm_image_formats:
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
        click.secho(operation + " image... ")
        sys.stdout.flush()
        try:
            subprocess.check_output(
                ["qemu-img", "convert",
                 "-f", src_format,
                 "-O", dst_format,
                 source_path, dst_path])
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
            backing_opt = ['-b', backing_path]

        try:
            subprocess.check_output(
                ["qemu-img", "create", "-f", fmt] + backing_opt + [path, size])
        except subprocess.CalledProcessError, e:
            raise PcoccError("Unable to create image. "
                             "The qemu-img command failed with: " + e.output)


def _dir_size(path, depth=0):
    ret = 0
    if depth >= 5:
        # Do not go too deep
        return
    for e in os.listdir(path):
        targ = path_join(path, e)
        if os.path.isdir(targ):
            ret += _dir_size(targ, depth=depth + 1)
        else:
            if os.path.islink(targ):
                targ = os.readlink(targ)

            ret += os.stat(targ).st_size
    return ret


def _compute_path_size(path):
    if os.path.isdir(path):
        return _dir_size(path) / (1024.0 * 1024.0)
    elif os.path.isfile(path):
        # This is a file
        return os.stat(path).st_size / (1024.0 * 1024.0)
    else:
        # Cannot conclude
        return None


def _cont_get_tmp_directory(size=None):
    # If tmp directory is forced in environment
    # it superseded every choice
    if "PCOCC_CONT_TMP_DIR" in os.environ:
        tmp_cont = os.environ["PCOCC_CONT_TMP_DIR"]
        logging.info("Using PCOCC_CONT_TMP_DIR=%s as tmp directory" % tmp_cont)
        return tempfile.mkdtemp(dir=tmp_cont)

    if size:
        tmp_path = Config().containers.config.container_tmp_path
        # Only do to the optimized case if size is small enough
        if int(size) <= Config().containers.config.container_tmp_path_trsh_mb:
            logging.info("Size %s MB is small"
                         " enough for *container_tmp_path*" % str(size))
            return tempfile.mkdtemp(dir=tmp_path)
        else:
            logging.info("Size %s MB is too"
                         " big for *container_tmp_path*" % size)

    logging.info("Using system default for container TMP dir")
    # Use system's default
    return tempfile.mkdtemp()


class ContainerView(object):

    def __init__(self, image, view_type=None, target_dir=None, can_mount=True):
        self.image = image
        # Extract image info
        self.meta, _ = Config().images.get_image(image)

        if self.meta is None:
            raise PcoccError("Could not find "
                             "image '%s' in repositories" % image)

        repo = self.meta["repo"]
        self.src_store = Config().images.object_store.get_repo(repo)

        self.can_mount = can_mount
        self.target_dir = target_dir
        self.path = None
        self.view_type = view_type

        self.squashfs_atexit_umount = None
        self.ociview_atexit_delete = None

    def get(self, view_type=None, target_dir=None):
        if not view_type:
            view_type = self.view_type

        if view_type == "oci":
            self.path = self._init_oci_view(target_dir)
        elif (view_type == "bundle") or (view_type == "rootfs"):
            self.path = self._init_bundle_view(target_dir)
        else:
            raise PcoccError("No such view type {}".format(view_type))

        self.view_type = view_type

        return self.path

    def cleanup(self):
        if self.view_type == "oci":
            self._delete_oci_view()
        elif (self.view_type == "bundle") or (self.view_type == "rootfs"):
            self._delete_bundle_view()
        else:
            return
        self.view_type = None

    def __enter__(self):
        return self.get(self.view_type,
                        target_dir=self.target_dir)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def _init_oci_view(self, target_dir=None):
        if not target_dir:
            target_dir = tempfile.mkdtemp()
        repos_blobs = OciRepoBlobs(self.src_store, self.meta)
        image = OciImage(oci_blobs_iface=repos_blobs)
        image.load()
        image.mirror(target_dir)

        def atexit_delete_ociview():
            chmod_rm(self.path)

        self.ociview_atexit_delete = atexit_delete_ociview
        pcocc_at_exit.register(self.ociview_atexit_delete)

        return target_dir

    def _delete_path(self):
        # Remove tmp directory
        chmod_rm(self.path)

        pcocc_at_exit.deregister(self.ociview_atexit_delete)
        self.ociview_atexit_delete = None

        self.path = None

    def _delete_oci_view(self):
        self._delete_path()

    def _init_bundle_view(self, target_dir=None):
        if (not self.view_type == "rootfs" and
                Config().containers.config.use_squashfs):
            return self._init_bundle_view_squashfs(target_dir)
        else:
            return self._init_bundle_view_rootfs(target_dir)

    def _delete_bundle_view(self):
        if (not self.view_type == "rootfs" and
                Config().containers.config.use_squashfs):
            self._delete_bundle_view_squashfs()
        else:
            self._delete_bundle_view_rootfs()

    def _get_bundle_from_cache(self):
        if Config().containers.config.use_squashfs:
            # This is a path to the squashfs image
            return Config().images.cache_get(self.image, "cached_squashfs")
        else:
            # This is a path to the rootfs in cache
            return Config().images.cache_get(self.image, "cached_bundle")

    def _init_bundle_view_rootfs(self, target_dir=None):
        self.path = self._get_bundle_from_cache()

        if not self.path:
            self.path = self._cont_create_bundle(kind="rootfs")

        return self.path

    def _delete_bundle_view_rootfs(self):
        # We do not want to delete the roofs from cache
        pass

    def _init_bundle_view_squashfs(self, target_dir=None):
        squashfs_image = self._get_bundle_from_cache()

        if not squashfs_image:
            squashfs_image = self._cont_create_bundle(kind="squashfs")

        if self.can_mount:
            # At this point we still need to mount
            self.path = self._mount_squashfs(squashfs_image,
                                             target_dir=target_dir)
            return self.path
        else:
            return None

    def _delete_bundle_view_squashfs(self):
        if not self.path:
            return

        def try_unmount():
            if self.can_mount:
                self._squash_fs_umount(self.path, force=True)

        # There is sometimes latency relative to the update
        # of the mount table so we add some tolerance with
        # respect to the unmounting phase to prevent leftovers
        if self._run_with_patience(try_unmount):
            logging.warning("Failed to unmount"
                            " squashfs mount %s" % (self.path))
        else:
            # Unmount suceeded remove from atexit
            pcocc_at_exit.deregister(self.squashfs_atexit_umount)
            self.squashfs_atexit_umount = None

        def delete_squashfs_mountdir():
            shutil.rmtree(self.path)

        # Here in order not to race fuse we add some tolerance too
        if self._run_with_patience(delete_squashfs_mountdir):
            logging.warning("Failed to remove squashfs mount %s"
                            % self.path)
        # If we failed to umount give up without errors

    def _squash_fs_umount(self, directory, force=False):

        if not force and not self._check_mounted(directory):
            # Directory does not seem to be mounted
            return

        if spawn.find_executable("fusermount"):
            try:
                with open("/dev/null", "w") as devnull:
                    subprocess.check_call(["fusermount",
                                           "-uz",
                                           directory],
                                          stdout=devnull,
                                          stderr=devnull)
            except subprocess.CalledProcessError:
                raise PcoccError("Failed to unmount {}".format(directory))
        else:
            raise PcoccError("Could not locate 'fusermount'\n"
                             "Fuse (and squashfuse) are required to\n"
                             "mount container images if squashfs is enabled\n"
                             "in 'containers.yaml', consider disabling it.")

    def _check_mounted(self, directory):
        mounts = ""

        if os.path.exists("/proc/mounts"):
            with open("/proc/mounts", "r") as f:
                mounts = f.read()
        else:
            # First make sure path is a mount
            try:
                mounts = subprocess.check_output(["mount"])
            except (subprocess.CalledProcessError, OSError):
                pass

        if directory in mounts:
            # Nothing to do skip
            return True

        return False

    def _run_with_patience(self, func, trials=20, wait=0.1):
        while trials:
            trials = trials - 1
            if trials == 0:
                return True
            try:
                func()
                break
            except Exception as e:
                time.sleep(wait)
                if not trials:
                    print(e)
        return False

    def _mount_squashfs(self, squash_fs_image, target_dir=None):

        if not target_dir:
            target_dir = tempfile.mkdtemp()

        if not os.path.isdir(target_dir):
            os.makedirs(target_dir)
        else:
            self._squash_fs_umount(target_dir)

        os.stat(target_dir)

        if spawn.find_executable("squashfuse"):
            try:
                # For debug if needed start the daemon
                # in foreground
                # sp = subprocess.Popen(["squashfuse",
                #                        "-s",
                #                        "-d",
                #                        "-f",
                #                        squash_fs_image,
                #                        target_dir])
                # time.sleep(5)
                subprocess.check_call(["squashfuse",
                                       squash_fs_image,
                                       target_dir])
            except subprocess.CalledProcessError:
                raise PcoccError("Failed to mount squashfs image")

            # Now list directory content to ensure the FS is available
            # in order not to race squashfuse
            def local_check_mounted():
                # Make sure the mount table is updated
                if not self._check_mounted(target_dir):
                    raise PcoccError("Not mounted yet")
                # Make sure there is someting in the dir
                if not os.listdir(target_dir):
                    raise PcoccError("Not mounted yet")

            def atexit_umount():
                self._squash_fs_umount(target_dir, force=True)

            if self._run_with_patience(local_check_mounted, wait=0.5):
                raise PcoccError("squashfs mount failed")
            else:
                logging.debug("Squashfs image"
                              " for %s mounted at %s" % (squash_fs_image,
                                                         target_dir))
                # If mount succeeded register unmount atexit
                self.squashfs_atexit_umount = atexit_umount
                pcocc_at_exit.register(self.squashfs_atexit_umount)
        else:
            raise PcoccError("Could not locate 'squashfuse'"
                             "required to mount the container bundle.\n"
                             " you may consider disabling squashfs support "
                             "in the 'containers.yaml' configuration.")
        # done mounting
        return target_dir

    def _cont_add_to_cache(self,
                           image,
                           src_store,
                           meta,
                           cache_key,
                           create_op,
                           etype="DIR"):
        # Prepare to save inside image cache
        oci_bundle_dir = None

        img = Config().images

        # Make sure we have no conflict
        img.cache_delete(image, cache_key)

        with ContainerView(image, "oci") as oci_image:
            # Make sure to delete a previously failed image
            img.cache_delete(image, cache_key + "_tmp")
            if etype == "DIR":
                # Create in a temporary destination
                with img.cache_add_dir(image, cache_key + "_tmp") as cache_dir:
                    # Convert to bundle with Pcocc / Umoci / oci-image-tools
                    create_op(image, oci_image, cache_dir)
            elif etype == "FILE":
                # Create in a temporary destination
                cache_file = img.cache_new_blob(image, cache_key + "_tmp")
                create_op(image, oci_image, cache_file)
            else:
                raise PcoccError("No such cache type {}".format(etype))

            # If we are done we can rename the resulting blob
            img.cache_rename(image, cache_key + "_tmp", cache_key)

            oci_bundle_dir = img.cache_get(image,
                                           cache_key)

            # Return where the bundle is instanciated
            return oci_bundle_dir

    def _cont_squashfs_populate_systematic_mounts(self, rootfs):
        mountpoints = ["/etc/resolv.conf",
                       "/etc/group",
                       "/etc/passwd"]
        mountpoints += Config().containers.config.squashfs_image_mountpoints
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
            help_output = stdout + stderr
        except (subprocess.CalledProcessError, OSError):
            # Do not crash for reading the help
            pass
        return "-quiet" in help_output

    def _cont_create_bundle(self, kind="rootfs"):
        # Add to cache using squashfs
        def generate_squashfs_image(image, oci_image, cache_file):
            # Create a TMP directory in /dev/shm
            image_size = _compute_path_size(oci_image)
            tmp_bundle = _cont_get_tmp_directory(size=image_size)
            # Extract the OCI bundle in it

            def remove_tmp_bundle():
                chmod_rm(tmp_bundle)

            # Ensure cleanup using atexit
            pcocc_at_exit.register(remove_tmp_bundle)

            try:
                ContImage.oci_bundle(oci_image, tmp_bundle)
                # Invoke mksquashfs on it
                if not spawn.find_executable("mksquashfs"):
                    raise PcoccError("Could not locate 'mksquashfs'"
                                     " to extract the container")

                print("Generating squashfs image ...")

                rootfs = path_join(tmp_bundle, "rootfs")
                if os.path.exists(rootfs):
                    self._cont_squashfs_populate_systematic_mounts(rootfs)

                base_cmd = ["mksquashfs",
                            tmp_bundle,
                            cache_file.path,
                            "-noappend",
                            "-all-root",
                            # No need to compress
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
                            print(stdout + stderr)
                            raise subprocess.CalledProcessError(ret,
                                                                base_cmd)
                except (subprocess.CalledProcessError, OSError):
                    raise PcoccError("Failed to generate squashfs image")
            finally:
                remove_tmp_bundle()
                pcocc_at_exit.deregister(remove_tmp_bundle)

        # Add to cache using the bundle extraction method
        def extract_oci_bundle(image, oci_image, cache_dir):
            # Convert to bundle with Pcocc / Umoci / oci-image-tools
            ContImage.oci_bundle(oci_image, cache_dir.path)

        # Add to cache using external extraction tools
        def extract_oci_bundle_umoci(image, oci_image, cache_dir):
            try:
                if spawn.find_executable("umoci"):
                    subprocess.check_call(["umoci",
                                           "--log",
                                           "error",
                                           "unpack",
                                           "--rootless",
                                           "--image",
                                           oci_image,
                                           cache_dir])
                else:
                    # No bundle extraction tool found
                    raise PcoccError("Could not locate 'umoci'"
                                     " to extract the container")
            except subprocess.CalledProcessError as e:
                raise PcoccError("Failed to extract bundle " + str(e))

        if kind == "squashfs":
            # If squashfs is enabled try to export as squashfs
            return self._cont_add_to_cache(self.image,
                                           self.src_store,
                                           self.meta,
                                           "cached_squashfs",
                                           generate_squashfs_image,
                                           etype="FILE")
            # If the user wants to use regular bundles
            # we expect pcocc to be installed as such
            # and therefore we do not use extra logic to fallback

        #
        # "Regular" bundles
        #
        elif kind == "rootfs":
            # Add to cache using the bundle extraction method
            # using internal OCI driver
            try:
                return self._cont_add_to_cache(self.image,
                                               self.src_store,
                                               self.meta,
                                               "cached_bundle",
                                               extract_oci_bundle)
            except (PcoccError, subprocess.CalledProcessError):
                # Something went wrong
                pass

            # Attemp to add using UMOCI as external tool
            try:
                return self._cont_add_to_cache(self.image,
                                               self.src_store,
                                               self.meta,
                                               "cached_bundle",
                                               extract_oci_bundle_umoci)
            except PcoccError:
                raise PcoccError("Failed to extract OCI bundle using all"
                                 " methods you may have to install UMOCI")
        else:
            raise PcoccError("No such image kind {}".format(kind))


class ContImage(object):
    """Container Images manipulation routines."""

    known_container_image_formats = ["containers-storage", "dir", "docker",
                                     "docker-archive", "docker-daemon", "oci",
                                     "oci-archive", "ostree", "tarball",
                                     "simg", "pcocc-docker-daemon"]

    @classmethod
    def known_format(cls, ext):
        """Check if the image type is a container type.

        Arguments:
            ext {str} -- image type to be checked

        Raises:
            PcoccError -- image type is not a container type

        """
        if ext not in cls.known_container_image_formats:
            raise PcoccError("Container Image format not supported: " + ext)

    @staticmethod
    def oci_bundle(oci_image_dir, destination_dir):
        oci = OciImage(oci_image_dir)
        oci.load(checksig=False)
        oci.extract_bundle(destination_dir)

    @staticmethod
    def export(source_path, dst_fmt, dst_path, src_fmt="oci"):
        """Export a container image (from objectstore).

        Arguments:
            source_path {str} -- path in objectstore
            dst_fmt {str} -- output image format
            dst_path {str} -- output image file
            src_format {str} -- output image format (optionnal)

        """
        ContImage.convert(source_path,
                          dst_path,
                          src_fmt,
                          dst_fmt)

    @staticmethod

    def convert_singularity_to_oci(src_path):
        if not spawn.find_executable("unsquashfs"):
            # Stop early is squashfs-tools is not installed
            raise PcoccError("The 'unsquashfs' tool is required to extract "
                             " Singularity images")

        bundle_dest = tempfile.mkdtemp()

        if not os.path.isfile(src_path):
            raise PcoccError("Cannot access image file")

        # First check input type
        with open(src_path, 'rb') as f:
            magic = "#!/usr/bin/env run-singularity\nhsqs"
            header = f.read(len(magic))
            if header != magic:
                raise PcoccError("Unsuported Singularity image format")
            no_header_file = path_join(bundle_dest, "simg")
            with open(no_header_file, 'wb') as out:
                # Do not leave out the squashfs magic
                out.write("hsqs")
                while True:
                    buf = f.read(4096)
                    if buf:
                        out.write(buf)
                    else:
                        break

        # Now proceed to unsquashs the headerless image
        unsquash_cmd = ["unsquashfs", "-d", "rootfs", no_header_file]
        oldpwd = os.getcwd()
        os.chdir(bundle_dest)

        try:
            out = subprocess.check_output(unsquash_cmd)
        except subprocess.CalledProcessError:
            os.unlink(no_header_file)

        os.chdir(oldpwd)
        os.unlink(no_header_file)

        # Insert the "run" command
        singularity_run = """
#!/bin/sh

if test -f /environment
then
    . /environment
fi

if test -f /singularity
then
    /singularity
fi
"""
        sing_run_script = path_join(bundle_dest, "rootfs/singularity_run")
        with open(sing_run_script, 'w') as f:
            f.write(singularity_run)
        os.chmod(sing_run_script, 0o755)

        # Is now time to convert this to an OCI image
        temp_oci = tempfile.mkdtemp()
        oci = OciImage(temp_oci)

        cont = oci.new_container()
        cont.set_cmd(["/bin/sh", "/singularity_run"])
        oci.add_layer(cont, path_join(bundle_dest, "rootfs/"))
        oci.save()

        # We can now remove the bundle
        shutil.rmtree(bundle_dest)

        return temp_oci

    @staticmethod
    def skopeo_parse(path, fmt, docker, prefix='src-'):
        args = []
        if fmt == "pcocc-docker-daemon":
            fmt = "docker-daemon"
            try:
                vm_name, path = path.split('/', 1)
                vm_index = re.match(r'vm(\d+)$', vm_name).group(1)
            except Exception:
                raise PcoccError('Unable to parse image location')

            docker_host = docker.get_docker_host()
            cert = docker.cert_dir()

            args += ["--{}daemon-host".format(prefix), docker_host,
                     "--{}cert-dir".format(prefix), cert]

        return path, fmt, args

    @staticmethod
    def skopeo_convert(src_path,
                       dest_path,
                       src_fmt,
                       dst_format,
                       docker=None):

        src_path, src_fmt, args = ContImage.skopeo_parse(src_path, src_fmt, docker, 'src-')

        if not args:
            args = ["--src-tls-verify=false"]


        cmd = (["skopeo", "copy" ] + args +
               [src_fmt + ":" + src_path ] +
               [dst_format + ":" + dest_path + ":latest"])

        try:
            subprocess.call(cmd)
        except subprocess.CalledProcessError:
            os.unlink(dest_path)
            raise PcoccError("An error occured during container conversion")

    @staticmethod
    def pre_convert(src_path,
                    src_fmt,
                    tmp_path):

        did_convert = False
        dst_path = src_path
        if src_fmt == "simg":
            # Extract singularity images to an OCI bundle first so that OCI
            # compliant tools may manage it
            dst_path = os.path.join(tmp_path, 'simg')
            ContImage.convert_singularity_to_oci(src_path)
            src_fmt = "oci"
            did_convert = True

        return did_convert, dst_path, src_fmt

    @staticmethod
    def prepare_skopeo_cache(src_path,
                             src_fmt,
                             dst_path,
                             dst_store,
                             docker=None
                         ):

        src_path, src_fmt, args = ContImage.skopeo_parse(src_path, src_fmt, docker, '')

        cmd = ["skopeo", "inspect", "--tls-verify=false" ] + args + [src_fmt + ":" + src_path]

        # Check error messages readability
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

    @staticmethod
    def convert(src_path,
                dst_path,
                src_fmt,
                dst_format="oci",
                dst_store=None,
                docker=None):
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
        did_convert, src_path, src_fmt = ContImage.pre_convert(src_path,
                                                               src_fmt,
                                                               dst_path)

        ContImage.prepare_skopeo_cache(src_path,
                                       src_fmt,
                                       dst_path,
                                       dst_store,
                                       docker)

        ContImage.skopeo_convert(src_path,
                                 dst_path,
                                 src_fmt,
                                 dst_format,
                                 docker)

        if did_convert:
            shutil.rmtree(src_path)

        return dst_format

    @staticmethod
    def add_oci_image_to_repo(image_name,
                              dst_store,
                              oci_image):
        # First lets load the image
        oci = OciImage(oci_image)
        oci.load(checksig=True)

        oci_index = oci.index
        all_blobs = oci.blobs_resolve(add_path=True)

        for h, infos in all_blobs.items():
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

        return {key: value for key, value in meta.iteritems()
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

        if meta is None:
            return None, None

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
            print 'Rebasing snapshot to preserve chaining...'
            self.rebase(path, tgt_backing_file, False)

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
        return dst_store.put_meta(dst_name, revision, kind, [h], {})

    def import_image(self, src_path, dst_uri, src_fmt=None, docker=None):
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
                                                    src_fmt,
                                                    True)

        self.check_overwrite(dst_uri)

        image_blobs = []
        image_custom_meta = {}
        image_custom_meta["source_format"] = src_fmt

        click.secho("Storing image in repository '{0}' as '{1}' ... "
                    .format(dst_store.name,
                            dst_name))

        if kind == ImageType.vm:
            tmp_path = dst_store.tmp_file(ext=".qcow2")

            # VM images are stored in QCOW2 in pcocc repo
            image_custom_meta["target_format"] = "qcow2"

            try:
                VMImage.convert(src_path, tmp_path, src_fmt)
            except PcoccError as e:
                os.unlink(tmp_path)
                raise PcoccError("Failed to import {0} : {1}".format(src_path,
                                                                     str(e)))
            h = dst_store.put_data_blob(tmp_path)
            image_blobs = [h]
        elif kind == ImageType.cont:
            image_custom_meta["target_format"] = "oci"

            tmp_oci = dst_store.tmp_dir()
            def remove_tmp_oci():
                shutil.rmtree(tmp_oci)
            pcocc_at_exit.register(remove_tmp_path)
            try:
                ContImage.convert(src_path,
                                  tmp_oci,
                                  src_fmt,
                                  "oci",
                                  dst_store,
                                  docker=docker)

                # At this point tmp_oci contains an OCI image
                index, blobs = ContImage.add_oci_image_to_repo(dst_name,
                                                               dst_store,
                                                               tmp_oci)
                # At this points all blobs are saved
                image_blobs = [b["digest"] for b in blobs.values()]
                image_custom_meta["oci_index"] = index

            except PcoccError as e:
                raise PcoccError("Failed to import {0} : {1}".format(src_path,
                                                                     str(e)))
            finally:
                remove_tmp_path()
                # Regular cleanup done deregister from atexit
                pcocc_at_exit.deregister(remove_tmp_path)

        meta = dst_store.put_meta(dst_name, 0, kind.name, image_blobs,
                                  image_custom_meta)

        if kind == ImageType.cont:
            # If the image was a container we try to immediately
            # generate corresponding bundle for user-friendlyness
            with ContainerView(dst_name, "bundle") as bundle:
                logging.debug("Bundle generated in %s", bundle)

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

        dst_path, dst_fmt, guessed_kind = self.guess_format(dst,
                                                            dst_fmt)

        if guessed_kind != kind:
            raise PcoccError("Cannot export image of kind '{}'"
                             " to format '{}' of kind '{}'"
                             .format(kind.name,
                                     dst_fmt,
                                     guessed_kind.name))

        src_store = self.object_store.get_repo(meta["repo"])

        if kind == ImageType.vm:
            source_path = src_store.get_obj_path('data',
                                                 meta['data_blobs'][-1])
            VMImage.export(source_path, dst_fmt, dst_path)
        elif kind == ImageType.cont:
            # Just in case we store something else than OCI
            storage_format = meta["custom_meta"]["target_format"]

            if storage_format == "oci":
                # For OCI we need to rebuild an OCI view
                with ContainerView(src_uri, view_type="oci") as source_path:
                    ContImage.export(source_path,
                                     dst_fmt,
                                     dst_path,
                                     src_fmt=storage_format)
            else:
                # Get the blob directly
                source_path = src_store.get_obj_path('data',
                                                     meta['data_blobs'][-1])

                ContImage.export(source_path,
                                 dst_fmt,
                                 dst_path,
                                 src_fmt=storage_format)

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

        return dst_store.put_meta(dst_name, 0, src_meta["kind"],
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
        elif kind == ImageType.cont:
            ContImage.known_format(fmt)
        else:
            raise PcoccError("Container Image format not supported: " + fmt)

    def guess_format(self, path, fmt=None, allow_default=False):
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
        kind = ImageType.none

        if fmt:
            fmt = fmt.lower()
        else:
            # Check if the format was prefixed
            spl = path.split(":")
            if len(spl) >= 2:
                fmt = spl[0].lower()
                path = ":".join(spl[1:])
            else:
                # Or Suffixed
                fmt = os.path.splitext(path)[-1].lower().replace(".", "")

        kind = ImageType.infer_from_format(fmt)

        # For VMs we can detect the input file type
        # and validate the input arguments
        if os.path.exists(path) and kind == ImageType.vm:
            detect = VMImage.image_type(path)
            if fmt and fmt != detect:
                raise PcoccError("Mismatch between specified format {} "
                                 "and detected format {}"
                                 .format(fmt, detect))
            fmt = detect
            kind = ImageType.infer_from_format(fmt)

        # Default type fallback if allowed (only export)
        if not fmt:
            if allow_default and kind != ImageType.none:
                fmt = ImageType.default_format(kind)
            else:
                raise PcoccError("Could not infer format or image type for {} "
                                 "you may specify it with the '-t' option."
                                 .format(path))

        self.check_supported_format(kind, fmt)

        # Make sure to expand ~
        path = expanduser(path)

        return path, fmt, kind
