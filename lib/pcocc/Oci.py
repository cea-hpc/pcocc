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
from __future__ import division
import hashlib
import os
import shutil
import tempfile
import subprocess
import json
import binascii
import signal
import multiprocessing as mproc
from distutils import spawn
import threading
import re
import tarfile
import logging
import sys
import time
import six

from .Error import PcoccError
from .Misc import path_join


if six.PY2:
    import xtarfile

def human_size(size):
    for u in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if size < 1024.0:
            return "{} {}".format(size, u)
        size /= 1024.0
    return "{} EB".format(size)


class CompressedArchive(object):

    def __init__(self, path, output_dir, atype, size, layer_id):
        self.path = path
        self.layer_id = layer_id
        self.output_dir = output_dir
        self.atype = atype
        self.size = size
        if not os.path.isfile(self.path):
            raise PcoccError("Could not locate archive " + self.path)

    def _get_compress_program(self):
        if self.atype == 'tar':
            return None
        elif self.atype == 'tar+gzip':
            if spawn.find_executable("pigz"):
                return "pigz"
            else:
                return "gzip"
        else:
            raise PcoccError('Unsupported layer archive format')

    def _get_file_set(self, compress_program=None):
        cmd = ["tar"]
        if compress_program:
            cmd += ["--use-compress-program", compress_program]
        cmd += ["-tvf", self.path]
        ret = {"set": set(), "rights": {}}
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            # We now split to separate name and permisions
            dat = line.split(" ")
            rights = " ".join(dat[:-1])
            # Name without the newline
            name = dat[-1][:-1]
            ret["rights"][name] = rights
            # All files are part of the set
            ret["set"].add(name)
        self.number_of_files = len(ret["set"])
        return ret

    def file_set(self):
        compress_program = self._get_compress_program()
        return self._get_file_set(compress_program=compress_program)

    @staticmethod
    def extract_tar_elem_no_right(tar, elem, output_dir):
        if os.path.basename(elem.name).startswith(".wh."):
            return

        try:
            elem_path = path_join(output_dir, elem.name)

            if os.path.islink(elem_path):
                # Check for broken links
                # which cannot be overwriten
                if not os.path.exists(elem_path):
                    # This is a broken link delete before overwrite
                    os.unlink(elem_path)
            elif os.path.isdir(elem_path) and not elem.isdir():
                shutil.rmtree(elem_path)

            # Skip device files which we cannot currently extract
            if elem.ischr() or elem.isblk():
                pass
            else:
                tar.extract(elem, path=output_dir)

            if elem.isdir() or elem.isfile():
                os.chmod(elem_path, 0o700)
        except (OSError, IOError,) as e:
            logging.warning("Warning: could not extract "
                            "file '{}': {}".format(str(elem.name), str(e)))

    def extract_no_right(self):
        compress_program = self._get_compress_program()

        if compress_program:
            cmd = [compress_program, "-cdf", self.path]
            tar = tarfile.open(mode = "r|",
                               fileobj = subprocess.Popen(cmd,
                                                          stdout=subprocess.PIPE,
                                                          bufsize=65536).stdout)
        else:
            tar = tarfile.open(self.path)


        for elem in tar:
            self.extract_tar_elem_no_right(tar,
                                           elem,
                                           self.output_dir)
        tar.close()


class OciImageConfig(object):

    def __init__(self, arch="amd64", os="linux"):
        self.data = {"os": os, "architecture": arch}
        self.data["config"] = {}
        self.data["rootfs"] = {"type": "layers", "diff_ids": []}

    def load(self, oci, config_blob):
        self.data = oci.load_json_blob(config_blob)

    def gen_runtime_config(self):
        minimal_configjson = {"ociVersion": "0.1.0",
                              "root": {"path": "rootfs"}}

        # Now set the image params
        process = minimal_configjson.setdefault("process", {})

        # Cwd is required
        if self.cwd():
            process["cwd"] = self.cwd()
        else:
            process["cwd"] = "/"

        if self.env():
            process["env"] = self.env()

        if self.cmd():
            process["args"] = self.cmd()

        if self.entrypoint():
            # Entrypoint is not in OCI bundles !
            # it is present though in the OCI image
            process["entrypoint"] = self.entrypoint()

        return json.dumps(minimal_configjson)

    def _config_set(self, key, val):
        self.data["config"][key] = val

    def _config_get(self, key):
        if key in self.data["config"]:
            return self.data["config"][key]
        else:
            return None

    def cwd(self):
        return self._config_get("WorkingDir")

    def entrypoint(self):
        return self._config_get("Entrypoint")

    def cmd(self):
        return self._config_get("Cmd")

    def env(self):
        return self._config_get("Env")

    def set_cwd(self, cwd):
        self._config_set("WorkingDir", cwd)

    def set_entrypoint(self, cmd):
        self._config_set("Entrypoint", cmd)

    def set_cmd(self, cmd):
        self._config_set("Cmd", cmd)

    def set_env(self, env):
        self._config_set("Env", env)

    def append_diff_layer(self, diff_id):
        self.data["rootfs"]["diff_ids"].append("sha256:" + diff_id)

    def save(self, oci):
        digest, length = oci.register_blob(json.dumps(self.data))
        return {"mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:" + digest,
                "size": length}


flist_lock = threading.Lock()


def call_flist(archive):
    ret = {"archive": archive, "content": archive.file_set()}
    with flist_lock:
        print("\033[2KDONE layer contains {}"
              " files".format(len(ret["content"]["set"])))
    return ret


def call_extract(archive):
    archive.extract_no_right()
    with flist_lock:
        print("\t- layer {} has been extracted".format(archive.layer_id))


def set_file_rights(entry):
    try:
        os.chmod(entry["path"], entry["rights"])
    except OSError:
        pass


def rm_wh_file(path):
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)
    except OSError:
        logging.debug("Could not whiteout '%s'" % path)


class OciManifest(object):
    def __init__(self, arch="amd64", os="linux", label="latest"):
        self.arch = arch
        self.os = os
        self.label = label
        self.config = OciImageConfig(arch, os)
        self.data = {"schemaVersion": 2,
                     "config": {},
                     "layers": []}

    @property
    def blobs(self):
        ret = []
        ret = ret + self.data["layers"]
        if "digest" in self.data["config"]:
            ret.append(self.data["config"])
        return ret

    def validate(self, oci, check_digest=False):
        for l in self.data["layers"]:
            if "digest" not in l:
                raise PcoccError("No digest in layer"
                                 " '{}'".format(json.dumps(l)))
            esize = None
            if "size" in l:
                esize = int(l["size"])
            oci.check_blob(l["digest"], esize=esize, check_digest=check_digest)

    def _get_archive_list(self, oci, output_dir):
        archives = []
        for i in range(0, len(self.data["layers"])):
            layer = self.data["layers"][i]
            path = oci.get_blob_path(layer["digest"])
            atype = layer["mediaType"].split('.')[-1]
            size = layer["size"]
            archives.append(CompressedArchive(path, output_dir, atype, size, i))
        return archives

    def _get_file_sets(self, archives):
        # Handle interrupt with pools

        cpucount = mproc.cpu_count()
        worker = cpucount if cpucount < len(archives) else len(archives)
        log = ["Listing files in layer {}/{} ...".format(i, len(archives))
               for i in range(1, len(archives) + 1)]
        log = "\n".join(log)
        print(log)
        print("\033[F" * (len(archives) + 1))

        original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        p = mproc.Pool(processes=worker)
        signal.signal(signal.SIGINT, original_sigint_handler)
        try:
            result = p.map_async(call_flist, archives)
            result = result.get(timeout=1000000)
        except KeyboardInterrupt:
            p.terminate()
            raise PcoccError("Interrupted")

        p.close()
        p.join()

        print("\033[F\033[2K" * len(archives))
        print("Listed files for {} layers".format(len(archives)))

        return result

    @classmethod
    def _normalize_path(cls, path):
        if path[-1] == '/':
            path = path[:-1]
        return path

    @classmethod
    def _set_file_state(cls, path, state_dict, visible=False):
        state_dict[cls._normalize_path(path)] = visible

    @classmethod
    def _is_in_dir(cls, path, directory):
        return (path).startswith(directory + os.sep)

    @classmethod
    def _set_dir_state(cls, directory, state_dict, visible=False):
        directory = cls._normalize_path(directory)
        for f, _ in state_dict.items():
            if cls._is_in_dir(f, directory) and f != directory:
                state_dict[f] = visible

    def _compute_whiteouts(self, file_sets, output_dir):
        """Returns the list of files that should be removed from the rootfs
        due to whiteouts"""
        state_dict = {}
        opaque_wh_list = [".wh..wh..opq"]

        for i in range(0, len(file_sets)):
            fset = file_sets[i]

            for f in fset["content"]["set"]:
                dirname = os.path.dirname(f)
                basename = os.path.basename(f)

                if basename.startswith(".wh."):
                    if basename in opaque_wh_list:
                        self._set_dir_state(dirname, state_dict, visible=False)
                    else:
                        target_file = os.path.join(dirname, basename[4:])
                        self._set_file_state(target_file, state_dict, visible=False)

                dirname = os.path.dirname(f)
                basename = os.path.basename(f)

            for f in fset["content"]["set"]:
                if not f.startswith(".wh."):
                    self._set_file_state(f, state_dict, visible=True)

        return [path_join(output_dir, k) for (k, v) in state_dict.items()
                if not v]

    def _delta_groups(self, file_sets, no_strict_ts=True):
        # It is now time to compute parallel buckets
        # for extraction by making sure that content do not intersect
        # in each group
        # First reorder by layer ID to ensure correct layering
        file_sets.sort(key=lambda x: x["archive"].layer_id)

        seen_files = set()
        seen_rights = {}
        group_list = []
        current_group = []
        for fset in file_sets:
            inter = seen_files.intersection(fset["content"]["set"])
            new_group = False

            if inter:
                new_group = True
                # Make sure we are not only considering directories
                # which have the same right
                to_delete = []
                right_re = r"[0-9]+-[0-9]+-[0-9]+ [0-9]+:[0-9]+"
                for e in inter:
                    if e.endswith("/"):
                        new_rights = fset["content"]["rights"][e]
                        if e in seen_rights:
                            old_rights = seen_rights[e]
                            if no_strict_ts:
                                # Remove TS informations if asked for
                                new_rights = re.sub(right_re,
                                                    "TS",
                                                    new_rights)
                                old_rights = re.sub(right_re,
                                                    "TS",
                                                    old_rights)
                            if new_rights == old_rights:
                                # This elemen can be ignored
                                to_delete.append(e)
                # We delete now after iterating elements
                for e in to_delete:
                    inter.remove(e)
                # Did we remove all elements ?
                if len(inter) == 0:
                    new_group = False

            if new_group:
                group_list.append(current_group)
                current_group = [fset["archive"]]
                seen_files = fset["content"]["set"]
                seen_rights.update(fset["content"]["rights"])
            else:
                current_group.append(fset["archive"])
                seen_files.update(fset["content"]["set"])
                seen_rights.update(fset["content"]["rights"])

        group_list.append(current_group)
        return group_list, seen_rights

    def _parse_right(self, txtright):
        bin_rep = "0"
        for e in txtright[1:]:
            if e != "-":
                bin_rep += "1"
            else:
                bin_rep += "0"
        return int(bin_rep, base=2)

    def extract_rootfs(self, oci, output_dir, no_strict_ts=True):
        # Initialize archive on each layer
        archives = self._get_archive_list(oci, output_dir)
        # Retrieve file lists inside layers
        file_sets = self._get_file_sets(archives)
        # Generate delta groups
        group_list, file_rights = self._delta_groups(file_sets,
                                                     no_strict_ts=no_strict_ts)

        paral = max([len(e) for e in group_list])
        print("Maximum layer extraction parallelism is {}".format(paral))

        # Create out dir if needed before parallel extraction
        if not os.path.isdir(output_dir):
            os.mkdir(output_dir)

        original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        # Start parallel extraction
        p = mproc.pool.ThreadPool(processes=4)
        signal.signal(signal.SIGINT, original_sigint_handler)

        for i in range(0, len(group_list)):
            group = group_list[i]
            total_size = sum([a.size for a in group])
            print("Extracting layer group {}/{} "
                  "(size {}) ...".format(i + 1,
                                         len(group_list),
                                         human_size(total_size)))
            try:
                r = p.map_async(call_extract, group)
                r.wait(timeout=1000000)
            except KeyboardInterrupt:
                p.terminate()
                raise PcoccError("Interrupted")

        # Make mode path absolute and parse them
        new_rights = []
        for archive_path, rights in file_rights.items():
            abs_path = path_join(output_dir, archive_path)
            txt_rights = rights.split(" ")[0]
            new_rights.append({"path": abs_path,
                               "rights": self._parse_right(txt_rights)})

        try:
            r = p.map_async(set_file_rights, new_rights, chunksize=128)
            r.wait(timeout=1000000)
        except KeyboardInterrupt:
            p.terminate()
            raise PcoccError("Interrupted")


        # We now process whiteout files
        wh = self._compute_whiteouts(file_sets, output_dir)
        try:
            r = p.map_async(rm_wh_file, wh)
            r.wait(timeout=1000000)
        except KeyboardInterrupt:
            p.terminate()
            raise PcoccError("Interrupted")

        p.close()
        p.join()

    def extract_bundle(self, oci, output_dir, no_strict_ts=True):
        print("Generating OCI bundle ... ")
        if not os.path.isdir(output_dir):
            os.mkdir(output_dir)

        rootfs = path_join(output_dir, "rootfs/")
        self.extract_rootfs(oci, rootfs, no_strict_ts=no_strict_ts)

        config = self.config.gen_runtime_config()
        with open(path_join(output_dir, "config.json"), "w") as f:
            f.write(config)

    def load(self, oci, manifest_blob):
        self.data = oci.load_json_blob(manifest_blob)
        if "config" not in self.data:
            raise PcoccError("No config in Image Manifest")
        self.config.load(oci, self.data["config"]["digest"])

    def add_layer(self, diff_id, mediatype, digest, size):
        self.config.append_diff_layer(diff_id)
        self.data["layers"].append({"mediaType": mediatype,
                                    "digest": digest,
                                    "size": size})

    def set_entrypoint(self, entrypoint):
        self.config.set_entrypoint(entrypoint)

    def set_cmd(self, cmd):
        self.config.set_cmd(cmd)

    def set_cwd(self, cwd):
        self.config.set_cwd(cwd)

    def set_env(self, env):
        self.config.set_env(env)

    def save(self, oci):
        self.data["config"] = self.config.save(oci)
        digest, length = oci.register_blob(json.dumps(self.data))
        ret = {"mediaType": "application/vnd.oci.image.manifest.v1+json",
               "digest": "sha256:" + digest,
               "size": length,
               "platform": {
                            "architecture": self.arch,
                            "os": self.os}
               }
        if self.label:
            ret["annotations"] = {"org.opencontainers.image.ref.name":
                                  self.label}
        return ret


class OciBlobs(object):
    def __init__(self):
        pass

    def split_blob_id(self, blob_id):
        sp = blob_id.split(":")
        if len(sp) != 2:
            raise PcoccError("Bad blob hash expected TYPE:HASH")
        alg = sp[0]
        h = sp[1]
        return alg, h

    def get_blob_path(self, blob_id):
        raise NotImplementedError()

    def put_blob(self, alg, digest, path, symlink=False):
        raise NotImplementedError()

    def mirror(self, blob_id, src_path):
        raise NotImplementedError()

    def validate(self):
        raise NotImplementedError()

    @property
    def index(self):
        raise NotImplementedError()

    def register_file(self, path):
        digest, filelen = self.shasum_file(path)
        self.put_blob("sha256", digest, path)
        return digest, filelen

    def register_blob(self, data):
        d = hashlib.sha256()
        d.update(data)
        digest = d.hexdigest()

        path = tempfile.mktemp()

        with open(path, 'w') as fd:
            fd.write(data)

        self.put_blob("sha256", digest, path)
        os.unlink(path)

        return digest, len(data)

    def checksum_file(self, path, alg="sha256"):
        if alg == "sha256":
            return self.shasum_file(path)
        else:
            raise PcoccError("Checksum algorithm {} is not implemented".format(alg))

    def shasum_file(self, path):
        d = hashlib.sha256()
        filelen = 0
        with open(path, 'rb') as f:
            b = f.read(65536)
            while len(b) > 0:
                filelen += len(b)
                d.update(b)
                b = f.read(65536)
        digest = d.hexdigest()
        return digest, filelen

    def load_json_blob(self, blob_id):
        bpath = self.get_blob_path(blob_id)

        with open(bpath, 'r') as f:
            ret = json.load(f)
        return ret

    def check_blob(self, blob_id, esize=None, check_digest=False):
        alg, h = self.split_blob_id(blob_id)
        bpath = self.get_blob_path(blob_id)

        if not os.path.isfile(bpath):
            raise PcoccError("Could not locate blob " + h)

        print("\033[2KChecking blob {} ...".format(h))

        oneup = "\033[2K\033[F"
        up = oneup

        if esize:
            fsize = os.stat(bpath).st_size
            if fsize != esize:
                raise PcoccError("Blob size mistmatch "
                                 " {} instead of {} for '{}'".format(fsize,
                                                                     esize,
                                                                     h))
            else:
                print("\tSize OK ({})".format(human_size(fsize)))
                up += oneup
        if check_digest:
            print("\tChecking digest ...")
            digest, _ = self.checksum_file(bpath, alg=alg)
            if digest != h:
                raise PcoccError("Digest mismatch"
                                 " for '{}'({}) had '{}'".format(h,
                                                                 alg,
                                                                 digest))
            else:
                print("\033[2K\033[F\tDigest OK")
                up += oneup
        print(up)
        print("\033[F\033[2K\033[F")


class OciFileBlobs(OciBlobs):
    def __init__(self, oci_image_path):
        if oci_image_path is None:
            raise PcoccError("No path provided for OCI image")
        super(OciFileBlobs, self).__init__()
        self.oci_image = oci_image_path
        self.blobdir = path_join(oci_image_path, "blobs")
        self._try_makedirs(self.blobdir)

    def validate(self):
        if not os.path.isfile(path_join(self.oci_image, "index.json")):
            raise PcoccError("Could not locate 'index.json'")
        # Check OCI layout
        if not os.path.isfile(path_join(self.oci_image, "oci-layout")):
            raise PcoccError("Could not locate 'oci-layout'")
        with open(path_join(self.oci_image, "oci-layout"), 'r') as f:
            layout = json.load(f)
            if "imageLayoutVersion" not in layout:
                raise PcoccError("Could not validate 'oci-layout'")
            layoutv = layout["imageLayoutVersion"]
            if layoutv != "1.0.0":
                raise PcoccError("Unsuported image layout"
                                 " '{}' expected '1.0.0'".format(layoutv))

    def mirror(self, blob_id, src_path):
        alg, h = self.split_blob_id(blob_id)
        self.put_blob(alg, h, src_path, symlink=True)

    def set_index(self, data):
        # Create the OCI layout file
        layout = '{"imageLayoutVersion": "1.0.0"}'
        with open(path_join(self.oci_image, "oci-layout"), 'w') as f:
            f.write(layout)
        with open(path_join(self.oci_image, "index.json"), 'w') as f:
            f.write(json.dumps(data))

    @property
    def index(self):
        self.validate()
        with open(path_join(self.oci_image, "index.json"), 'r') as f:
            data = json.load(f)
        return data

    def get_blob_path(self, blob_id):
        alg, h = self.split_blob_id(blob_id)
        return path_join(self.oci_image, "blobs", alg, h)

    def put_blob(self, alg, digest, path, symlink=False):
        self._try_makedirs(path_join(self.blobdir, alg))
        if symlink:
            os.symlink(path, path_join(self.blobdir, alg, digest))
        else:
            shutil.copy(path, path_join(self.blobdir, alg, digest))

    def _try_makedirs(self, path):
        try:
            os.makedirs(path)
        except os.error:
            pass

class OciRepoBlobs(OciBlobs):
    def __init__(self, repo, meta):
        if meta is None:
            raise PcoccError("No meta provided for OCI image")
        super(OciRepoBlobs, self).__init__()
        self.repo = repo
        self.meta = meta

    def validate(self):
        pass

    def set_index(self, data):
        raise PcoccError("cannot set index REPO "
                         "container images are read-only")

    @property
    def index(self):
        if "oci_index" not in self.meta["custom_meta"]:
            raise PcoccError("Could not locate index in meta")
        return self.meta["custom_meta"]["oci_index"]

    def get_blob_path(self, blob_id):
        return self.repo.get_obj_path("data", blob_id, check_exists=True)

    def put_blob(self, alg, digest, path, symlink=False):
        self.repo.put_data_blob(self, path, known_hash=digest)


class OciImage(object):

    def __init__(self, oci_image_dir=None, oci_blobs_iface=None):
        if oci_blobs_iface is None:
            # By default we assume we read a directory
            self.oci = OciFileBlobs(oci_image_dir)
        else:
            self.oci = oci_blobs_iface
        self._conts = []
        self.data = {"schemaVersion": 2,
                     "manifests": []}

    @property
    def containers(self):
        return self._conts

    @property
    def index(self):
        return self.data

    @property
    def blobs(self):
        ret = []
        for m in self.data["manifests"]:
            ret.append(m)
        for c in self._conts:
            ret = ret + c.blobs
        return ret

    def blobs_resolve(self, add_path=False):
        ret = {}
        all_blobs = self.blobs
        for blob_id in all_blobs:
            digest = blob_id["digest"]
            if add_path:
                path = self.oci.get_blob_path(digest)
                blob_id["path"] = path
            ret[digest] = blob_id
        return ret

    @property
    def manifests(self):
        return self.data["manifests"]

    def _manifest_to_cont(self, manifest):
        index = self.data["manifests"].index(manifest)
        return self._conts[index]

    def extract_bundle(self, output_dir, os="linux", arch="amd64"):
        for c in self._conts:
            if ((c.os == os) and
               (c.arch == arch)):
                # Bundle found proceed to extraction
                return c.extract_bundle(self.oci, output_dir)
        raise PcoccError("Could not locate an image "
                         " for os={} and arch={}".format(os, arch))

    def load(self, check_digest=False):
        self.data = self.oci.index
        for cont in self.data["manifests"]:
            if cont["mediaType"] != "application/vnd.oci.image.manifest.v1+json":
                continue

            label = None
            if "annotations" in cont:
                if "org.opencontainers.image.ref.name" in cont["annotations"]:
                    annotations = cont["annotations"]
                    label = annotations["org.opencontainers.image.ref.name"]
            nc = self.new_container(arch=cont["platform"]["architecture"],
                                    os=cont["platform"]["os"],
                                    label=label)
            nc.load(self.oci, cont["digest"])
            nc.validate(self.oci, check_digest=check_digest)

    def new_container(self, arch="amd64", os="linux", label="latest"):
        nc = OciManifest(arch, os, label)
        self._conts.append(nc)
        return nc

    def _run_cmd(self, cmd):
        out = ""
        try:
            out = subprocess.check_output(cmd)
        except subprocess.CalledProcessError as e:
            print(out)
            raise e

    def add_layer(self, container, rootfs):
        # Tar the directory content
        tmp = tempfile.mktemp()
        cmd = ["tar", "cf", tmp, "-C", rootfs, "."]
        self._run_cmd(cmd)
        # Generate the diffID
        diffid, _ = self.oci.shasum_file(tmp)

        # And now gzip the layer (gzip removes the tar)
        cmd = ["gzip", tmp]
        self._run_cmd(cmd)

        gziped_file = tmp + ".gz"

        if not os.path.isfile(gziped_file):
            raise PcoccError("Failed to compress layer")

        # Add to blobs
        digest, length = self.oci.register_file(gziped_file)
        os.unlink(gziped_file)
        # Now add to target container
        container.add_layer(diffid,
                            "application/vnd.oci.image.layer.v1.tar+gzip",
                            "sha256:" + digest,
                            length)

    def mirror(self, target_dir):
        all_blobs = self.blobs_resolve(add_path=True)
        oci_dir = OciFileBlobs(target_dir)

        for k, data in all_blobs.items():
            oci_dir.mirror(k, data["path"])
        oci_dir.set_index(self.data)

    def save(self):
        for cont in self._conts:
            manifest = cont.save(self.oci)
            self.data["manifests"].append(manifest)
        self.oci.set_index(self.data)
