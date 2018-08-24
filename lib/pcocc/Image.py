
import logging
import os
import stat
import subprocess
import sys
import ObjectStore
from Error import PcoccError, InvalidConfigurationError
import tempfile
import yaml
import json
import errno
import re
from Config import DEFAULT_CONF_DIR, DEFAULT_USER_CONF_DIR, Config

known_vm_image_formats = ["raw", "qcow2", "qed", "vdi", "vpc", "vmdk"]

def check_qemu_image_ext(ext):
    if ext not in known_vm_image_formats:
        raise PcoccError("VM Image format not supported: " + ext)
    return True

known_container_image_formats = ["containers-storage", "dir", "docker",
                                 "docker-archive", "docker-daemon", "oci",
                                 "oci-archive", "ostree", "tarball"]

def check_container_image_ext(ext):
    if ext not in known_container_image_formats:
        raise PcoccError("Container Image format not supported: " + ext)
    return True


def convert(src, dest, overwrite=False, quiet=True, src_type=None):
    src = os.path.abspath(src)
    dest = os.path.abspath(dest)

    if not os.path.isfile(src):
        raise PcoccError("No such file " + src)

    if os.path.isfile(dest) and (overwrite is False):
        raise PcoccError(
            "Would overwrite "
            + dest
            + " set overwrite to true if you want to do so")

    if not src_type:
        src_ext = os.path.splitext(src)[-1].lower().replace(".", "")

        if src_ext == "":
            src_ext = "qcow2"
    else:
        src_ext=src_type

    check_qemu_image_ext(src_ext)

    dest_ext = os.path.splitext(dest)[-1].lower().replace(".", "")

    if dest_ext == "":
        dest_ext = "qcow2"

    check_qemu_image_ext(dest_ext)

    try:
        if not quiet:
            sys.stderr.write(
                "Convert '{0}'\n     to '{1}'... "
                .format(src, dest))

        subprocess.check_output(
            ["qemu-img",
             "convert",
             "-p",
             "-f", src_ext,
             "-O", dest_ext,
             src,
             dest],
            stderr=subprocess.STDOUT,
            shell=False)
        if not quiet:
            sys.stderr.write("OK\n")
    except subprocess.CalledProcessError, e:
        raise PcoccError("ERROR:" +
                        "****** qemu-img output ******\n" +
                        e.output +
                        "*****************************\n")


def create(path, size="1M", iformat="qcow2", quiet=True):
    path = os.path.abspath(path)
    check_qemu_image_ext(iformat)

    try:
        if not quiet:
            sys.stderr.write(
                "Creating image '{0}' format '{1}' size '{2}'... "
                .format(path, iformat, size))
        subprocess.check_output(
            ["qemu-img",
             "create",
             "-f", iformat,
             path,
             size],
            stderr=subprocess.STDOUT,
            shell=False)
        if not quiet:
            sys.stderr.write("OK\n")
    except subprocess.CalledProcessError, e:
        raise PcoccError("ERROR:" +
                        "****** qemu-img output ******\n" +
                        e.output +
                        "*****************************\n")


class ImageRepoConfig(object):

    def __init__(self):
        self.local = []
        self.glob = []
        self.object_store = ObjectStore.ObjectStore()

    def load(self, repo_file, user_level=False):
        try:
            stream = file(repo_file, 'r')
            repo_config = yaml.load(stream)
        except IOError as err:
            if user_level == False or err.errno != errno.ENOENT:
                raise InvalidConfigurationError(str(err))
            else:
                return
        except Exception as err:
            raise InvalidConfigurationError(str(err))

        # There should be a repo list if we get a file
        if not "repos" in repo_config:
            raise InvalidConfigurationError("Could not find a 'repos' key in configuration")

        if type(repo_config["repos"]) != type([]):
            raise InvalidConfigurationError("The 'repos' key must be an array")

        # Now inspect the configuration
        if user_level:
            # Save in local config
            self.local = repo_config["repos"]
            # We need to populate the REPO env variable
            # for dynamically inserted repos
        else:
            #This is the system-wide list
            # Just store the array
            self.glob = repo_config["repos"]

        #It is not time to update repolist
        self.object_store.set_repo_list(self.get_list())

    def get_list(self):
        return self.local + self.glob

    def get_local(self):
        return self.local[:]

    def get_global(self):
        return self.glob[:]

    def save(self):
        out = {}
        out["repos"] = self.local
        user_config = Config().resolve_path(os.path.join(DEFAULT_USER_CONF_DIR, 'repos.yaml'))
        with open(user_config, 'w') as outfile:
            yaml.dump(out, outfile)

    def remove_local(self, value):
        try:
            idx = self.local.index(value)
            # Delete it
            del self.local[idx]
            # Save the new config
            self.save()
        except ValueError:
            # Might have tried to delete a global repo
            glob_found = len([i for i in self.glob if (value == self.object_store._unfoldpath(i))])
            if glob_found:
                raise PcoccError("'{0}' is in a global repository and".format(value)
                                +" cannot be removed from CLI")

            raise PcoccError("No such entry '{0}' in local repositories".format(value))

    def add_local(self, value):
        # First make sure it could be a valid repo
        # before pushin it to the config and getting
        # the same error later on
        abspath = os.path.abspath(value)
        path = os.path.dirname(abspath)

        # Is it already in the list ?
        try:
            self.local.index(abspath)
            raise PcoccError("{0} is already ub the local repository list".format(abspath))
        except ValueError:
            pass

        # Parent path exists
        try:
            mode = os.stat(path).st_mode
            # It is a directory
            if not stat.S_ISDIR(mode):
                raise PcoccError("A pccocc repository must be located"\
                                +" in a directory (check {0})".format(path))
        except os.error as e:
            raise PcoccError(str(e))

        try:
            mode = os.stat(abspath).st_mode
            # If path exists make sure it is a directory
            if not stat.S_ISDIR(mode):
                raise PcoccError("A pccocc repository must a directory (check {0})".format(abspath))
        except os.error as e:
            # Repo path do not exists make sure parent is writable
            if not os.access(path, os.W_OK):
                raise PcoccError("Parent directory for {0} is not writable".format(abspath)
                                +" cannot create pcocc repository")
            # If we are here the ObjectStore will create the directory

        # We passed all the checks lets now add a repo
        self.local.append(abspath)
        # And save the config
        self.save()
        # Also save to environ for immediate effect
        self.object_store.set_repo_list(self.get_list())


class PcoccImage(object):

    def __init__(self):
        self.object_store = Config().repos.object_store


    def _tempfile(self, ext):
        fd, path = tempfile.mkstemp(suffix=ext)
        os.close(fd)
        return path

    def image_descriptor_parse(self, image_descriptor):
        repo=""
        image_name=""
        # First extract reponame from the descriptor
        s = image_descriptor.split(":")
        if len(s) == 1:
            repo = ""
            image_name = image_descriptor
        else:
            repo = s[0]
            image_name = s[1]
        return image_name, repo

    def reloadconfig(self):
        self.object_store.reloadconfig()

    def find(self, regexpr, repo=""):
        val_list = self.object_store.listval(repo)
        try:
            search = re.compile(regexpr)
        except re.error as e:
            raise PcoccError("Could not parse regular expression :%s" % str(e))

        def filter_by_key(entry):
            return search.match(entry["key"])

        return filter(filter_by_key, val_list)

    def get_by_name(self, image_descriptor):
        """
        Get a pcocc image from repository by name
        Returns:
            string -- Path to the image with this name
        """
        image_name, repo = self.image_descriptor_parse(image_descriptor)

        logging.info("pcocc repo : Locating %s in %s" % (image_name, repo))

        try:
            path, meta = self.object_store.getval(image_name, repo_name=repo)
            return path, meta
        except:
            return None, None

    def get_type_from_meta(self, meta_data):
        if "metadata" in meta_data:
            if "type" in meta_data["metadata"]:
                return meta_data["metadata"]["type"]
        return None


    def image_infos(self, image_descriptor):
        # Get the image and its meta-data
        src_file, src_meta = self.get_by_name(image_descriptor)

        if not src_file:
            raise PcoccError("No such image '{0}'".format(image_descriptor))

        # Enrich with Skopeo when possible
        if src_meta:
            if "metadata" in src_meta:
                if self.get_type_from_meta(src_meta) == "cont":
                    #Proceed to extract container infos
                    cmd = ["skopeo", "inspect", "oci-archive:" + src_file]

                    try:
                        result = subprocess.check_output(cmd)
                        info = json.loads(result)
                        #If we get someting JSON-y
                        src_meta["metadata"]["skopeo"] = info
                    except:
                        pass

        return src_meta


    def delete_image(self, image_descriptor):
        image_name, repo = self.image_descriptor_parse(image_descriptor)

        if repo == "":
            raise PcoccError("Cannot delete an image which is not fully"
                            +" described (use complete image descriptor REPO:IMAGENAME)")

        try:
            self.object_store.delval(image_name, repo_name=repo)
        except:
            raise PcoccError("No such image '{0}' in repository '{1}'".format(image_name, repo))

    def check_image_type(self, itype, src_ext):
        if itype == "vm":
            if not check_qemu_image_ext(src_ext):
                raise PcoccError("Imported type '{0}' does not match VM type".format(src_ext))
        elif itype == "cont":
            if not check_container_image_ext( src_ext ):
                raise PcoccError("Imported type '{0}' does not".format(src_ext)
                                +" match CONTAINER type")
        else:
            raise PcoccError("Image type {0} not recognized make sure".format(src_ext)
                            +" your file has the proper extension")

    def extract_extension(self, in_path):
        try:
            src_ext = os.path.splitext(in_path)[-1].lower().replace(".", "")
        except:
            raise PcoccError("Could not infer image type through"\
                            +" extension you may rely on direct tagging 'type:path'")
        return src_ext

    def get_vm_type(self, path):
        try:
            jsdata = subprocess.check_output(["qemu-img", "info","--output=json", path])
            data = json.loads(jsdata)
            if "format" in data:
                return data["format"]
            else:
                return None
        except:
            return None

    def import_image(self, in_path, key, itype="vm", dest_repo="", img_type=None, force=False):
        src_ext = None
        # Fist extract input file type
        if img_type:
            #Type was given explicitly
            src_ext = img_type
        else:
            #If no type given and is a VM try whith qemu-img info
            if itype == "vm":
                src_ext = self.get_vm_type(in_path)

            if src_ext is None:
                #Type is given by prefix
                spl = in_path.split(":")

                if len(spl) == 1:
                    in_path = in_path
                    src_ext = self.extract_extension(in_path)
                elif 2 <= len(spl):
                    src_ext = spl[0]
                    in_path = ":".join(spl[1:])

        self.check_image_type(itype, src_ext)

        # Now check if image exists or shadows and force is passed

        dst_file, dst_meta = self.get_by_name(key)

        if dst_file:
            if not force:
                raise PcoccError("'{0}' image is already present in '{1}' you"
                                .format(key, dst_meta["repo"])
                                +" may use '-f/--force' to overwrite or shadow existing image")

        # Now handle import according to types

        used_tmp=False
        tmp = ""
        # Save before possible convert/import override
        input_path=in_path
        if itype == "vm":
            if src_ext != "qcow2":
                # The source needs conversion
                tmp = self._tempfile(ext=".qcow2")
                try:
                    # Convert to qcow2
                    sys.stderr.write("Converting image to QCOW2 ... ")
                    convert(in_path, tmp, overwrite=True, src_type=src_ext)
                    sys.stderr.write("DONE\n")
                except Exception as e:
                    os.unlink(tmp)
                    raise PcoccError("Failed to import {0} : {1}".format(in_path, str(e)))
                used_tmp=True
                in_path = tmp

        elif itype == "cont":
            # Create temp storage
            tmp = self._tempfile(ext=".tar.gz")
            used_tmp=True
            # Here we directly use skopeo to copy to an OCI tarball
            # and pcocc accepts the skopeo subtypes
            cmd = ["skopeo", "copy", src_ext + ":" + in_path,  "oci-archive:" + tmp + ":latest"]

            def import_error():
                os.unlink(tmp)
                raise PcoccError("An error occured when importing"
                                +" container image see previous logs.")

            try:
                ret = subprocess.call(cmd)
            except subprocess.CalledProcessError:
                import_error()

            if ret != 0:
                import_error()

            in_path=tmp
        else:
            raise PcoccError("No such image type %s" % itype)

        # Save meta-data
        meta = {}

        meta["type"] = itype
        meta["source_type"] = src_ext
        meta["source"] = input_path

        # Set in KVS
        sys.stderr.write("Storing image in repository as '{0}' ... ".format(key))
        self.object_store.setval( key, in_path, meta_data=meta, repo_name=dest_repo)
        sys.stderr.write("DONE\n")

        # Remove TMP if needed
        if used_tmp:
            os.unlink(tmp)


    def export_image(self, descriptor, out_path, img_type=None, silent=False):
        in_path, meta = self.get_by_name(descriptor)

        if not in_path:
            raise PcoccError("Could not find image {0}".format(descriptor))

        # Fist extract input file type
        if img_type:
            #Type was given explicitly
            targ_ext = img_type
        else:
            #Type is given by prefix
            spl = out_path.split(":")

            if len(spl) == 1:
                out_path = out_path
                targ_ext = self.extract_extension(out_path)
            elif 2 <= len(spl):
                targ_ext = spl[0]
                out_path = ":".join(spl[1:])

        itype = self.get_type_from_meta(meta)

        self.check_image_type(itype, targ_ext)

        if itype == "vm":
            sys.stderr.write("Exporting image '{0}' to '{1}' in '{2}' format ... "
                             .format(descriptor, out_path, targ_ext))
            convert(in_path, out_path, overwrite=True)
            sys.stderr.write("DONE\n")
        elif itype == "cont":
            # Here we directly use skopeo to copy from an OCI tarball to the target type
            cmd = ["skopeo", "copy",  "oci-archive:" + in_path,
                   targ_ext + ":" + out_path + ":latest"]

            def export_error():
                raise PcoccError("An error occured when exporting"
                                +" container image see previous logs.")

            try:
                if silent:
                    with open("/dev/null", "w") as dn:
                        subprocess.check_call(cmd, stdout=dn)
                else:
                    subprocess.check_call(cmd)
            except subprocess.CalledProcessError:
                export_error()

        else:
            raise PcoccError("No such image type %s" % itype)


    def move_image(self, source_descriptor, target_descriptor, force=False ):
        # Check source
        src_name, _ = self.image_descriptor_parse(source_descriptor)

        # Check that image exists
        src_file, src_meta = self.get_by_name(source_descriptor)

        if not src_file:
            raise PcoccError("Could not locate source image {0}".format(source_descriptor))

        # Check destination
        dest_name, dest_repo = self.image_descriptor_parse(target_descriptor)

        if dest_repo == "":
            raise PcoccError("You must specify a destination"
                            +" repo to push images '[DEST REPO]:[IMAGE NAME]'")

        if  (src_name == dest_name) and (src_meta["repo"] == dest_repo):
            raise PcoccError("Cannot move an image to itself {0}:{1} to {2}:{3}"
                             .format(src_meta["repo"], src_name, dest_repo, dest_name))

        # Check overwrite
        dst_file, _ = self.get_by_name(target_descriptor)

        if dst_file:
            if not force:
                raise PcoccError("{0} image is already present in {1}".format(dest_name, dest_repo)
                                 +"you may use '-f/--force' to overwrite")

        self.object_store.setval( dest_name, src_file, meta_data=src_meta["metadata"], repo_name=dest_repo)
        self.object_store.delval(src_name, src_meta["repo"])
