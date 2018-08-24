
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
        raise PcoccError("VM image format {} not supported".format(ext))

known_container_image_formats = ["containers-storage", "dir", "docker",
                                 "docker-archive", "docker-daemon", "oci",
                                 "oci-archive", "ostree", "tarball"]

def check_container_image_ext(ext):
    if ext not in known_container_image_formats:
        raise PcoccError("Container image format {} not supported".format(ext))

def convert(src, dest, src_format, dest_format):
    src = os.path.abspath(src)
    dest = os.path.abspath(dest)

    try:
        print("Converting from format '{0}' "
              "to '{1}'... ".format(src_format, dest_format))

        subprocess.check_output(
            ["qemu-img",
             "convert",
             "-p",
             "-f", src_format,
             "-O", dest_format,
             src,
             dest],
            stderr=subprocess.STDOUT,
            shell=False)

    except subprocess.CalledProcessError as e:
        raise PcoccError("Unable to convert image. "
                         "The qemu-img command failed with: " +e.output)


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
            if "kind" in meta_data["metadata"]:
                return meta_data["metadata"]["kind"]
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

    def check_supported_format(self, ikind, iformat):
        if ikind == "vm":
            check_qemu_image_ext(iformat)
        elif ikind == "cont":
            check_container_image_ext(iformat)

    def extract_extension(self, in_path):
        return os.path.splitext(in_path)[-1].lower().replace(".", "")

    def get_vm_type(self, path):
        if not os.path.isfile(path):
            raise PcoccError("Image file {} does not exist".format(path))
        if not os.access(path, os.R_OK):
            raise PcoccError("Image file {} is not readable".format(path))

        try:
            jsdata = subprocess.check_output(["qemu-img", "info","--output=json", path])
            data = json.loads(jsdata)
            if "format" in data:
                return data["format"]
            else:
                return None
        except:
            return None

    def import_image(self, in_path, key, ikind="vm", dest_repo="", iformat="", force=False):
        if iformat:
            iformat = iformat.lower()

        #Check if the format was prefixed
        if not iformat:
            spl = in_path.split(":")
            if len(spl) >= 2:
                iformat = spl[0].lower()
                in_path = ":".join(spl[1:])

        #Check if the format was suffixed
        if not iformat:
            iformat = self.extract_extension(in_path)

        # For VMs we can detect the input file type
        if ikind == "vm":
            detect = self.get_vm_type(in_path)
            if iformat and iformat != detect:
                raise PcoccError("Mismatch between specified format {} "
                                 "and detected format {}".format(iformat, detect))
            iformat = detect

        self.check_supported_format(ikind, iformat)

        # Now check if image exists or shadows and force is passed
        dst_file, dst_meta = self.get_by_name(key)

        if dst_file:
            if not force:
                raise PcoccError("'{0}' image is already present in repo '{1}' you"
                                .format(key, dst_meta["repo"])
                                +" may use '-f/--force' to overwrite or shadow existing image")

        did_convert = False
        # Save before possible convert/import override
        orig_path=in_path

        if ikind == "vm":
            if iformat != "qcow2":
                # The source needs conversion
                tmp = self._tempfile(ext=".qcow2")
                try:
                    # Convert to qcow2
                    convert(in_path, tmp, iformat, "qcow2")
                except Exception as e:
                    os.unlink(tmp)
                    raise PcoccError("Failed to import {0} : {1}".format(in_path, str(e)))
                did_convert = True
                in_path = tmp
        elif itype == "cont":
            # Create temp storage
            tmp = self._tempfile(ext=".tar.gz")
            did_convert = True

            print("Converting image to oci-archive ... ",)
            # Here we directly use skopeo to copy to an OCI tarball
            # and pcocc accepts the skopeo subtypes
            cmd = ["skopeo", "copy", src_ext + ":" + in_path,  "oci-archive:" + tmp + ":latest"]
            try:
                ret = subprocess.check_call(cmd)
            except subprocess.CalledProcessError:
                os.unlink(tmp)
                raise PcoccError("An error occured when importing"
                                +" container image (see previous logs).")
            in_path=tmp

        # Save meta-data
        meta = {}

        meta["kind"] = ikind
        meta["source_format"] = iformat
        meta["source_path"] = orig_path

        # Set in KVS
        print("Storing image in repository as '{0}' ... ".format(key))
        self.object_store.setval( key, in_path, meta_data=meta, repo_name=dest_repo)

        # Remove TMP if needed
        if did_convert:
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

        self.check_supported_format(itype, targ_ext)

        if itype == "vm":
            sys.stderr.write("Exporting image '{0}' to '{1}' in '{2}' format ... "
                             .format(descriptor, out_path, targ_ext))
            convert(in_path, out_path, "qcow2", targ_ext)
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
