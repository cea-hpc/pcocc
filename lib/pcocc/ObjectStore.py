"""
This is the Object Store Python interface
"""
import json
import os
import md5
import time
import getpass
import grp
import time
from pwd import getpwnam
from shutil import copyfile
import glob

from .Error import InvalidConfigurationError
from .Error import PcoccError

class ObjectStore(object):
    def __init__(self, repolist=None):
        #Variables
        self.default_repo = ""
        self.repolist = []
        self.reponames = []
        self.repos = {}
        # Check parameters
        if repolist:
            if type(repolist) != type([]):
                raise Exception("Repolist must be an array")
            #Unfold paths
            to_add =[self._unfoldpath(e) for e in repolist]
            #Normalize paths
            to_add = [ os.path.normpath(e) for e in to_add]
            #Check paths
            to_add_filtered = []
            for e in to_add:
                try:
                    self._check_repodir(e)
                    to_add_filtered.append(e)
                except:
                    pass
                
            #Save repolist
            self.repolist = to_add_filtered
            #Hash repolist
            self._hash_repos()


    def set_repo_list(self, repolist):
        #Unfold paths
        to_add =[self._unfoldpath(e) for e in repolist]
        #Check if already present
        to_add = [os.path.normpath(e) for e in to_add if not os.path.normpath(e) in self.repolist]
        #Check if correct
        to_add_filtered = []
        for e in to_add:
            try:
                self._check_repodir(e)
                to_add_filtered.append(e)
            except:
                pass
        #Save in list
        self.repolist = self.repolist + to_add_filtered
        #Rehash
        self._hash_repos()

    def reloadconfig(self):
        pass

    def setval(self, key, file_path, meta_data=None, repo_name=""):
        clean_key = self._normalize_key(key)

        #Force parent dir refresh
        os.listdir(os.path.dirname(file_path))

        trial=5
        while (not os.path.isfile(file_path)) and  (0 <= trial):
            #Be gentle with NFS
            time.sleep(1)
            #Force parent dir refresh
            os.listdir(os.path.dirname(file_path))
            trial = trial - 1

        if not os.path.isfile(file_path):
            raise PcoccError("ObjectStore : %s is not a regular file" % file_path)
        if not repo_name:
            repo_name = self.default_repo
        key_root = self._get_key_root(repo_name, clean_key)
        #Make sure of repo's correctness
        #And create the directory if needed
        self._check_repodir(key_root)
        #
        # Prepare to write
        #
        target_blob = os.path.join(key_root, clean_key)
        target_blob_meta = target_blob + ".meta"

        meta = self._gen_metadata(key,
                                  repo_name,
                                  file_path,
                                  target_blob,
                                  meta_data)
        #First try to copy file
        copyfile(file_path, target_blob)
        #Proceed to write meta-data
        with open(target_blob_meta, 'w') as m:
            json.dump(meta, m, indent=4)

    def getval(self, key, repo_name=""):
        if not repo_name:
            #Scan repos in decreasing order of priority
            for r in reversed(self.reponames):
                target_blob, meta = self._getval(key, r)
                if target_blob and meta:
                    return target_blob, meta
        else:
            return self._getval(key, repo_name)

    def listval(self, repo_name=""):
        if not repo_name:
            #All repos
            ret = []
            for r in self.repos:
                ll = self._get_meta_for_repo(r)
                ret = ret + ll
            return ret
        else:
            return self._get_meta_for_repo(repo_name)

    def delval(self, key, repo_name="" ):
        target_blob, target_blob_meta = self._get_blob_infos(key, repo_name)
        os.remove(target_blob_meta)
        os.remove(target_blob)

    #
    # Internal functions
    #
    def _check_repodir(self, rdir):
        parent_dir = os.path.dirname(rdir)
        if not os.path.isdir(parent_dir):
            raise InvalidConfigurationError("ObjectStore : %s is not a directory" % parent_dir)
        try:
            os.stat(rdir)
            if not os.path.isdir(rdir):
                raise InvalidConfigurationError("ObjectStore : %s is not a directory" % rdir)
        except:
            #We need to create it
            os.mkdir(rdir)

    def _hash_repos(self):
        self.default_repo = ""
        if len(self.repolist) == 0:
            return
        for e in self.repolist:
            name = os.path.basename(e)
            self.reponames.append(name)
            #The last repository is the default
            self.default_repo = name
            directory = e
            self.repos[name] = {'path': directory}
        if not self.default_repo:
            raise PcoccError("ObjectStore : No repository found")

    def _unfoldpath(self,path):
        user = getpass.getuser()
        home = getpwnam(user).pw_dir
        uid = getpwnam(user).pw_uid
        gid = grp.getgrnam(user).gr_gid

        #Apply subst
        path = path.replace("%USER%", user)
        path = path.replace("%HOME%", home)
        path = path.replace("%UID%", str(uid))
        path = path.replace("%GID%", str(gid))
        return path

    def _normalize_key(self, key):
        ascii_val = ( [chr(e) for e in range(48,57)] #0-9
                    + [chr(e) for e in range(65,90)] #A-Z
                    + [chr(e) for e in range(97,122)] #a-z
                    + ['.','_']) #Some special chars
        return "".join([e for e in key if e in ascii_val])

    def _hash_key(self, key):
        md = md5.new()
        md.update("".join(key))
        return md.hexdigest()[:2]

    def _gen_metadata(self, key, repo, source, dest, meta):
        ret = {}
        ret["key"] = key
        ret["author"] = getpass.getuser()
        ret["src_path"] = source
        ret["filename"] = os.path.dirname(source)
        ret["path"] = dest
        ret["repo"] = repo
        ret["metadata"] = meta
        ret["timestamp"] = time.time()
        return ret

    def _get_key_root(self, repo_name, clean_key):
        if not repo_name in self.repos:
            raise PcoccError("ObjectStore : No such repo %s" % repo_name)
        repo_root = self.repos[repo_name]["path"]
        key_hash = self._hash_key(clean_key)
        key_root = os.path.join(repo_root, key_hash)
        return key_root


    def _get_meta_for_repo(self, repo_name):
        if not repo_name in self.repos:
            raise PcoccError("ObjectStore : No such repo %s" % repo_name)
        base = self.repos[repo_name]["path"]
        metalist = glob.glob(base + "/*/*.meta")
        ret = []
        for m in metalist:
            with open(m) as mf:
                ret.append(json.load(mf))
        return ret

    def _get_blob_infos(self, key, repo_name):
        clean_key = self._normalize_key(key)
        if not repo_name:
            repo_name = self.default_repo
        key_root = self._get_key_root(repo_name, clean_key)
        target_blob = os.path.join(key_root, clean_key)
        target_blob_meta = target_blob + ".meta"
        # Check for existence
        if not os.path.isfile(target_blob_meta):
            return None, None
        if not os.path.isfile(target_blob):
            return None, None
        return target_blob, target_blob_meta

    def _getval(self, key, repo_name):
        target_blob, target_blob_meta = self._get_blob_infos(key, repo_name)
        # Load meta-data
        meta = None
        if target_blob_meta:
            with open(target_blob_meta) as m:
                meta = json.load(m)
        #Now return the blob and its meta
        return target_blob, meta