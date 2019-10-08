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

import jsonschema
import os
import time
import glob
import yaml
import re
import hashlib
import shutil
import errno
import logging
import tempfile
import json

from .Error import InvalidConfigurationError, PcoccError
from .Config import Config
from .Backports import OrderedDict
from .Cache import Cache
from .Misc import get_current_user

metadata_schema = yaml.load("""
type: object
properties:
  name:
    type: string
  revision:
    type: integer
  data_blobs:
    type: array
    items:
      type: string
  description:
    type: string
  kind:
    type: string
  owner:
    type: string
  timestamp:
    type: number
  custom_meta:
    type: object
required:
  - name
  - revision
  - data_blobs
  - kind
  - owner
  - timestamp
additionalProperties: false
""", Loader=yaml.CLoader)

repo_config_schema = yaml.load("""
type: object
properties:
  version:
    type: number
required:
  - version
additionalProperties: false
""", Loader=yaml.CLoader)

repo_definition_schema = yaml.load("""
type: object
properties:
  repos:
    type: array
    items:
      type: object
      properties:
        name:
           type: string
        path:
           type: string
      required:
           - name
           - path
      additionalProperties: false
  cache:
    type: object
    properties:
        path:
            type: string
    required:
        - path
    additionalProperties: false
required:
  - repos
additionalProperties: false
""", Loader=yaml.CLoader)


class ObjectNotFound(PcoccError):
    def __init__(self, name,  repo=None, revision=None):
        err = 'Object {0}{1} not found{2}'.format(
            name,
            self._revision_msg(revision),
            self._repo_msg(repo))

        super(ObjectNotFound, self).__init__(err)

    @staticmethod
    def _revision_msg(revision):
        if revision is not None:
            return ' revision {0}'.format(revision)
        else:
            return ''

    @staticmethod
    def _repo_msg(repo):
        if repo:
            return ' in repository {0}'.format(repo)
        else:
            return ' in configured repositories'


class HierarchObjectStore(object):
    def __init__(self):
        self._repos = OrderedDict()
        self._cache = None

    @property
    def has_cache(self):
        return (self._cache is not None)

    @property
    def cache(self):
        if not self.has_cache:
            raise InvalidConfigurationError("A cache needs to be configured "
                                            "in the repos.yaml config file")
        return self._cache

    def load_repos(self, repo_config_file, tag):
        try:
            stream = file(repo_config_file, 'r')
            repo_config = yaml.load(stream, Loader=yaml.CSafeLoader)
        except (yaml.YAMLError, IOError) as err:
            raise InvalidConfigurationError(str(err))

        try:
            jsonschema.validate(repo_config, repo_definition_schema)
        except jsonschema.exceptions.ValidationError as err:
            raise InvalidConfigurationError(err.message)

        if "cache" in repo_config:
            if self._cache:
                raise InvalidConfigurationError("Only a single cache"
                                                " should be configured"
                                                " in repo.yaml")
            self._cache = Cache(repo_config["cache"]["path"])

        for repo in repo_config['repos']:
            if repo['name'] in self._repos.keys():
                message = 'Duplicate'' repository: {0}'.format(repo['name'])
                raise InvalidConfigurationError(message)

            repo['tag'] = tag
            repo['store'] = ObjectStore(Config().resolve_path(repo['path']),
                                        repo['name'])
            self._repos[repo['name']] = repo

    @property
    def default_repo(self):
        try:
            return self._repos.values()[0]['name']
        except IndexError:
            raise InvalidConfigurationError('No repository configured')

    def get_repo(self, repo_name):
        if repo_name:
            try:
                return self._repos[repo_name]['store']
            except KeyError:
                raise PcoccError('Unknown repository {0}'.format(repo_name))

        try:
            return self._repos.values()[0]['store']
        except IndexError:
            raise InvalidConfigurationError('No repository configured')

    def list_repos(self, tag):
        return [r['store']
                for r in self._repos.itervalues()
                if not tag or r['tag'] == tag]

    def get_meta(self,
                 name,
                 revision=None,
                 repo=None):
        if repo:
            return self.get_repo(repo).get_meta(name, revision)

        for r in self._repos.itervalues():
            obj_store = r['store']
            try:
                return obj_store.get_meta(name, revision)
            except ObjectNotFound:
                pass

        raise ObjectNotFound(name, repo, revision)

    def get_revisions(self, name, repo=None):
        if repo:
            return self.get_repo(repo).get_revisions(name)

        for r in self._repos.itervalues():
            obj_store = r['store']
            try:
                return obj_store.get_revisions(name)
            except ObjectNotFound:
                pass

        raise ObjectNotFound(name, repo, None)

    def load_meta(self, repo=None, shallow=False):
        if repo:
            return self.get_repo(repo).load_meta()

        glob_meta = {}
        for r in reversed(self._repos.values()):
            meta = r['store'].load_meta(shallow=shallow)
            glob_meta.update(meta)

        return glob_meta


class ObjectStore(object):
    def __init__(self, path, name):
        self._path = Config().resolve_path(path)
        self._name = name

        self._data_path = os.path.join(self._path, 'data')
        self._meta_path = os.path.join(self._path, 'meta')
        self._tmp_path = os.path.join(self._path, '.tmp')
        self._config_path = os.path.join(self._path, '.config')

        self._init_repodir()

    def _check_path_in_tmp(self, path):
        real_tmp_path = os.path.realpath(self._tmp_path)
        real_file_path = os.path.realpath(path)

        return real_file_path.startswith(real_tmp_path + os.sep)

    @staticmethod
    def _hash_file(path):
        h = hashlib.sha256()
        with open(path, 'rb', buffering=0) as f:
            while True:
                b = f.read(128*1024)
                if not b:
                    break
                h.update(b)
            return h.hexdigest()

    @staticmethod
    def _hash_meta(name, revision):
        h = hashlib.sha256()
        h.update('{0}\n{1}'.format(name, revision).encode('ascii',
                                                          'ignore'))
        return h.hexdigest()

    @property
    def path(self):
        return self._path

    @property
    def name(self):
        return self._name

    @staticmethod
    def _parse_hash_algorithm(obj_hash):
        if ":" in obj_hash:
            d = obj_hash.split(":")
            kind = d[0]
            h = d[1]
            if kind != "sha256":
                raise PcoccError("Only sha256 is supported currently")
            # Hash is supported extract the actual hash
            obj_hash = h
        return obj_hash

    def get_meta_path(self,
                      name,
                      revision,
                      check_exists=False):

        if self.version < 2:
            h = self._hash_meta(name, revision)
            return self.get_obj_path('meta', h, check_exists)
        else:
            image = '{}@{}'.format(name, revision)
            target = os.path.join(self._meta_path, image)

            if check_exists and not os.path.exists(target):
                raise PcoccError('Object {} not found in repository {}'.format(
                    image, self.name))
            return target

    def get_obj_path(self,
                     obj_type,
                     obj_hash,
                     check_exists=False,
                     relative=False):
        if obj_type == 'data':
            base = self._data_path
        elif obj_type == 'meta':
            base = self._meta_path
        else:
            raise PcoccError('Bad object type {0}'.format(obj_type))

        # Check if the hash contains an algorithm descriptor
        obj_hash = ObjectStore._parse_hash_algorithm(obj_hash)

        try:
            os.mkdir(os.path.join(base, obj_hash[:2]))
        except OSError as e:
            if e.errno != errno.EEXIST and e.errno != errno.EACCES:
                raise e

        if check_exists and not os.path.exists(os.path.join(base,
                                                            obj_hash[:2],
                                                            obj_hash)):
            raise PcoccError('Object {} not found in repository {}'.format(
                obj_hash, self.name))

        if relative:
            base = os.path.join('../../', obj_type)

        return os.path.join(base, obj_hash[:2], obj_hash)

    def tmp_file(self, ext=None):
        fd, path = tempfile.mkstemp(suffix="", dir=self._tmp_path)
        os.close(fd)
        return path

    def tmp_dir(self, ext=None):
        return tempfile.mkdtemp(dir=self._tmp_path)

    def _unlink_and_cleanup_dir(self, path):
        os.unlink(path)
        dirname = os.path.dirname(path)
        if not os.listdir(dirname):
            os.rmdir(dirname)

    def upgrade(self):
        if self.version == 1:
            logging.warning("Upgrading repository")
            meta = self.load_meta()
            self.version = 2
            shutil.move(self._meta_path, self._meta_path + '.old')
            try:
                os.mkdir(self._meta_path)
                for revs in meta.itervalues():
                    for m in revs.itervalues():
                        self.put_meta(m['name'], m['revision'], m['kind'],
                                      m['data_blobs'], m['custom_meta'],
                                      m['owner'], m['timestamp'])

                with open(self._config_path, 'w') as f:
                    yaml.safe_dump({'version': 2}, f)
            except Exception:
                logging.error("Failed to upgrade repository")
                self.version = 1
                try:
                    shutil.rmtree(self._meta_path, ignore_errors=True)
                except Exception:
                    pass
                shutil.move(self._meta_path + '.old', self._meta_path)
                raise

    def garbage_collect(self):
        meta = self.load_meta()
        in_use = set()
        for revs in meta.itervalues():
            for m in revs.itervalues():
                for o in m["data_blobs"]:
                    in_use.add(o)

        in_use = map(ObjectStore._parse_hash_algorithm,
                     in_use)

        obj_list = glob.glob(os.path.join(
                self._data_path, '*/*'))

        for o in obj_list:
            if os.path.basename(o) not in in_use:
                logging.info("deleting unused data %s", o)
                self._unlink_and_cleanup_dir(o)

        # Cleanup any leftover tmp file
        tmp_list = glob.glob(os.path.join(self._tmp_path, '*'))
        for t in tmp_list:
            logging.info("deleting leftover tmp file %s", t)
            if os.path.isdir(t):
                shutil.rmtree(t, ignore_errors=True)
            else:
                os.unlink(t)

        self.upgrade()

    def put_data_blob(self, file_path, known_hash=None):
        if not os.path.isfile(file_path):
            raise PcoccError("{0} is not a regular file".format(file_path))

        if known_hash:
            h = known_hash
        else:
            h = self._hash_file(file_path)

        target = self.get_obj_path('data', h)

        if os.path.exists(target):
            logging.info('Skipping import of data blob %s '
                         'already in repository', h)
            return h

        move = self._check_path_in_tmp(file_path)
        if move:
            to_move = file_path
        else:
            tmp = self.tmp_file()
            shutil.copyfile(file_path, tmp)
            to_move = tmp

        os.chmod(to_move, 0o444)
        shutil.move(to_move, target)

        return h

    def put_meta(self, name, revision, kind, data_blobs, custom_meta=None, user=None,
                 timestamp=None):
        self._validate_name(name)
        target = self.get_meta_path(name, revision)

        meta = {}
        meta['name'] = name
        meta['revision'] = revision
        meta['kind'] = kind
        meta['owner'] = (user or get_current_user().pw_name)
        meta['timestamp'] = (timestamp or time.time())
        meta['data_blobs'] = data_blobs
        meta['custom_meta'] = custom_meta

        # Check that all the data blobs referred in the meta data are
        # already in the repo
        for b in data_blobs:
            self.get_obj_path('data', b, True)

        with open(target, 'w') as f:
            if self.version < 2:
                yaml.safe_dump(meta, f)
            else:
                json.dump(meta, f)

        return meta

    def _read_meta(self, meta_path, name, revision):
        if not os.path.isfile(meta_path):
            raise ObjectNotFound(name, self._name, revision)

        try:
            with open(meta_path, 'r') as f:
                raw_meta = f.read()
        except (OSError, IOError) as e:
            raise PcoccError('Unable to get metadata for {0}: {1}'.format(
                    name, e))

        try:
            if self.version < 2:
                meta = yaml.load(raw_meta, Loader=yaml.CSafeLoader)
            else:
                meta = json.loads(raw_meta)
        except (yaml.YAMLError, ValueError) as e:
            raise PcoccError('Bad metadata for {0}: {1}'.format(name, e))

        try:
            jsonschema.validate(meta, metadata_schema)
        except jsonschema.exceptions.ValidationError as e:
            raise PcoccError('Bad metadata for {0}: {1}'.format(
                    name, e))

        return meta

    def get_meta(self, name, revision=None):
        if revision is None:
            revision = max(self.get_revisions(name))

        target = self.get_meta_path(name, revision)

        meta = self._read_meta(target, name, revision)
        meta['repo'] = self._name
        return meta

    def get_revisions(self, name):
        if self.version < 2:
            try:
                return self.load_meta()[name].keys()
            except KeyError:
                raise ObjectNotFound(name, self._name, None)
        else:
            ret = []
            image_list = glob.glob(os.path.join(self._meta_path, '*'))
            for image_path in image_list:
                image = os.path.basename(image_path)
                image, revision = image.split('@')
                if image == name:
                    ret.append(revision)
            if not ret:
                raise ObjectNotFound(name, self._name, None)

            return ret

    def load_meta(self, shallow=False):
        if self.version < 2:
            meta_list = glob.glob(os.path.join(self._meta_path, '*/*'))
        else:
            meta_list = glob.glob(os.path.join(self._meta_path, '*'))
        ret = {}
        for meta_path in meta_list:
            if self.version < 2 or not shallow:
                meta = self._read_meta(meta_path, None, None)
                name = meta['name']
                revision = meta['revision']
            else:
                name, revision = os.path.basename(meta_path).split('@')
                meta = {}
                meta['name'] = name
                meta['revision'] = revision

            meta['repo'] = self._name
            ret.setdefault(meta['name'], {})[meta['revision']] = meta

        return ret

    def delete(self, name, revision=None):
        if revision is not None:
            revisions = [revision]
        else:
            revisions = self.get_revisions(name)

        for r in revisions:
            try:
                target = self.get_meta_path(name, r, check_exists=True)
            except:
                raise ObjectNotFound(name, self._name, r)

        if self.version < 2:
            self._unlink_and_cleanup_dir(target)
        else:
            os.unlink(target)

    def _validate_repo_config(self):
        try:
            with open(self._config_path) as f:
                repo_config = yaml.load(f, Loader=yaml.CSafeLoader)
                jsonschema.validate(repo_config, repo_config_schema)
        except (yaml.YAMLError,
                IOError,
                jsonschema.exceptions.ValidationError) as err:
            raise PcoccError('Bad repository config'
                             ' file {0} : {1}'.format(self._config_path, err))

        self.version = repo_config['version']

        if repo_config['version'] < 2:
            logging.info('Please upgrade your %s repository', self.name)
        elif repo_config['version'] != 2:
            raise InvalidConfigurationError('Unsupported version for repository "{}"'.format(
                self.name))

    def _init_repodir(self):
        if os.path.isdir(self._path):
            self._validate_repo_config()
            return

        if os.path.exists(self._path):
            raise PcoccError("Repository path {0} is not a directory".format(
                    self._path))

        parent_dir = os.path.dirname(self._path)
        if not os.path.isdir(parent_dir):
            raise PcoccError("Invalid repository parent directory {0}".format(
                    parent_dir))

        try:
            os.mkdir(self._path)
            os.mkdir(self._data_path)
            os.mkdir(self._meta_path)
            os.mkdir(self._tmp_path)
            with open(self._config_path, 'w') as f:
                yaml.safe_dump({'version': 2}, f)
        except OSError as e:
            raise PcoccError('Unable to create repository directory '
                             '{0}: {1}: '.format(self._path, str(e)))

        self.version = 2

    def _validate_name(self, name):
        if re.search(r"[^a-zA-Z0-9_\.-]+", name):
            raise PcoccError('Object name contains invalid characters')
        if not name:
            raise PcoccError('Empty object name')
