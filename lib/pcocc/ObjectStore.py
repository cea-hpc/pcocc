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
import getpass
import glob
import yaml
import re
import hashlib
import shutil
import errno
import logging
import tempfile

from .Error import InvalidConfigurationError, PcoccError
from .Config import Config
from .Backports import OrderedDict

repo_config_schema="""
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
required:
  - repos
additionalProperties: false
"""

metadata_schema="""
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
"""

repo_config_schema="""
type: object
properties:
  version:
    type: number
required:
  - version
additionalProperties: false
"""

repo_definition_schema="""
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
required:
  - repos
additionalProperties: false
"""

class ObjectNotFound(PcoccError):
    def __init__(self, name,  repo=None, revision=None):
        err = 'Object {0}{1} not found{2}'.format(
            name,
            self._revision_msg(revision),
            self._repo_msg(repo))

        super(ObjectNotFound, self).__init__(err)

    @staticmethod
    def _revision_msg(revision):
        if revision:
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

    def load_repos(self, repo_config_file, tag):
        try:
            stream = file(repo_config_file, 'r')
            repo_config = yaml.safe_load(stream)
        except (yaml.YAMLError, IOError) as err:
            raise InvalidConfigurationError(str(err))

        try:
            jsonschema.validate(repo_config,
                                yaml.safe_load(repo_definition_schema))
        except jsonschema.exceptions.ValidationError as err:
            raise InvalidConfigurationError(err.message)

        for repo in repo_config['repos']:
            if repo['name'] in self._repos.keys():
                raise InvalidConfigurationError('Duplicate repository: {0}'.format(
                    repo['name']))

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
        return [ r['store'] for r in self._repos.itervalues() if not tag or
                 r['tag'] == tag ]

    def get_meta(self, name, revision=None, repo=None):
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
            return self.get_revisions(repo).get_revisions(name)

        for r in self._repos.itervalues():
            obj_store = r['store']
            try:
                return obj_store.get_revisions(name)
            except ObjectNotFound:
                pass

        raise ObjectNotFound(name, repo, None)

    def load_meta(self, repo=None):
        if repo:
            return self.get_repo(repo).load_meta()

        glob_meta = {}
        for r in reversed(self._repos.values()):
            meta = r['store'].load_meta()
            glob_meta.update(meta)

        return glob_meta

class ObjectStore(object):
    def __init__(self, path, name):
        self._path = Config().resolve_path(path)
        self._name = name

        self._data_path    = os.path.join(self._path, 'data')
        self._meta_path    = os.path.join(self._path, 'meta')
        self._tmp_path     = os.path.join(self._path, '.tmp')
        self._config_path  = os.path.join(self._path, '.config')

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

    def get_obj_path(self, obj_type, obj_hash, check_exists = False, relative = False):
        if obj_type == 'data':
            base = self._data_path
        elif obj_type == 'meta':
            base = self._meta_path
        else:
            raise PcoccError('Bad object type {0}'.format(obj_type))

        try:
            os.mkdir(os.path.join(base, obj_hash[:2]))
        except OSError as e:
            if e.errno != errno.EEXIST:
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
            shutil.move(file_path, target)
        else:
            tmp = self.tmp_file()
            shutil.copyfile(file_path, tmp)
            shutil.move(tmp, target)

        return h

    def put_meta(self, name, revision, kind, data_blobs, custom_meta=None):
        self._validate_name(name)
        h = self._hash_meta(name, revision)
        target = self.get_obj_path('meta', h)

        meta = {}
        meta['name'] = name
        meta['revision'] = revision
        meta['kind'] = kind
        meta['owner'] = getpass.getuser()
        meta['timestamp'] = time.time()
        meta['data_blobs'] = data_blobs
        meta['custom_meta'] = custom_meta

        # Check that all the data blobs referred in the meta data are
        # already in the repo
        for b in data_blobs:
            self.get_obj_path('data', b, True)

        with open(target, 'w') as f:
            yaml.safe_dump(meta, f)

        return meta

    def _read_meta(self, meta_path, name, revision):
        if not os.path.isfile(meta_path):
            raise ObjectNotFound(name, self._name, revision)

        try:
            with open(meta_path, 'r') as f:
                meta = yaml.safe_load(f)
        except (OSError, IOError) as e:
            raise PcoccError('Unable to get metadata for {0}: {1}'.format(
                    name, e))
        except yaml.YAMLError as e:
            raise PcoccError('Bad metadata for {0}: {1}'.format(
                    name, e))

        try:
            jsonschema.validate(meta,
                                yaml.safe_load(metadata_schema))
        except jsonschema.exceptions.ValidationError as e:
            raise PcoccError('Bad metadata for {0}: {1}'.format(
                    name, e))

        return meta

    def get_meta(self, name, revision=None):
        if revision is None:
            revision = max(self.get_revisions(name))
        h = self._hash_meta(name, revision)
        target = self.get_obj_path('meta', h)
        meta = self._read_meta(target, name, revision)
        meta['repo'] = self._name
        return meta

    def get_revisions(self, name):
        try:
            return self.load_meta()[name].keys()
        except KeyError:
            raise ObjectNotFound(name, self._name, None)

    def load_meta(self):
        meta_list = glob.glob(os.path.join(self._meta_path, '*/*'))
        ret = {}
        for meta_path in meta_list:
            meta = self._read_meta(meta_path, None, None)
            meta['repo'] = self._name
            ret.setdefault(meta['name'], {})[meta['revision']] = meta

        return ret

    def delete(self, name, revision=None):
        if revision:
            revisions = [ revision ]
        else:
            revisions = self.get_revisions(name)

        for r in revisions:
            h = self._hash_meta(name, r)
            try:
                target = self.get_obj_path('meta', h, check_exists=True)
            except:
                raise ObjectNotFound(name, self._name, r)
            os.unlink(target)

    def _validate_repo_config(self):
        try:
            with open(self._config_path) as f:
                repo_config = yaml.safe_load(f)
                jsonschema.validate(repo_config,
                                        yaml.safe_load(repo_config_schema))

        except (yaml.YAMLError,
                IOError,
                jsonschema.exceptions.ValidationError) as err:
            raise PcoccError(
                'Bad repository config file {0} : {1}'.format(self._config_path,
                                                                      err))

        if repo_config['version'] != 1:
            raise InvalidConfigurationError(
                'unsupported repository {0} version'.format(self.name))

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
                yaml.safe_dump({'version': 1}, f)

        except OSError as e:
            raise PcoccError('Unable to create repository directory {0}: {1}: '.format(
                    self._path, str(e)))

    def _validate_name(self, name):
        if re.search(r"[^a-zA-Z0-9_\.-]+", name):
            raise PcoccError('Object name contains invalid characters')
        if not name:
            raise PcoccError('Empty object name')
