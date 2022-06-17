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
import pwd
import yaml
import socket
import re
import shutil
import errno
import subprocess
import sys
import random
import datetime
import logging
import jsonschema
import etcd
import etcd.auth
import atexit
import binascii
import stat
import psutil
import signal
import argparse
import uuid
import threading

from ClusterShell.NodeSet import NodeSet, NodeSetException, RangeSet
from abc import ABCMeta, abstractmethod

from .Tbon import  UserCA
from .Config import Config
from .Backports import subprocess_check_output
from .Error import PcoccError, InvalidConfigurationError
from .Misc import fake_signalfd, wait_or_term_child
from .Misc import CHILD_EXIT, datetime_to_epoch, stop_threads, systemd_notify



class BatchError(PcoccError):
    """Generic exception for Batch related issues
    """
    def __init__(self, error):
        super(BatchError, self).__init__(error)

class InvalidJobError(BatchError):
    """Exception raised when a specific job cannot be found or doesn't belong to
    the user
    """
    def __init__(self, error):
        super(InvalidJobError, self).__init__('Unable to find job: '
                                              + error)

class NoJobError(BatchError):
    """Exception raised when there is no job specified or implied by
    the current context but one is required to continue
    """
    def __init__(self):
        super(NoJobError, self).__init__('The target job was neither specified '
                                         'nor implied and could not be guessed '
                                         'by name')

class AllocationError(BatchError):
    """Exception raised when an allocation fails
    """
    def __init__(self, error):
        super(AllocationError, self).__init__('Failure in job allocation: '
                                              + error)

class KeyTimeoutError(BatchError):
    """Exception raised after a time out waiting for a key
    """
    def __init__(self, key):
        super(KeyTimeoutError, self).__init__('Timeout waiting for key: ' + key)

class KeyCredentialError(BatchError):
    """Exception raised if the user cannot be authenticated
    """
    def __init__(self, error):
        super(KeyCredentialError, self).__init__(
            'Keystore authentication error: ' + error)

# Schema to validate batch.yaml config file
batch_config_schema = """
type: object
properties:
  type:
    enum:
      - slurm
      - local
  settings:
    type: object
    properties:
      etcd-servers:
        type: array
      etcd-client-port:
        type: integer
      etcd-protocol:
        enum:
          - http
          - https
      etcd-ca-cert:
        type: string
      etcd-auth-type:
        enum:
          - password
          - munge
          - none
      batch-args:
        type: array
    additionalProperties: false
    required:
      - etcd-servers
      - etcd-client-port
      - etcd-protocol
      - etcd-auth-type
required:
  - type
  - settings
"""

class ProcessType(object):
    """Enum class defining the type of process wrt batch management"""
    # Privileged process for node setup
    SETUP = 1
    # Hypervisor process running one VM
    HYPERVISOR = 2
    # Launcher process
    LAUNCHER = 3
    # User process related to a job
    USER = 4
    # Other user process
    OTHER = 5


ETCD_PASSWORD_BYTES = 16


class BatchManager(object, metaclass=ABCMeta):
    """Manages all interactions with the batch environment"""
    def load(batch_config_file, batchid, batchname, default_batchname,
             proc_type, batchuser):
        """Factory function to initialize a batch manager"""
        try:
            stream = open(batch_config_file, 'r')
            batch_config = yaml.safe_load(stream)
        except yaml.YAMLError as err:
            raise InvalidConfigurationError(str(err))
        except IOError as err:
            raise InvalidConfigurationError(str(err))

        try:
            jsonschema.validate(batch_config,
                                yaml.safe_load(batch_config_schema))
        except jsonschema.exceptions.ValidationError as err:
            raise InvalidConfigurationError(str(err))

        settings = batch_config['settings']
        if batch_config['type'] == 'slurm':
            return SlurmManager(
                batchid, batchname, default_batchname,
                settings, proc_type, batchuser)
        elif batch_config['type'] == 'local':
            return LocalManager(
                batchid, batchname, default_batchname,
                settings, proc_type, batchuser)
        else:
            raise InvalidConfigurationError("Invalid batch manager type")


    def __init__(self, batchid, batchname, default_batchname, settings,
                 proc_type, batchuser):

        self.proc_type = proc_type

        # "abstract" properties
        self.batchid = 0
        self.batchuser = None
        self.nodeset = None
        self.node_rank = None
        self.cluster_state_dir = None
        self.vm_state_dir_prefix = None
        self.pcocc_state_dir = None

    def find_job_by_name(self, user, batchname, host=None, include_expired=False):
        """Return a jobid matching a user and batchname

        There must be one and only one job matching the specified criteria

        """
        raise PcoccError("Not implemented")

    @abstractmethod
    def run(self, cluster, run_opt, cmd):
        """Launch the VM tasks"""
        raise PcoccError("Not implemented")

    @abstractmethod
    def alloc(self, cluster, alloc_opt, cmd):
        """Allocate an interactive job"""
        raise PcoccError("Not implemented")

    @abstractmethod
    def _only_in_a_job(self):
        """Called on each node at the resource deletion step"""
        raise PcoccError("Not implemented")

    def batch(self, cluster, alloc_opt, cmd):
        """Allocate a batch job"""
        raise PcoccError("Not implemented")

    def init_node(self):
        """Called on each node at the init step"""

    def create_resources(self):
        """Called on each node at the resource creation step"""

    def delete_resources(self, force=False):
        """Called on each node at the resource deletion step"""

    def dump_resources(self):
        """Called on each node after resources have been created"""

    @abstractmethod
    def vm_count(self):
        """Returns the number of VMs in the cluster"""

    @property
    def task_rank(self):
        """Returns the rank of the current process in the SLURM job

        This is only valid for hypervisor processes

        """
        raise PcoccError("Not implemented")

    @property
    def coreset(self):
        """Returns the list of cores allocated to the current task

        Only valid for hypervisor processes

        """
        self._only_in_a_job()
        # Assume we've been bound to our cores by the batch manager
        taskset = subprocess_check_output(['hwloc-bind', '--get']).decode().strip()
        coreset = subprocess_check_output(['hwloc-calc', '--intersect', 'Core',
                                           taskset]).decode().strip()

        return RangeSet(coreset)

    @property
    def num_cores(self):
        """Returns the number of cores allocated per task

        Only valid for hypervisor processes

        """
        raise PcoccError("Not implemented")

    @property
    def cluster_definition(self):
        """Returns the cluster definition passed to the spank plugin

        This is only valid for node setup processes

        """
        raise PcoccError("Not implemented")

    def get_host_rank(self, rank):
        """Returns rank of the host where the specified task rank runs"""
        raise PcoccError("Not implemented")

    def get_rank_on_host(self, rank):
        """Returns the relative rank of the specified task rank on its host

        """
        raise PcoccError("Not implemented")

    def get_rank_host(self, rank):
        """Returns the hostname where the specified task rank runs"""
        self._only_in_a_job()
        return self.nodeset[self.get_host_rank(rank)]

    def is_rank_local(self, rank):
        """ True if the specified process rank is allocated on the current node
        """
        self._only_in_a_job()
        return self.node_rank == self.get_host_rank(rank)

    @property
    def num_nodes(self):
        """Returns the number of host nodes in the job"""
        self._only_in_a_job()
        return len(self.nodeset)

    @property
    def _in_a_job(self):
        return self.batchid != 0

    @property
    def ca_cert(self):
        """Returns a CA certificate for authenticating the user (CLI and hypervisor agents)

        """
        raise PcoccError("Not implemented")

    @property
    def client_cert(self):
        """Returns a Certificate for authenticating the user (clientss)

        """
        raise PcoccError("Not implemented")

    load = staticmethod(load)


def _retry_on_cred_expiry(func):
    """Wraps etcd call to automtically regenerate expired credentials"""
    def _wrapped_func(*args, **kwargs):
        while True:
            try:
                return func(*args, **kwargs)
            except etcd.EtcdException as e:
                args[0]._try_renew_credential(e) # pylint: disable=W0212
    return _wrapped_func

class EtcdManager(BatchManager):
    """Common class for batch managers based on etcd"""
    def __init__(self, batchid, batchname, default_batchname, settings,
                 proc_type, batchuser):

        super(EtcdManager, self).__init__(
            batchid, batchname, default_batchname, settings,
            proc_type, batchuser)

        # Load settings
        self._etcd_servers = settings['etcd-servers']
        self._etcd_ca_cert = settings.get('etcd-ca-cert', None)
        self._etcd_client_port = settings['etcd-client-port']
        self._etcd_protocol = settings['etcd-protocol']
        self._etcd_auth_type = settings['etcd-auth-type']
        if self._etcd_auth_type == 'password':
            self._etcd_password = None
        self._ca_cert = None

    def _init_vm_dir(self):
        self._only_in_a_job()
        try:
            os.mkdir(self._get_vm_state_dir(self.task_rank), 0o700)
        except OSError as e:
            raise PcoccError('Failed to create temporary directory for '
                             'VM data: ' + str(e))

        atexit.register(self._clean_vm_dir)

    def _init_cluster_dir(self):
        self._only_in_a_job()
        if os.path.exists(self.cluster_state_dir):
            shutil.rmtree(self.cluster_state_dir)

        os.makedirs(self.cluster_state_dir)
        atexit.register(self._clean_cluster_dir)

    def _clean_cluster_dir(self):
        self._only_in_a_job()
        logging.info("Cleaning cluster dir")
        if os.path.exists(self.cluster_state_dir):
            shutil.rmtree(self.cluster_state_dir)

    def _clean_vm_dir(self):
        self._only_in_a_job()
        if os.path.exists(self._get_vm_state_dir(self.task_rank)):
            shutil.rmtree(self._get_vm_state_dir(self.task_rank))

    def get_cluster_state_path(self, name):
        """ Return path to store cluster state file """
        return os.path.join(self.cluster_state_dir, name)

    def _get_vm_state_dir(self, rank):
        return '%s_%d' % (self.vm_state_dir_prefix, rank)

    def get_vm_state_path(self, rank, name):
        """ Return path to store vm state file """
        return '%s/%s' % (self._get_vm_state_dir(rank), name)

    def _only_in_a_job(self):
        if not self._in_a_job:
            raise NoJobError()

    def _is_user_key_type(self, key_type):
        return key_type.endswith('user')

    def _is_cluster_key_type(self, key_type):
        return key_type.startswith('cluster')

    def infer_user_and_alloc_id(self, user, batchid, key_type):
        ruser = user
        rid = batchid
        if ruser is None and self._is_user_key_type(key_type):
            ruser = self.batchuser
        if rid is None and self._is_cluster_key_type(key_type):
            self._only_in_a_job()
            rid = self.batchid
        return ruser, rid

    def read_key(self, key_type, key,
                 blocking=False, timeout=0,
                 user=None,
                 batchid=None):
        """Reads a key from keystore

        Returns None if the key doesn't exist except if blocking is
        True, then we block until the key is set or the timeout
        expires.

        """
        user, batchid = self.infer_user_and_alloc_id(user, batchid, key_type)

        val, index = self.read_key_index(key_type, key, user=user, batchid=batchid)
        if val or not blocking:
            return val

        while not val:
            val, index = self.wait_key_index(key_type, key, index,
                                             timeout=timeout,
                                             user=user,
                                             batchid=batchid)

        return val.value




    @_retry_on_cred_expiry
    def read_key_index(self, key_type, key,
                       realindex=False,
                       user=None,
                       batchid=None):
        """Reads a key and its modification index from keystore

        By default, return an index suitable for watches, for updates
        use realindex=True.

        Returns None if the key doesn't exist.

        """
        user, batchid = self.infer_user_and_alloc_id(user, batchid, key_type)

        key_path = self.get_key_path(key_type, key,
                                     user, batchid)

        try:
            ret = self.keyval_client.read(key_path)
        except etcd.EtcdKeyNotFound as e:
            return None, e.payload['index']

        if realindex:
            return ret.value, ret.modifiedIndex
        else:
            return ret.value, max(ret.modifiedIndex,
                                  ret.etcd_index)

    def read_dir(self, key_type, key, user=None, batchid=None):
        """Reads a directory from keystore

        Returns None if the directory doesn't exist. Otherwise,
        returns the full directory content (as returned by the etcd
        lib)

        """
        user, batchid = self.infer_user_and_alloc_id(user, batchid, key_type)
        val, _ = self.read_dir_index(key_type, key)
        return val

    @_retry_on_cred_expiry
    def read_dir_index(self, key_type, key, user=None, batchid=None):
        """Reads a directory from keystore

        Returns None if the directory doesn't exist. Otherwise,
        returns the full directory content (as returned by the etcd
        lib) and associated modification index

        """
        user, batchid = self.infer_user_and_alloc_id(user, batchid, key_type)

        key_path = self.get_key_path(key_type, key, user, batchid)
        try:
            val = self.keyval_client.read(key_path, recurse = True)
        except etcd.EtcdKeyNotFound as e:
            return None, e.payload['index']

        return val, max(val.modifiedIndex,
                        val.etcd_index)

    @_retry_on_cred_expiry
    def write_ttl(self, key_type, key, value, ttl):
        """Write a single key with a ttl"""
        key_path = self.get_key_path(key_type, key)
        self.keyval_client.write(key_path, value, ttl=ttl)

    @_retry_on_cred_expiry
    def write_key(self, key_type, key, value):
        """Write a single key"""
        key_path = self.get_key_path(key_type, key)
        return self.keyval_client.write(key_path, value)

    @_retry_on_cred_expiry
    def write_key_index(self, key_type, key, value, index):
        """Write a single key using compare and swap on the index"""
        key_path = self.get_key_path(key_type, key)
        return self.keyval_client.write(key_path, value,
                                        prevIndex=index)

    @_retry_on_cred_expiry
    def write_key_new(self, key_type, key, value):
        """Write a single key if it didnt exist"""
        key_path = self.get_key_path(key_type, key)
        return self.keyval_client.write(key_path, value,
                                        prevExist=False)

    @_retry_on_cred_expiry
    def atom_update_key(self, key_type, key, func, *args, **kwargs):
        """Wrap a function to atomically update a key

        Read the current value of the key and pass it to the wrapped
        function which returns the updated value. Then, try to
        update the value with compare and swap and restart the whole
        process if there was a race.

        """
        while True:
            try:
                value, index = self.read_key_index(key_type, key,
                                                   realindex=True)
                nargs = args + (value,)
                new_value, ret = func(*nargs, **kwargs)

                logging.debug(
                    "Trying atomic update \"%s\" for \"%s\" ",
                        str(value).strip(),
                        str(new_value).strip())

                if value is None:
                    if new_value is None:
                        return ret
                    else:
                        self.write_key_new(key_type, key, new_value)
                else:
                    self.write_key_index(key_type, key, new_value,
                                         index)

                return ret
            except ( etcd.EtcdCompareFailed,
                     etcd.EtcdKeyNotFound,
                     etcd.EtcdAlreadyExist ):
                logging.debug("Retrying atomic update")

    @_retry_on_cred_expiry
    def make_dir(self, key_type, key):
        """Create a directory"""
        key_path = self.get_key_path(key_type, key)
        self.keyval_client.write(key_path, False, dir = True)

    @_retry_on_cred_expiry
    def delete_key(self, key_type, key):
        """Delete a key

        This fails for directories
        """
        key_path = self.get_key_path(key_type, key)
        self.keyval_client.delete(key_path, recursive = False, dir = False)

    @_retry_on_cred_expiry
    def delete_dir(self, key_type, key):
        """Delete a directory

        Also succeeds for keys
        """
        key_path = self.get_key_path(key_type, key)
        try:
            self.keyval_client.delete(key_path, recursive = True, dir = True)
        except etcd.EtcdNotDir:
            self.delete_key(self, key_type, key)

    @_retry_on_cred_expiry
    def wait_key_index(self, key_type, key, index,
                       timeout = 0,
                       user=None,
                       batchid=None):
        """Wait until a key is updated from the specified index"""
        user, batchid = self.infer_user_and_alloc_id(user, batchid, key_type)

        key_path = self.get_key_path(key_type, key, user, batchid)

        while True:
            try:
                ret = self.keyval_client.watch(key_path, recursive = True,
                                         index = index + 1, timeout = timeout)
                return ret, max(ret.modifiedIndex,
                              ret.etcd_index)
            except etcd.EtcdWatchTimedOut:
                logging.info("Timeout while waiting for key " + key_path)
                raise KeyTimeoutError(key_path)
            except etcd.EtcdEventIndexCleared as e:
                return None, e.payload['index']
            except etcd.EtcdClusterIdChanged:
                return None, e.payload['index']

    @_retry_on_cred_expiry
    def wait_child_count(self, key_type, key, count):
        """Wait until a directory has the specified number of elements"""
        while True:
            ret, last_index  = self.read_dir_index(key_type, key)
            if ret:
                num_complete = len([child for child in ret.children])
            else:
                num_complete = 0

            if num_complete == count:
                return ret

            self.wait_key_index(key_type, key, last_index, timeout=30)

    def get_key_path(self, key_type, key,
                     user=None,
                     batchid=None):
        """Returns the path of a key

        Global keys are global to the whole physical cluster whereas
        cluster keys are per virtual cluster/job.

        User keys are writable by the user whereas standard keys may
        only be written as root.

        """
        user, batchid = self.infer_user_and_alloc_id(user, batchid, key_type)

        if key_type == 'global':
            return '/pcocc/global/{0}'.format(key)
        if key_type == 'global/user':
            return '/pcocc/global/users/{0}/{1}'.format(user, key)
        elif key_type == 'cluster':
            return '/pcocc/cluster/{0}/{1}'.format(batchid, key)
        elif key_type == 'cluster/user':
            return '/pcocc/cluster/users/{0}/{1}/{2}'.format(user,
                                                             batchid,
                                                             key)
        else:
            raise KeyError(key_type)

    @property
    def keyval_client(self):
        try:
            return self._keyval_client
        except AttributeError:
            hosts_tuple = [ (host, self._etcd_client_port) for
                            host in self._etcd_servers ]
            random.shuffle(hosts_tuple)
            hosts_tuple = tuple(hosts_tuple)
            logging.debug('Starting etcd client')
            self._keyval_client = etcd.Client(
                host=hosts_tuple,
                ca_cert=self._etcd_ca_cert,
                protocol=self._etcd_protocol,
                allow_reconnect=True,
                read_timeout=10,
                username=self._get_keyval_username(),
                password=self._get_keyval_credential())

            logging.info('Started etcd client')
            self._last_cred_renew = datetime.datetime.utcnow()

            return self._keyval_client

    def _try_renew_credential(self, e):
        # Expired credential status
        if (hasattr(e.payload, "get") and (
                e.payload.get("errorCode", 0) == 110 or
                e.payload.get("error_code", 0) == 110 or
                e.payload.get("status", 0) == 401 )):

            delta = datetime.datetime.utcnow() - self._last_cred_renew

            if delta > datetime.timedelta(seconds=15):
                logging.debug('Renewing etcd credentials')
                self._last_cred_renew = datetime.datetime.utcnow()
                self._keyval_client.password = self._get_keyval_credential()
                return
            else:
                raise KeyCredentialError('access denied')

        raise e

    def _get_keyval_credential(self):
        if self._etcd_auth_type == 'munge':
            return subprocess_check_output(['/usr/bin/munge', '-n']).decode()
        elif self._etcd_auth_type == 'password':
            if self._etcd_password is None:
                self._init_password()
            return self._etcd_password
        elif self._etcd_auth_type == 'none':
            return None

    def _get_keyval_username(self):
        if self._etcd_auth_type == 'none':
            return None
        else:
            return pwd.getpwuid(os.getuid()).pw_name

    def _init_password(self):
        bad_perms = (stat.S_IRGRP |
                     stat.S_IWGRP |
                     stat.S_IROTH |
                     stat.S_IWOTH)

        if os.getuid() == 0:
            try:
                pwd_path = os.path.join(Config().conf_dir,
                                 'etcd-password')

                st = os.stat(pwd_path)
                if st.st_mode & bad_perms:
                    logging.warning('Loose permissions on password file ' +
                                    pwd_path)
                self._etcd_password = open(
                    os.path.join(Config().conf_dir,
                                 'etcd-password')).read().strip()
            except:
                raise KeyCredentialError('unable to read password file')
        else:
            pwd_path = os.path.join(self.pcocc_state_dir,
                                    '.etcd-password')
            try:
                st = os.stat(pwd_path)
                if st.st_mode & bad_perms:
                    logging.warning('Loose permissions on password file ' +
                                    pwd_path)

                self._etcd_password = open(pwd_path).read().strip()
                if len(self._etcd_password) != 2 * ETCD_PASSWORD_BYTES:
                    raise KeyCredentialError(
                        'password file {0} is invalid, '
                        'please delete it and allocate '
                        'a new virual cluster'.format(pwd_path))
                else:
                    return
            except (OSError, IOError) as e:
                # Only generate a password if the file is missing
                # Hypervisor processes should not have to do this
                # as it should have been done beforehand
                if (e.errno != errno.ENOENT or
                    self.proc_type == ProcessType.HYPERVISOR):
                    raise KeyCredentialError('unable to read password file')

            logging.info('Password is not set, generating a new one')

            # Try to generate a password
            try:
                os.mkdir(self.pcocc_state_dir)
            except OSError as e:
                logging.debug(str(e))

            try:
                self._etcd_password = binascii.b2a_hex(
                    os.urandom(ETCD_PASSWORD_BYTES)).decode()
                f = os.open(pwd_path,
                            os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o400)
                os.write(f, self._etcd_password.encode())
                os.close(f)
            except OSError as e:
                raise KeyCredentialError('unable to generate password: ' + str(e))

    def init_cluster_keys(self):
        if self._etcd_auth_type != 'none':
            role = '{0}-pcocc'.format(self.batchuser)
            logging.info('Initializing etcd role %s', role)
            u = etcd.auth.EtcdRole(self.keyval_client, role)
            u.grant('/pcocc/cluster/*', 'R')
            u.grant('/pcocc/global/public/*', 'R')
            u.grant('/pcocc/cluster/users/{0}/*'.format(self.batchuser), 'RW')
            u.grant('/pcocc/global/users/{0}/*'.format(self.batchuser), 'RW')
            u.write()

            logging.info('Initializing etcd user %s', self.batchuser)
            u = etcd.auth.EtcdUser(self.keyval_client, self.batchuser)
            try:
                u.read()
            except etcd.EtcdKeyNotFound:
                pass
            u.roles = list(u.roles) + [role]
            if self._etcd_auth_type == 'password':
                requested_cred = os.environ.get('SPANK_PCOCC_REQUEST_CRED', '')
                if (len(requested_cred) == 2 * ETCD_PASSWORD_BYTES
                    and u.password != requested_cred):
                    logging.info('Updating password')
                    u.password = requested_cred

            u.write()
            self.make_dir('cluster/user', '')

    def cleanup_cluster_keys(self):
        try:
            logging.debug('Setting self-destruct on cluster etcd keystore')
            self.write_key('cluster', 'destroyed', True)
            self.keyval_client.write(self.get_key_path('cluster', ''),
                                     None, dir=True, prevExist=True, ttl=600)
            self.keyval_client.write(self.get_key_path('cluster/user', ''),
                                     None, dir=True, prevExist=True, ttl=600)
        except:
            logging.warning('Failed to cleanup cluster etcd keystore')

    def populate_env(self):
        """ Populate environment variables with batch related info to propagate """
        os.putenv('PCOCC_JOB_ID', str(self.batchid))

    @property
    def ca_cert(self):
        """Returns a CA certificate for authenticating the user

        """
        if not self._ca_cert:
            self._ca_cert = UserCA.load_yaml(Config().batch.read_key('cluster/user', 'ca_cert',
                                                                     blocking=True))
        return self._ca_cert

    @property
    def client_cert(self):
        return self.ca_cert

# Schema to validate the global pkey state in the key/value store
local_job_allocation_schema = """
type: object
properties:
  jobs:
    type: object
    patternProperties:
      "^([0-9]+)+$":
        type: object
        properties:
          batchname:
            type: string
          coreset:
            type: string
          definition:
            type: string
          uuid:
            type: string
          host:
            type: string
          user:
            type: string
          start:
            type: integer
        required:
          - batchname
          - definition
          - uuid
          - host
          - user
          - start
        additionalProperties: no
  next_batchid:
    type: integer
additionalProperties: no
"""
class LocalManager(EtcdManager):
    def __init__(self, batchid, batchname, default_batchname, settings,
                 proc_type, batchuser):

        super(LocalManager, self).__init__(
            batchid, batchname, default_batchname, settings,
            proc_type, batchuser)

        # Find the uid: if we are executed as a management plugin via
        # sudo the uid will be set as an env var, otherwise we can use
        # the current user unless a specific user is requested for
        # commands which support it
        if batchuser and self.proc_type == ProcessType.USER:
            self.batchuser = batchuser
        else:
            try:
                self.batchuser = os.environ['SUDO_USER']
            except KeyError:
                self.batchuser = pwd.getpwuid(os.getuid()).pw_name

        self.pcocc_state_dir = os.path.join(os.path.expanduser('~/.pcocc'))

        # Find the job id.
        # Look in order at the specified job id, job name, environment variable,
        # and default job name
        self.batchid = 0
        if batchid:
            self.batchid = batchid
        elif batchname:
            self.batchid = self.find_job_by_name(self.batchuser, batchname)
        elif not batchuser:
            try:
                self.batchid = int(os.environ['PCOCC_LOCAL_JOB_ID'])
            except KeyError:
                if default_batchname:
                    try:
                        self.batchid = self.find_job_by_name(self.batchuser,
                                                             default_batchname)
                    except InvalidJobError:
                        pass


        if self.batchid == 0 or self.proc_type == ProcessType.OTHER:
            # Not related to a job, no need to initialize job state
            return


        job_record = self._get_job_record(self.batchid)
        self.nodeset = NodeSet(job_record['host'])
        # Only on node per job in local mode
        self.node_rank = 0

        # Define working directories
        self.node_state_dir = '/tmp/.pcocc_%s_node' % (self.batchid)
        self.vm_state_dir_prefix = '/tmp/.pcocc_%s_vm' % (self.batchid)
        self.cluster_state_dir = os.path.join(self.pcocc_state_dir,
                                              'job_%s' % (self.batchid))


        if self.proc_type == ProcessType.HYPERVISOR:
            self._init_vm_dir()

        if self.proc_type == ProcessType.LAUNCHER:
            self._init_cluster_dir()

    def alloc(self, cluster, alloc_opt, cmd):
        if self._in_a_job:
            raise AllocationError("already in a job")

        if self._etcd_auth_type == 'password':
            os.environ['SPANK_PCOCC_REQUEST_CRED'] = self._get_keyval_credential()

        os.environ['PCOCC_LOCAL_CLUSTER_DEFINITION'] = cluster.resource_definition

        parser = argparse.ArgumentParser()
        parser.add_argument('-c','--cpus-per-vm', type=int, default='1',
                            dest='ncpus')
        parser.add_argument('-J','--job-name', type=str, default='pcocc',
                            dest='jobname')
        parser.add_argument('--core-set', type=str, default='',
                            dest='coreset')
        parser.add_argument('-n', '--nvms', type=int, default=1,
                            dest='nvms')
        parser.add_argument('-m', '--mem-per-core', type=int, default='1000',
                            dest='mpc')

        alloc_opt = parser.parse_args(alloc_opt)

        if (alloc_opt.mpc < 1):
            raise AllocationError('invalid mem-per-core: {0}'.format(
                alloc_opt.mpc))
        os.environ['PCOCC_LOCAL_MEM_PER_CPU'] = str(alloc_opt.mpc)

        if (alloc_opt.ncpus < 1):
            raise AllocationError('invalid cpus-per-vm: {0}'.format(
                alloc_opt.ncpus))
        os.environ['PCOCC_LOCAL_CPUS_PER_VM'] = str(alloc_opt.ncpus)

        if not re.match(r'[a-zA-Z_]\w*', alloc_opt.jobname):
            raise AllocationError('invalid job-name: {0}'.format(
                alloc_opt.jobname))
        os.environ['PCOCC_LOCAL_JOB_NAME'] = alloc_opt.jobname

        if alloc_opt.coreset:
            try:
                _ = RangeSet(alloc_opt.coreset)
            except:
                raise AllocationError('invalid core-set: {0}'.format(
                    alloc_opt.coreset))
            os.environ['PCOCC_LOCAL_CORE_SET'] = alloc_opt.coreset

        self._req_uuid = uuid.uuid4()
        os.environ['PCOCC_LOCAL_JOB_UUID'] = str(self._req_uuid)

        # TODO: Only one VM in local mode for now
        os.environ['PCOCC_LOCAL_PROCID'] = '0'
        if (alloc_opt.nvms != 1):
            raise AllocationError('local batch manager only '
                                  'supports 1 VM per cluster')

        jobid_in_use = None
        try:
            jobid_in_use = self.find_job_by_name(self.batchuser,
                                                 alloc_opt.jobname,
                                                 socket.gethostname().split('.')[0])
        except:
            pass

        if not jobid_in_use is None:
            logging.warning('Job name %s is already in use by %s',
                    alloc_opt.jobname,
                    jobid_in_use)

        self._run_pid = 0
        self._shutdown = False

        # Make sure we don't get spuriously interrupted
        # once we start allocating host resources
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        term_sigfd = fake_signalfd([signal.SIGTERM, signal.SIGABRT, signal.SIGHUP])

        subprocess.check_call(['sudo',
                               'pcocc'] + Config().verbose_opt +
                               ['internal', 'setup', 'init'])

        atexit.register(self._kill_tasks, os.getpid())
        atexit.register(self._run_resource_cleanup)

        subprocess.check_call(['sudo',
                               'pcocc'] + Config().verbose_opt +
                               ['internal', 'setup', 'create'])

        self.batchid = self._uuid_to_batchid(self.batchuser, self._req_uuid)
        os.environ['PCOCC_LOCAL_JOB_ID'] = str(self.batchid )

        systemd = False
        if systemd_notify('Initializing...'):
            systemd = True

        heartbeat = threading.Thread(None, self._heartbeat_thread, args=[systemd])
        heartbeat.start()

        # We expect to be given 60s to shutdown so give 50s to
        # our child process
        r, _, s = wait_or_term_child(subprocess.Popen(cmd),
                                     signal.SIGTERM, term_sigfd, 50, "alloc")
        stop_threads.set()
        if s == CHILD_EXIT.KILL:
            raise PcoccError('VM launcher did not acknowlege VM shutdown ' +
                             'request after SIGTERM was received')
        return r

    def _heartbeat_thread(self, notify_systemd=False):
        logging.debug("Starting job heartbeat thread")
        retry = 0
        max_retry = 3

        while not stop_threads.wait(10):
            # Update pcocc heartbeat
            try:
                if retry < max_retry:
                    self._update_heartbeat()
                    retry = 0
            except Exception:
                retry += 1

            if retry >= max_retry:
                logging.exception("Failed to update heartbeat: aborting")
                # If we're unable to access the keystore after
                # multiple tries, we have to shutdown as other processes
                # may soon consider us dead: send a signal and
                # exit this thread
                os.kill(os.getpid(), signal.SIGTERM)
                break

            elif retry > 0:
                logging.exception("Failed to update heartbeat: will retry")
                # No need to check if VMs are running if we have
                # trouble accessing the keystore: try again before
                # going further
                continue

            if not notify_systemd:
                continue

            # Update systemd watchodg
            try:
                r = self.read_key('global/user',
                                  'batch-local/heartbeat.vm/{0}.0'.format(self.batchid),
                                  blocking=True)
                if r is not None:
                    systemd_notify("VM is running", watchdog=True)
                    continue
            except Exception:
                logging.exception("Error while reading VM heartbeat")

            systemd_notify("VM is not responsive")



    def _run_resource_cleanup(self):
        try:
            os.environ['PCOCC_LOCAL_JOB_ID'] = str(self._uuid_to_batchid(self.batchuser,
                                                                         self._req_uuid))
            subprocess.call(['sudo', 'pcocc'] + Config().verbose_opt +
                            ['internal', 'setup', 'delete'])
        except Exception:
            logging.exception("Failed to run resource cleanup")

    def run(self, cluster, run_opt, cmd):
        """Launch the VM tasks"""
        return subprocess.Popen(cmd)

    @property
    def task_rank(self):
        self._only_in_a_job()
        return int(os.environ['PCOCC_LOCAL_PROCID'])

    @property
    def cluster_definition(self):
        return os.environ.get('PCOCC_LOCAL_CLUSTER_DEFINITION')

    @property
    def mem_per_core(self):
        """Returns the amount of memory allocated per core in MB"""
        self._only_in_a_job()
        return int(os.environ['PCOCC_LOCAL_MEM_PER_CPU'])

    @property
    def num_cores(self):
        """Returns the number of cores allocated per task

        Only valid for hypervisor processes

        """
        self._only_in_a_job()
        return int(os.environ['PCOCC_LOCAL_CPUS_PER_VM'])

    def get_host_rank(self, rank):
        self._only_in_a_job()
        return 0

    def get_rank_on_host(self, rank):
        self._only_in_a_job()
        return rank

    def _cpuset_cluster(self, batchid=None):
        if batchid is None:
            batchid = self.batchid

        return os.path.join(self._cpuset_base(), 'pcocc', str(batchid))

    def _cpuset_base(self):
        cpuset_base = subprocess.check_output(['lssubsys', '-m', 'cpuset']).decode()
        cpuset_base = cpuset_base.split(' ')[1].strip()
        return cpuset_base

    def _validate_jobname(self, batchname):
        if not re.match('[a-zA-Z0-9_-]+', batchname):
            raise InvalidJobError('Invalid characters in job name {0}'.format(
                batchname))

    def _job_allocation_key(self):
        return 'public/batch-local/job_allocation_state'

    def _cleanup_failed_jobs(self):
        """Cleanup jobs which were not properly deleted
        """
        job_alloc_state = self.read_key('global',
                                        self._job_allocation_key())
        job_alloc_state = self._validate_job_state(job_alloc_state)

        live_batchids = self._list_alive_jobs()

        for batchid, job in job_alloc_state['jobs'].items():
            if job['host'] == socket.gethostname().split('.')[0]:
                f = None
                try:
                    f = open(os.path.join(self._cpuset_cluster(int(batchid)), 'tasks'))
                except IOError:
                    pids = ''

                if f:
                    pids = f.read().splitlines()
                    f.close()

                if not pids:
                    # All processes died but the job entry was not cleaned
                    logging.warning('Trying to clean orphan job %s', batchid)
                elif not int(batchid) in live_batchids:
                    # Heartbeat stopped, we should clean the job
                    logging.warning('Trying to clean stale job %s', batchid)
                else:
                    continue


                subprocess.call(['pcocc'] + Config().verbose_opt +
                                ['internal', 'setup', 'delete', '-j', batchid, '--nolock'])

    def _list_alive_jobs(self):
        path = self.get_key_path('global/user', 'batch-local/heartbeat')
        d = self.read_dir('global/user', 'batch-local/heartbeat')
        if d is None:
            return []

        batchids = []
        for child in d.children:
            if child.key == path:
                continue
            else:
                try:
                    batchids.append(int(os.path.split(child.key)[-1]))
                except:
                    logging.warning('Invalid heartbeat entry for '
                                    'user %s: %s',
                                        self.batchuser,
                                        child.key
                                    )
        return batchids

    def _update_heartbeat(self, ttl=180):
        _ = self.write_ttl('global/user',
                           'batch-local/heartbeat/{0}'.format(self.batchid),
                           '',
                           ttl)

    def list_all_jobs(self, include_expired=False, details=False):
        """List all jobs in the cluster

        Returns a list of the batchids of all jobs in the cluster

        """
        job_alloc_state = self.read_key('global',
                                        self._job_allocation_key())
        job_alloc_state = self._validate_job_state(job_alloc_state)


        user_live_batchids = self._list_alive_jobs()

        jobs = {}
        for batchid, job in job_alloc_state['jobs'].items():
            batchid = int(batchid)
            if (include_expired or
                job['user'] != self.batchuser or
                datetime_to_epoch(datetime.datetime.utcnow()) - job['start'] < 5 or
                batchid in user_live_batchids):

                jobs[batchid] = job
            else:
                logging.info('list_all_jobs: ignoring stale job %d on %s ',
                             batchid, job['host'])

        if details:
            return jobs
        else:
            return list(jobs.keys())

    def get_job_details(self, user=None):
        """Gather details about pcocc jobs
        """
        ret = []
        for batchid, job in self.list_all_jobs(details=True).items():
            if user and job['user'] != user:
                continue

            elapsed = datetime_to_epoch(datetime.datetime.utcnow()) - job['start']
            entry = {'batchid':    str(batchid),
                     'user':       job['user'],
                     'exectime':   str(datetime.timedelta(seconds=elapsed)),
                     'timelimit':  'N/A',
                     'partition':  'N/A',
                     'node_count':  job['host'],
                     'state':      job['host'],
                     'jobname':    job['batchname']}


            ret.append(entry)

        return ret


    def find_job_by_name(self, user, batchname,
                         host=None, include_expired=False):

        job_alloc_state = self.read_key('global',
                                        self._job_allocation_key())
        job_alloc_state = self._validate_job_state(job_alloc_state)

        batchids = []
        hosts = []
        live_batchids = self._list_alive_jobs()

        for batchid, job in job_alloc_state['jobs'].items():
            batchid = int(batchid)

            if not include_expired and not batchid in live_batchids:
                continue

            if (job['user'] == user and job['batchname'] == batchname):
                if host and job['host'] == host:
                    return batchid
                elif not host:
                    if job['host'] == socket.gethostname().split('.')[0]:
                        return batchid
                    else:
                        batchids.append(batchid)
                        hosts.append(job['host'])


        if not batchids:
            raise InvalidJobError('no valid match for name '+ batchname)

        if len(batchids) > 1:
            raise InvalidJobError('name {0} is ambiguous (exists on {1})'.format(
                batchname, ', '.join(hosts)))

        return batchids[0]

    def _get_job_record(self, batchid):
        job_alloc_state = self.read_key('global',
                                        self._job_allocation_key())
        job_alloc_state = self._validate_job_state(job_alloc_state)

        try:
            return job_alloc_state['jobs'][str(batchid)]
        except KeyError:
            raise InvalidJobError('no job record for batchid ' + str(batchid))

    def _do_alloc_job(self, user, batchname, uuid, definition, job_alloc_state):
        """Helper to allocate a jobname"""
        job_alloc_state = self._validate_job_state(job_alloc_state)

        try:
            batchid = self._uuid_to_batchid(user, uuid, job_alloc_state)
        except AllocationError:
            batchid = -1

        if batchid != -1:
            raise AllocationError(
                'uuid {0} already in use by job {1} on host {2}'.format(
                    uuid, batchid, job_alloc_state['jobs'][str(batchid)]['host']))


        try:
            # At this point orphan cleanup should have run so there shouldnt be
            # any expired job remaining
            batchid = self.find_job_by_name(user, batchname,
                                            socket.gethostname().split('.')[0],
                                            include_expired=True)
        except InvalidJobError:
            batchid = -1

        if batchid != -1:
            raise AllocationError(
                'Jobname {0} already in use by job {1} on host {2}'.format(
                    batchname, batchid, job_alloc_state['jobs'][str(batchid)]['host']))


        batchid = job_alloc_state['next_batchid']
        job_alloc_state['next_batchid'] = batchid + 1

        job_alloc_state['jobs'][str(batchid)] = {
            'batchname': batchname,
            'definition': definition,
            'uuid': str(uuid),
            'user': user,
            'host': socket.gethostname().split('.')[0],
            'start': datetime_to_epoch(datetime.datetime.utcnow())
        }

        job_alloc_state = self._validate_job_state(job_alloc_state)
        return yaml.dump(job_alloc_state), batchid

    def _do_free_job(self, user, uuid, job_alloc_state):
        """Helper to allocate a jobname"""
        job_alloc_state = self._validate_job_state(job_alloc_state)

        batchid = self._uuid_to_batchid(user, uuid, job_alloc_state)
        job_record = job_alloc_state['jobs'].pop(str(batchid))

        job_alloc_state = self._validate_job_state(job_alloc_state)
        return yaml.dump(job_alloc_state), job_record

    def _validate_job_state(self, state):
        if state is None:
            job_alloc_state = {'jobs': {}, 'next_batchid': 1}
        elif isinstance(state, dict):
            job_alloc_state = state
        else:
            job_alloc_state = yaml.safe_load(state)

        schema = yaml.safe_load(local_job_allocation_schema)
        jsonschema.validate(job_alloc_state, schema)

        return job_alloc_state

    def _uuid_to_batchid(self, user, uuid, job_alloc_state=None):
        if job_alloc_state is None:
            job_alloc_state = self.read_key('global',
                                            self._job_allocation_key())

        job_alloc_state = self._validate_job_state(job_alloc_state)

        try:
            for batchid, job in job_alloc_state['jobs'].items():
                if job['uuid'] == str(uuid):
                    return int(batchid)
        except KeyError:
            pass

        raise AllocationError('Unable to find job with uuid {0}'.format(uuid))

    def vm_count(self):
        return 1

    def init_node(self):
        self._cleanup_failed_jobs()

    def create_resources(self):
        req_jobname = os.getenv('PCOCC_LOCAL_JOB_NAME', None)
        req_uuid = os.getenv('PCOCC_LOCAL_JOB_UUID', None)
        caller_pid = psutil.Process(os.getppid()).ppid()

        if caller_pid == 1:
            raise AllocationError('Invalid parent pid')

        logging.debug("Parent pid is %d", caller_pid)

        if not req_jobname:
            raise AllocationError('Job name was not specified')
        self._validate_jobname(req_jobname)

        if not req_uuid:
            raise AllocationError('Job uuid was not specified')

        try:
            req_uuid = uuid.UUID(req_uuid)
        except Exception:
            raise AllocationError('Invalid uuid')

        self.batchid = self.atom_update_key(
            'global',
            self._job_allocation_key(),
            self._do_alloc_job,
            self.batchuser,
            req_jobname,
            req_uuid,
            self.cluster_definition)
        self._update_heartbeat()


        # Create cpuset cgroup and move caller into it
        try:
            with open(os.path.join(
                    self._cpuset_base(), 'cgroup.clone_children'), 'w') as f:
                f.write('1')

            os.makedirs(self._cpuset_cluster())
        except OSError as e:
            if e.errno == errno.EEXIST:
                pass
            else:
                raise BatchError(
                    'Unable to set requested cpuset: ' + str(e))

        with open(os.path.join(self._cpuset_cluster(), 'tasks'), 'w') as f:
            try:
                f.write(str(caller_pid))
            except:
                raise AllocationError("Failed to create cpuset")

        try:
            cores = os.environ.get('PCOCC_LOCAL_CORE_SET', None)
            logging.info("Setting core set %s" % cores)
            if cores:
                cores = str(RangeSet(cores))
                pus = []
                for rng in cores.split(','):
                    pus += [subprocess_check_output(['hwloc-calc',
                                                     '--intersect', 'PU', '--po',
                                                     'cores:{}'.format(rng)]).decode().strip()]

                pus = ','.join(pus)
                with open(os.path.join(self._cpuset_cluster(),
                                       'cpuset.cpus'), 'w') as f:
                    f.write(str(pus))
        except Exception as e:
            raise BatchError('Unable to set requested cpuset: ' + str(e))

        self.node_rank=0
        self.nodeset=NodeSet(socket.gethostname().split('.')[0])

    def _kill_tasks(self, caller_pid):
        if not self.batchid:
            return

        logging.debug("Looking for remaining processes")
        try:
            with open(os.path.join(self._cpuset_cluster(), 'tasks')) as f:
                pids = f.read().splitlines()


                for pid in pids:
                    pid = int(pid)
                    try:
                        if (os.path.exists(os.path.join('/proc/', str(pid))) and
                            (psutil.Process(pid).username() == self.batchuser) and
                            pid != caller_pid and pid != os.getppid()
                            and pid != os.getpid()):
                            logging.debug("Killing process %d still active in cgroup", pid)
                            os.kill(pid, signal.SIGKILL)
                    except psutil.NoSuchProcess:
                        pass
                    except OSError:
                        pass

        except IOError:
            logging.warning('Kill tasks: no cpuset for job %d', self.batchid)
            return

    def delete_resources(self, force=False):
        if not self.batchid:
            raise AllocationError('Job id was not specified')

        job_record = self._get_job_record(self.batchid)
        if self.batchuser != 'root' and job_record['user'] != self.batchuser:
            raise AllocationError('Wrong user for job {0}'.format(self.batchid))

        remote = False
        if job_record['host'] != socket.gethostname().split('.')[0]:
            if force:
                remote = True
            else:
                raise AllocationError('Wrong host for job {0}'.format(self.batchid))

        if not remote:
            caller_pid = psutil.Process(os.getppid()).ppid()
            self._kill_tasks(caller_pid)

        logging.debug("Cleaning up allocation key")
        try:
            job_record = self.atom_update_key(
                'global',
                self._job_allocation_key(),
                self._do_free_job,
                self.batchuser,
                job_record['uuid'])

            self._update_heartbeat(0)
        except:
            logging.error('No allocation record to delete '
                          'matching job %d for user %s',
                          self.batchid,
                          self.batchuser)

        logging.debug("Global state cleanup complete")
        if remote:
            logging.warning('Exiting without performing host resource cleanup for '
                            'forced remote job deletion')
            sys.exit(1)

        # Allow recovering from the jobid if the allocation process
        # died without calling resource deletion
        if os.environ.get('PCOCC_LOCAL_CLUSTER_DEFINITION', None) is None:
            os.environ['PCOCC_LOCAL_CLUSTER_DEFINITION'] = job_record['definition']



class SlurmManager(EtcdManager):
    def __init__(self, batchid, batchname, default_batchname, settings,
                 proc_type, batchuser):

        super(SlurmManager, self).__init__(
            batchid, batchname, default_batchname, settings,
            proc_type, batchuser)

        # Parse batch settings
        self._batch_args = settings.get('batch-args', [])

        # At init time we get all the necessery info about the job state
        # from the batch scheduler
        self._rank_map = []

        if batchuser and self.proc_type == ProcessType.USER:
            # For some CLI invocations, we allow targeting arbitrary users
            self.batchuser = batchuser
        else:
            # Find the uid: if we are executed as a management plugin,
            # it has to be provided as an evironment variable by
            # SLURM. Otherwise, we default to the current user.
            try:
                uid = int(os.environ['SLURM_JOB_UID'])
            except KeyError:
                if self.proc_type == ProcessType.SETUP:
                    raise
                # Assume the user is the caller
                uid = os.getuid()

            self.batchuser = pwd.getpwuid(uid).pw_name

        # Find the job id.
        # Look in order at the specified job id, job name, environment variable,
        # and default job name
        self.batchid = 0
        if batchid:
            self.batchid = batchid
        elif batchname:
            self.batchid = self.find_job_by_name(self.batchuser, batchname)
        elif not batchuser:
            try:
                self.batchid = int(os.environ['SLURM_JOB_ID'])
            except KeyError:
                if default_batchname:
                    try:
                        self.batchid = self.find_job_by_name(self.batchuser,
                                                             default_batchname)
                    except InvalidJobError:
                        pass

        self.pcocc_state_dir = os.path.join(os.path.expanduser('~/.pcocc'))

        if self.batchid == 0 or self.proc_type == ProcessType.OTHER:
            # Not related to a job, no need to initialize job state
            return

        # If we are inside the allocation we can get the nodelist from an
        # environment variable. Otherwise, we'll have to query it with squeue
        if ('SLURM_NODELIST' in os.environ and
            self.batchid == int(os.environ['SLURM_JOB_ID'])):
            self.nodeset = NodeSet(os.environ['SLURM_NODELIST'])
        else:
            try:
                self.nodeset = NodeSet(
                    subprocess_check_output(['squeue', '-j',
                                             str(self.batchid),
                                             '-u', self.batchuser,
                                             '-h', '-o', '%N']).decode())
            except subprocess.CalledProcessError:
                raise InvalidJobError('no valid match for id '+ str(self.batchid))

            except NodeSetException:
                raise InvalidJobError('no valid match for id '+ str(self.batchid))

        # Define working directories
        self.node_state_dir = '/tmp/.pcocc_%s_node' % (self.batchid)
        self.vm_state_dir_prefix = '/tmp/.pcocc_%s_vm' % (self.batchid)
        self.cluster_state_dir = os.path.join(self.pcocc_state_dir,
                                              'job_%s' % (self.batchid))

        # Compute the rank of our node among the allocated nodes
        # FIXME: This assumes the slurm nodeset is based on host names
        hostname = socket.gethostname().split('.')[0]
        for i, node in enumerate(self.nodeset):
            if node == hostname:
                self.node_rank = i
                break
        else:
            self.node_rank = -1

        # For now, we let the batch manager handle VM placement and do not allow
        # the user to set this at the cluster definition level.
        # We compute the vm rank to host mapping at resource allocation time
        # which we store for later pcocc commands to use
        if (self.proc_type == ProcessType.SETUP or
            self.proc_type == ProcessType.LAUNCHER or
            self.proc_type == ProcessType.HYPERVISOR):
            self._build_rank_map()
        else:
            self._load_rank_map()

        if self.proc_type == ProcessType.HYPERVISOR:
            self._init_vm_dir()

        if self.proc_type == ProcessType.LAUNCHER:
            self._init_cluster_dir()

    def find_job_by_name(self, user, batchname, host=None, include_expired=False):
        """Return a jobid matching a user and batchname

        There must be one and only one job matching the specified criteria

        """

        cmd = [ 'squeue' , '-n', batchname, '-u', user,
                '-h', '-o', '%i' ]
        if host:
            cmd += ['-w', host]

        try:
            batchid = subprocess_check_output(cmd).decode()
        except subprocess.CalledProcessError:
            raise InvalidJobError('no valid match for name '+ batchname)

        if not batchid:
            raise InvalidJobError('no valid match for name '+ batchname)

        try:
            return int(batchid)
        except ValueError:
            raise InvalidJobError('name %s is ambiguous' % batchname)

    def list_all_jobs(self):
        """List all jobs in the cluster
        Returns a list of the batchids of all jobs in the cluster
        (including non pcocc jobs)
        """
        try:
            joblist = subprocess_check_output(['squeue', '-ho',
                                               '%A']).decode().split()
            return [ int(j) for j in joblist ]
        except subprocess.CalledProcessError as err:
            raise BatchError('Unable to retrieve SLURM job list: ' + str(err))

    def get_job_details(self, user=None):
        """Gather details about pcocc jobs
        """

        candidates = []
        try:
            d = self.keyval_client.read('/pcocc/cluster/')
        except etcd.EtcdKeyNotFound:
            # No pcocc jobs, no need to go further
            return []

        for child in d.children:
            try:
                candidates.append(int(os.path.split(child.key)[-1]))
            except ValueError:
                pass

        if user:
            user_filter = ['-u', user]
        else:
            user_filter = []

        try:
            joblist = subprocess_check_output(
                ['squeue'] + user_filter +
                ['-ho','%A %u %M %l %P %D %t %j']).decode().split("\n")
        except subprocess.CalledProcessError as err:
            raise BatchError('Unable to retrieve SLURM job list: ' + str(err))

        ret = []

        for line in joblist:
            if not line:
                continue
            entry = line.split()
            try:
                parsed_entry = {'batchid':    int(entry[0]),
                                'user':       entry[1],
                                'exectime':   entry[2],
                                'timelimit':  entry[3],
                                'partition':  entry[4],
                                'node_count': int(entry[5]),
                                'state':      entry[6],
                                'jobname':    ' '.join(entry[7:])}
            except (IndexError, ValueError):
                logging.error('Skipping unexpected slurm output: %s-', line)
                continue

            if user and parsed_entry['user'] != user:
                continue

            if parsed_entry['batchid'] not in candidates:
                continue

            ret.append(parsed_entry)

        return ret

    def list_user_jobs(self, user):
        all_jobs = self.list_all_jobs()
        return [ j for j in all_jobs if j["user"] == user ]


    def _build_rank_map(self, tasks_per_node=None):
        self._only_in_a_job()
        node_index = 0

        assert(not self._rank_map)

        if not tasks_per_node:
            tasks_per_node = os.environ['SLURM_TASKS_PER_NODE']

        for node_def in tasks_per_node.split(','):
            match = re.search(r'(\d+)\(x(\d+)\)', node_def)
            if match:
                ntasks = int(match.group(1))
                nnodes = int(match.group(2))
            else:
                ntasks = int(node_def)
                nnodes = 1

            for _ in range(nnodes):
                for _ in range(ntasks):
                    self._rank_map.append(node_index)
                node_index += 1

    def dump_resources(self):
        if self.node_rank == 0:
            self.write_key('cluster', 'rank_map',
                           yaml.dump(self._rank_map))

    def _load_rank_map(self):
        if self._rank_map:
            raise BatchError("Rank map was already loaded")

        data = self.read_key(
            'cluster', 'rank_map', blocking=True)
        if not data:
            raise BatchError("Unable to load rank map")

        self._rank_map = yaml.safe_load(data)

    def vm_count(self):
        return len(self._rank_map)

    def run(self, cluster, run_opt, cmd):
        """Launch the VM tasks"""
        return subprocess.Popen(['srun'] + run_opt +
                                ['--vm', cluster.resource_definition] +
                                cmd)

    def alloc(self, cluster, alloc_opt, cmd):
        """Allocate an interactive job"""
        if self._in_a_job:
            raise AllocationError("already in a job")
        try:
            if self._etcd_auth_type == 'password':
                os.environ['PCOCC_REQUEST_CRED'] = self._get_keyval_credential()
            #Make sure user owned keys and cert are generated
            os.environ['SLURM_DISTRIBUTION'] = 'block:block'
            ret = subprocess.call(['salloc'] + self._batch_args + alloc_opt + cmd)
        except KeyboardInterrupt:
            raise AllocationError("interrupted")

        return ret

    def batch(self, cluster, alloc_opt, cmd):
        """Allocate a batch job"""
        try:
            if self._etcd_auth_type == 'password':
                os.environ['PCOCC_REQUEST_CRED'] = self._get_keyval_credential()
            os.environ['SLURM_DISTRIBUTION'] = 'block:block'
            subprocess.check_call(['sbatch'] +
                                  ['-J', 'pcocc','--signal', '15'] +
                                  self._batch_args +
                                  alloc_opt +
                                  [cmd])
        except subprocess.CalledProcessError as err:
            raise AllocationError(str(err))

    @property
    def task_rank(self):
        """Returns the rank of the current process in the SLURM job

        This is only valid for hypervisor processes

        """
        self._only_in_a_job()
        return int(os.environ['SLURM_PROCID'])

    @property
    def cluster_definition(self):
        """Returns the cluster definition passed to the spank plugin

        This is only valid for node setup processes

        """
        self._only_in_a_job()
        return os.environ['SPANK_PCOCC_SETUP']

    @property
    def num_nodes(self):
        """Returns the number of host nodes in the job"""
        self._only_in_a_job()
        return len(self.nodeset)

    @property
    def _in_a_job(self):
        return self.batchid != 0

    @property
    def mem_per_core(self):
        """Returns the amount of memory allocated per core in MB"""
        self._only_in_a_job()

        raw_output = subprocess_check_output(
            ['scontrol', 'show', 'jobid=%d' % (self.batchid)]).decode()

        # First, assume the memory was specified on a per cpu basis:
        match = re.search(r'MinMemoryCPU=(\d+)M', raw_output)
        if match:
            return int(match.group(1))

        match = re.search(r'MinMemoryCPU=(\d+)G', raw_output)
        if match:
            return int(match.group(1)) * 1024

        # Else, try a per node basis:
        match = re.search(r'MinMemoryNode=(\d+)M', raw_output)
        if match:
            return int(match.group(1)) // self.num_cores

        match = re.search(r'MinMemoryNode=(\d+)G', raw_output)
        if match:
            return int(match.group(1)) * 1024 // self.num_cores

        raise BatchError("Failed to read memory per core")

    @property
    def num_cores(self):
        """Returns the number of cores allocated per task

        Only valid for hypervisor processes

        """
        self._only_in_a_job()

        try:
            return int(os.environ['SLURM_CPUS_PER_TASK'])
        except KeyError:
            # The variable isn't defined when not
            # provided explicitely
            return 1

    @property
    def coreset(self):
        """Returns the list of cores allocated to the current task

        Only valid for hypervisor processes
-
        """
        self._only_in_a_job()
        # Assume we've been bound to our cores by SLURM
        taskset = subprocess_check_output(['hwloc-bind', '--get']).decode().strip()
        coreset = subprocess_check_output(['hwloc-calc', '--intersect', 'Core',
                                           taskset]).decode().strip()

        return RangeSet(coreset)

    def get_host_rank(self, rank):
        """Returns rank of the host where the specified task rank runs"""
        self._only_in_a_job()
        return self._rank_map[rank]

    def get_rank_on_host(self, rank):
        """Returns the relative rank of the specified task rank on its host

        """
        self._only_in_a_job()
        host_rank = self._rank_map[rank]
        rank_on_host = 0

        while ( (rank - rank_on_host >= 0) and
                (self._rank_map[rank - rank_on_host] == host_rank) ):
            rank_on_host = rank_on_host + 1

        return rank_on_host - 1

    def populate_env(self):
        """ Populate environment variables with batch related info to propagate """
        os.environ['PCOCC_JOB_ID'] = str(self.batchid)
        try:
            os.environ.get('SLURM_JOB_ID')
        except:
            os.environ['SLURM_JOB_ID'] =  self.batchid

        os.environ['PCOCC_JOB_NAME'] =  os.environ.get('SLURM_JOB_NAME', '')
        os.environ['PCOCC_ALLOCATION'] =  '1'
