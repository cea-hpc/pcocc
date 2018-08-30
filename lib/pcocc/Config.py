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
import string
import logging
import errno
import fcntl
import pwd
import pcocc
from pcocc.Singleton import Singleton
from os.path import expanduser
from .NetUtils import Tracker

DEFAULT_CONF_DIR = '/etc/pcocc'
DEFAULT_RUN_DIR = '/var/run/pcocc'
DEFAULT_USER_CONF_DIR = os.environ.get('PCOCC_USER_CONF_DIR', '%homedir/.pcocc/')
PCOCC_DEBUG_FLAG = False
CKPT_RETRY_COUNT = 1


class TemplatePath(string.Template):
    delimiter = '%'
    pattern = r"""
    \%(?:
      (?P<escaped>\%)             |   # Escape sequence of two delimiters
      (?P<named>[_a-z][_a-z0-9]*) |   # delimiter and a Python identifier
      {(?P<braced>.*?)}           |   # delimiter and a braced identifier
      (?P<invalid>)                   # Other ill-formed delimiter exprs
    )
    """

class Lock(object):
    """Simple flock based Lock"""
    def __init__(self, filename):
        self.filename = filename
        self.handle = open(filename, 'w')

    def acquire(self):
        fcntl.flock(self.handle, fcntl.LOCK_EX)

    def release(self):
        fcntl.flock(self.handle, fcntl.LOCK_UN)

    def __del__(self):
        self.handle.close()

class Config(object):
    __metaclass__ = Singleton
    def __init__(self):
        self.vnets  = pcocc.Networks.VNetworkConfig()
        self.rsets  = pcocc.Resources.ResSetConfig()
        self.tpls   = pcocc.Templates.TemplateConfig()
        self.images = pcocc.Image.ImageMgr()

        # Initalize later depending on what's provided in the config files
        self.batch = None
        self.hyp = None

        self.debug = PCOCC_DEBUG_FLAG
        self.ckpt_retry_count = CKPT_RETRY_COUNT
        self.conf_dir = DEFAULT_CONF_DIR
        self._verbose = 0
        self._run_dir = DEFAULT_RUN_DIR

    def load(self, conf_dir=DEFAULT_CONF_DIR, jobid=None, jobname=None,
             default_jobname=None, process_type=None, batchuser=None):
        logging.debug('Loading system config')
        self.load_vnets(os.path.join(conf_dir, 'networks.yaml'))
        self.load_rsets(os.path.join(conf_dir, 'resources.yaml'))
        self.load_tpls(os.path.join(conf_dir, 'templates.yaml'))
        if jobid is None:
            jobid = os.getenv('PCOCC_LOCAL_JOB_ID')
        self.load_batch(os.path.join(conf_dir, 'batch.yaml'), jobid,
                        jobname, default_jobname, process_type,
                        batchuser)

        if process_type == Batch.ProcessType.SETUP:
            self.load_tracker()

        # We can add a config file to select/configure the hypervisor
        # here if we feel the need
        self.hyp = Hypervisor.Qemu()

    def load_user(self, user_conf_dir=DEFAULT_USER_CONF_DIR, conf_dir=DEFAULT_CONF_DIR):
        logging.debug('Loading user config')
        self.user_conf_dir = self.resolve_path(user_conf_dir)
        self.load_tpls(os.path.join(self.user_conf_dir,
                                    'templates.yaml'), required=False)

        tpl_dir = os.path.join(self.user_conf_dir, 'templates.d')
        if os.path.isdir(tpl_dir):
            for tpl_file in os.listdir(tpl_dir):
                if tpl_file.endswith('.yaml'):
                    self.load_tpls(os.path.join(tpl_dir, tpl_file), required=False)

        user_repos_path = os.path.join(self.user_conf_dir, 'repos.yaml')
        if os.path.exists(user_repos_path):
            self.load_repos(user_repos_path, 'user')
        self.load_repos(os.path.join(conf_dir, 'repos.yaml'), 'global')


    def load_vnets(self, network_conf_file):
        self.vnets.load(network_conf_file)

    def load_repos(self, repo_conf_file, tag):
        self.images.load_repos(repo_conf_file, tag)

    def load_rsets(self, resource_conf_file):
        self.rsets.load(resource_conf_file)

    def load_tpls(self, template_conf_file='templates.yaml', required=True):
        self.tpls.load(template_conf_file, required)

    def load_batch(self, batch_config_file, jobid, jobname, default_jobname,
                   process_type, batchuser):
        self.batch = Batch.BatchManager.load(batch_config_file, jobid,
                                             jobname, default_jobname,
                                             process_type, batchuser)

    def load_tracker(self):
        self._init_run_dir()
        self.tracker = Tracker(os.path.join(self._run_dir,
                                            'net_tracker.db'))

    def config_node(self):
        for vnet in self.vnets:
            self.vnets[vnet].init_node()

    def cleanup_node(self):
        for vnet in self.vnets:
            self.vnets[vnet].cleanup_node()

    def reset(self):
        self.vnets = pcocc.Networks.VNetworkConfig()
        self.rsets = pcocc.Resources.ResSetConfig()
        self.tpls = pcocc.Templates.TemplateConfig()
        self.batch = None

    def resolve_path(self, path, vm=None):
        """ Resolve a path from a custom template string
        %{env:ENVVAR}   is expanded to the content of the environment variable ENVVAR
        %{clusterdir}   to a temporary directory to store per-cluster data
        %{vm_rank}      to the rank of the virtual machine
        %{user}         to the current user name
        %{homedir}      to home directory of the current user
        %{clusterowner} to the user name of the cluster owner
        """
        tpl = TemplatePath(path)
        tplvalues = {}

        try:
            tplvalues['clusterdir']  = self.batch.cluster_state_dir
            tplvalues['clusteruser'] = self.batch.batchuser
        except AttributeError:
            pass

        for key, val in os.environ.iteritems():
            tplvalues['env:%s' % (key)] = val

        tplvalues['homedir'] =  expanduser("~")
        tplvalues['user'] =  pwd.getpwuid(os.getuid()).pw_name

        if vm:
            tplvalues['vm_rank'] = vm.rank

        return expanduser(tpl.safe_substitute(tplvalues))


    def lock_node(self):
        self._init_run_dir()
        self._lock = Lock(os.path.join(self._run_dir, 'setup.lock'))
        self._lock.acquire()

    def release_node(self):
        self._lock.release()

    def _init_run_dir(self):
        try:
            os.makedirs(self._run_dir)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        os.chmod(self._run_dir, 0o700)

    @property
    def verbose(self):
        return self._verbose

    @property
    def verbose_opt(self):
        return ['-v'] * self._verbose

    @verbose.setter
    def verbose(self, value):
        self._verbose = value

        if self._verbose > 0:
            self.debug = True

        if self._verbose == 0:
            logging.basicConfig(level=logging.WARNING)
        elif self._verbose == 1:
            logging.basicConfig(level=logging.INFO)
        elif self._verbose >= 2:
            logging.basicConfig(level=logging.DEBUG)

# Put at the end after Config is defined to prevent circular imports issues
# when doing from x import Config. They will be imported before Config method
# which require them are called.
from . import Networks    # pylint: disable=W0611
from . import Resources   # pylint: disable=W0611
from . import Templates   # pylint: disable=W0611
from . import Batch       # pylint: disable=W0611
from . import Hypervisor  # pylint: disable=W0611
from . import Image      # pylint: disable=W0611
