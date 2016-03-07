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
import re
import logging

from Error import PcoccError
from Singleton import Singleton
from os.path import expanduser

DEFAULT_CONF_DIR = os.path.join('/etc/pcocc')
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

class Config(object):
    __metaclass__ = Singleton
    def __init__(self):
        self.vnets = Networks.VNetworkConfig()
        self.rsets = Resources.ResSetConfig()
        self.tpls = Templates.TemplateConfig()

        # Initalize later depending on what's provided in the config files
        self.batch = None
        self.hyp = None

        self.debug = PCOCC_DEBUG_FLAG
        self.ckpt_retry_count = CKPT_RETRY_COUNT
        self.conf_dir = DEFAULT_CONF_DIR
        self._verbose = 0

    def load(self, conf_dir=DEFAULT_CONF_DIR, jobid=None, jobname=None,
             default_jobname=None, process_type=None, batchuser=None):
        logging.debug('Loading system config')
        self.load_vnets(os.path.join(conf_dir, 'networks.yaml'))
        self.load_rsets(os.path.join(conf_dir, 'resources.yaml'))
        self.load_tpls(os.path.join(conf_dir, 'templates.yaml'))
        self.load_batch(os.path.join(conf_dir, 'batch.yaml'), jobid,
                        jobname, default_jobname, process_type,
                        batchuser)

        # We can add a config file to select/configure the hypervisor
        # here if we feel the need
        self.hyp = Hypervisor.Qemu()

    def load_user(self, user_conf_dir=DEFAULT_USER_CONF_DIR):
        logging.debug('Loading user config')
        self.user_conf_dir = self.resolve_path(user_conf_dir)
        self.load_tpls(os.path.join(self.user_conf_dir,
                                    'templates.yaml'), required=False)

    def load_vnets(self, network_conf_file):
        self.vnets.load(network_conf_file)

    def load_rsets(self, resource_conf_file):
        self.rsets.load(resource_conf_file)

    def load_tpls(self, template_conf_file='templates.yaml', required=True):
        self.tpls.load(template_conf_file, required)

    def load_batch(self, batch_config_file, jobid, jobname, default_jobname,
                   process_type, batchuser):
        self.batch = Batch.BatchManager.load(batch_config_file, jobid,
                                             jobname, default_jobname,
                                             process_type, batchuser)
    def config_node(self):
        for vnet in self.vnets:
            self.vnets[vnet].init_node()

    def cleanup_node(self):
        for vnet in self.vnets:
            self.vnets[vnet].cleanup_node()

    def reset(self):
        self.vnets = Networks.VNetworkConfig()
        self.rsets = Resources.ResSetConfig()
        self.tpls = Templates.TemplateConfig()
        self.batch = None

    def resolve_path(self, path, vm=None):
        tpl = TemplatePath(path)
        tplvalues = {}

        try:
           tplvalues['clusterdir'] = self.batch.cluster_state_dir
        except AttributeError:
            pass

        for key, val in os.environ.iteritems():
            tplvalues['env:%s' % (key)] = val

        tplvalues['user'] =  self.batch.batchuser,
        tplvalues['homedir'] =  expanduser("~")

        if vm:
            tplvalues['vm_rank'] = vm.rank

        return expanduser(tpl.safe_substitute(tplvalues))

    @property
    def verbose(self):
        return self._verbose

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

import Networks
import Resources
import Templates
import Batch
import Hypervisor
