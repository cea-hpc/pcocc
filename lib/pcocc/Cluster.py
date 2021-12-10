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

import sys
import yaml
import time
import logging
import threading
import etcd
import click

from . import Hypervisor
from . import Batch
from .Error import PcoccError
from .Config import Config

from .Tbon import TreeNode, TreeClient
from .Templates import DRIVE_IMAGE_TYPE

class InvalidClusterError(PcoccError):
    """Exception raised when the cluster definition cannot be parsed
    """
    def __init__(self, error):
        super(InvalidClusterError, self).__init__('Unable to parse cluster '
                                                  'definition: '
                                                  + error)

class InvalidVMError(PcoccError):
    """Exception raised when referencing an invalid VM
    """
    def __init__(self, index, error):
        super(InvalidVMError, self).__init__('Unable to reference vm%s: %s'%(index, error))

class ClusterSetupError(PcoccError):
    """Exception raised when there was an error during cluster setup
    """
    def __init__(self, error):
        super(ClusterSetupError, self).__init__('Failed to start cluster: ' + error)

class VM(object):
    def __init__(self, rank, template):
        self.rank = rank
        self._template = template
        self.eth_ifs = {}
        self.vfio_ifs = {}
        self.mounts = {}

        # Local access to the VM agent through the hypervisor
        self._agent = None
        # Client to access to the agent of a remote VM
        self._agent_client = None
        # Server implementing the remote access to a VM
        self._agent_server = None
        # The agent client is initialized lazily on demand
        # so make sure it's only initialized by one thread
        self._agent_client_lock = threading.Lock()

    def from_repo(self):
        return self._template.from_repo()

    def image_repo_infos(self):
        return self._template.image_repo_infos()

    def is_on_node(self):
        return Config().batch.is_rank_local(self.rank)

    def get_host(self):
        return Config().batch.get_rank_host(self.rank)

    def get_host_rank(self):
        return Config().batch.get_host_rank(self.rank)

    def add_eth_if(self, net_name, tap, hwaddr, host_port=""):
        self.eth_ifs[net_name] = {
            'tap': tap,
            'hwaddr': hwaddr}
        if host_port:
            self.eth_ifs[net_name]['host_port'] = host_port

    def add_vfio_if(self, net_name, vf_name):
        self.vfio_ifs[net_name] = {
            'vf_name': vf_name
        }

    def enable_agent_server(self, hypervisor_agent):
        self._agent = hypervisor_agent
        self._agent_server = TreeNode(
            vmid    = self.rank,
            handler = self._agent.message_handler,
            stream_init_handler = self._agent.stream_init_handler
        )

    @property
    def agent_client(self):
        self._agent_client_lock.acquire()
        if self._agent_client is None:
            key_name =  "hostagent/vms/" + str(self.rank)
            root_info = Config().batch.read_key(
                "cluster/user",
                key_name,
                blocking=True
            )
            info = root_info.split(":")
            if len(info) != 3:
                raise Exception("Failed to parse VM info")
            self._agent_client = TreeClient(info)
        self._agent_client_lock.release()

        return self._agent_client

    def run(self, ckpt_dir=None, user_data=None, docker=False):
        return Config().hyp.run(self, ckpt_dir, user_data, docker=docker)

    def exec_cmd(self, cmd, user):
        return Config().hyp.exec_cmd(self, cmd, user)

    def put_file(self, source, dest):
        return Config().hyp.put_file(self, source, dest)

    def wait_start(self):
        Config().hyp.wait_vm_start(self.rank)

    @property
    def networks(self):
        return self._template.rset.networks

    @property
    def image_path(self):
        image_file, _ = self._template.resolve_image(self)
        return image_file

    @property
    def image_type(self):
        return self._template.image_type(self)

    @property
    def image(self):
        return self._template.image

    @property
    def image_dir(self):
        if self.image_type != DRIVE_IMAGE_TYPE.DIR:
            raise PcoccError("VM image is not a directory")

        return Config().resolve_path(self._template.image, self)

    @property
    def block_drives(self):
        drives = []
        idx = 0
        if self.image:
            drives.append({'image': self.image,
                           'name': 'drive0',
                           'path': self.image_path,
                           'type': self.image_type,
                           'persistent': False})
            idx+=1

        for path, settings in list(self.persistent_drives.items()):
            drives.append({
                    'image': settings['backup'],
                    'name': 'drive'+str(idx),
                    'path': Config().resolve_path(path, self),
                    'type': DRIVE_IMAGE_TYPE.REPO,
                    'persistent': False})
            idx+=1

        return drives
    @property
    def revision(self):
        _, revision = self._template.resolve_image(self)
        return revision

    @property
    def mount_points(self):
        if self._template.mount_points == []:
            #Handle the empty case to make sure
            #this is always a dict
            self._template.mount_points = {}
        return self._template.mount_points

    @property
    def serial_ports(self):
        return ['taskcontrolport', 'taskioport', 'taskinputport',
                 'pcocc_agent', Hypervisor.QEMU_GUEST_AGENT_PORT]

    @property
    def user_data(self):
        return self._template.user_data

    @property
    def instance_id(self):
        return self._template.instance_id

    @property
    def full_node(self):
        return self._template.full_node

    @property
    def bind_vcpus(self):
        return self._template.bind_vcpus

    @property
    def disk_cache(self):
        return self._template.disk_cache

    @property
    def persistent_drives(self):
        return self._template.persistent_drives

    @property
    def machine_type(self):
        return self._template.machine_type

    @property
    def disk_model(self):
        return self._template.disk_model

    @property
    def remote_display(self):
        return self._template.remote_display

    @property
    def wait_for_poweroff(self):
        if self._template.persistent_drives:
            return True
        else:
            return False

    @property
    def qemu_bin(self):
        return self._template.qemu_bin

    @property
    def kernel(self):
        return self._template.kernel

    @property
    def custom_args(self):
        return self._template.custom_args

    @property
    def nic_model(self):
        return self._template.nic_model

    @property
    def rank_on_host(self):
        return Config().batch.get_rank_on_host(self.rank)

    @property
    def emulator_cores(self):
        return self._template.emulator_cores

    @property
    def state(self):
        state, _ = Config().hyp.get_vm_state(self.rank)
        return state

    def checkpoint_img_file(self, ckpt_dir):
        return Config().hyp.checkpoint_img_file(self, ckpt_dir)

class VMList(list):
    def __getitem__(self, item):
        try:
            return list.__getitem__(self, item)
        except IndexError as err:
            raise InvalidVMError(item, str(err))

class Cluster(object):
    def __init__(self, template_string, vms_per_node="", resource_only=False):
        self.vms = VMList()
        self.resource_definition = ""
        self.definition = template_string

        count = 0
        # Parse definition to generate the list of VMs
        try:
            for tpl_def in template_string.split(','):
                tpl_def = tpl_def.strip()

                if ':' in tpl_def:
                    spl = tpl_def.split(':')
                    #Here we handle the case 'repo:vm:count'
                    tpl_name, tpl_count = ":".join(spl[0:len(spl)-1]), spl[len(spl)-1]
                else:
                    tpl_name, tpl_count = tpl_def, 1

                if resource_only:
                    tpl_name = Config().tpls.resource_template(tpl_name)

                tpl_count = int(tpl_count)
                for i in range(tpl_count):
                    self.vms.append(
                        VM(count + i, Config().tpls[tpl_name]))

                count += tpl_count
                self.resource_definition += '%s:%d,' % (
                    Config().tpls[tpl_name].rset.name, tpl_count)
        except KeyError:
            raise InvalidClusterError(repr(self.definition))

        self.resource_definition = self.resource_definition[:-1]

    def vm_count(self):
        return len(self.vms)

    def alloc_node_resources(self):
        destroyed, index = Config().batch.read_key_index('cluster', 'destroyed')

        if destroyed:
            logging.error("Stale cluster dirs found")
            if Config().batch.node_rank != 0:
                Config().batch.wait_key_index('cluster', 'destroyed', index,
                                              timeout=60)
            else:
                logging.error("Destroying cluster dirs")
                Config().batch.delete_dir('cluster', '')
                try:
                    Config().batch.delete_dir('cluster/user', '')
                except etcd.EtcdKeyNotFound:
                    pass

        self._set_host_state('network-config',
                             1,
                             'configuring networks',
                             None)
        try:
            if Config().batch.node_rank == 0:
                Config().batch.init_cluster_keys()
        except:
            self._set_host_state('failed',
                                 -1,
                                 'failed to setup keystore for user ',
                                 None)
            raise
        try:
            for net in list(Config().vnets.values()):
                net.alloc_node_resources(self)

        except Exception as e:
            self._set_host_state('failed',
                                 -1,
                                 'failed to setup network ' + net.name,
                                 str(e))
            raise

        self._set_host_state('complete',
                             2,
                             'done',
                             None)

    def free_node_resources(self):
        Config().batch.cleanup_cluster_keys()

        for net in list(Config().vnets.values()):
            net.free_node_resources(self)

    def load_node_resources(self):
        for net in list(Config().vnets.values()):
            net.load_node_resources(self)

    def get_license_list(self):
        license_list = []
        for net in list(Config().vnets.values()):
            license_list += net.get_license(self)

        return license_list

    def run(self, ckpt_dir=None, user_data=None, docker=False):
        self.vms[Config().batch.task_rank].run(ckpt_dir, user_data, docker)

    def exec_cmd(self, vmid_list, cmd, user):
        #TODO: This should be launched in parallel ala clush
        ret=[]
        for vmid in vmid_list:
            ret.append(self.vms[vmid].exec_cmd(cmd, user))

        return ret


    def _set_host_state(self, state, priority, desc, value, host_rank=None):
        Config().batch.write_key('cluster',
                                       self._host_state_key(host_rank),
                                       yaml.dump({'state': state,
                                                  'priority': priority,
                                                  'desc': desc,
                                                  'value': value}))

    def _unpack_host_state(self, value):
        if value:
            return yaml.safe_load(value)
        else:
            return {'state': 'not-started',
                    'priority': 0,
                    'desc': 'waiting for batch manager',
                    'value': None}

    def _host_state_dir(self):
        return "state/hosts"

    def _host_state_key(self, host_rank=None):
        if host_rank == None:
            host_rank = Config().batch.node_rank
            if host_rank == -1:
                host_rank = 0
        return '{0}/{1}'.format(self._host_state_dir(), host_rank)

    def _check_host_state(self, host_state):
        if host_state['state'] == 'complete':
            return True
        elif host_state['state'] == 'failed':
            raise ClusterSetupError(host_state['desc'])
        else:
            return False

    def _check_all_host_states(self, host_states):
        if host_states == None:
            return False, self._unpack_host_state(host_states)

        host_states = [ self._unpack_host_state(s.value)
                        for s in host_states.children ]

        num_complete = sum([ 1 for s in host_states if
                             self._check_host_state(s)])

        if num_complete == Config().batch.num_nodes:
            return True, host_states[0]
        elif len(host_states) != Config().batch.num_nodes:
            return False, self._unpack_host_state(None)
        else:
            return False, min(host_states,
                                 key=lambda x: x['priority'])

    def wait_host_config(self, host_rank=None):
        """Waits for hosts to be configured"""

        batch = Config().batch

        # The key store may not know the user yet in which case
        # we cannot query it to learn the config state.
        i = 0
        for i in range(5):
            try:
                destroyed, index = Config().batch.read_key_index('cluster', 'destroyed')
                break
            except Batch.KeyCredentialError:
                if i == 0:
                    logging.info('User unknown, is this your first job ?')
                time.sleep(1 + i*2)
                continue
        else:
            raise Batch.KeyCredentialError('access denied')

        # Greet the user if we had to wait for its credentials to be populated
        if i > 0:
            sys.stderr.write('User credentials added to keystore: '
                             'welcome to pcocc !\n')

        # The jobid was used by a previoius cluster, wait for cleanup
        if destroyed:
            logging.info("Stale cluster dir, waiting for cleanup")
            Config().batch.wait_key_index('cluster', 'destroyed', index)

        host_states, index = batch.read_dir_index(
            'cluster',
            self._host_state_dir())

        done, last_state = self._check_all_host_states(host_states)
        if done:
            return

        with click.progressbar(
            show_eta = False,
            show_percent = False,
            file=sys.stderr,
            length = 2,
            label = 'Configuring hosts...',
            bar_template = '%(label)s (%(info)s)',
            item_show_func = lambda x: x['desc'] if x else '') as bar:

            bar.current_item = last_state
            if sys.stderr.isatty():
                bar.update(0)

            while True:
                batch.wait_key_index(
                    'cluster',
                    self._host_state_dir(),
                    index)

                host_states, index = batch.read_dir_index(
                    'cluster',
                    self._host_state_dir())

                done, last_state = self._check_all_host_states(host_states)
                bar.current_item = last_state
                if sys.stderr.isatty():
                    bar.update(1)

                logging.debug("Seen host state " + str(last_state))

                if done:
                    logging.debug("Finished wiating for host states")
                    break
