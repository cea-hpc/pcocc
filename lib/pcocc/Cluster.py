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


import multiprocessing
import sys
import yaml
import time
import logging
from Queue import Queue
from threading import Thread

import Batch
from Error import PcoccError
from Config import Config
from pcocc.scripts import click
from pcocc import Hypervisor

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

class Worker(Thread):
    """Thread executing tasks from a given tasks queue"""
    def __init__(self, pool):
        Thread.__init__(self)
        self.pool = pool
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.pool.tasks.get()
            try:
                func(*args, **kargs)
            except Exception as e:
                self.pool.exception=e
            finally:
                self.pool.tasks.task_done()

class ThreadPool:
    """Pool of threads consuming tasks from a queue"""
    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        self.exception = None
        for _ in range(num_threads): Worker(self)

    def add_task(self, func, *args, **kargs):
        """Add a task to the queue"""
        self.tasks.put((func, args, kargs))

    def wait_completion(self):
        """Wait for completion of all the tasks in the queue"""
        self.tasks.join()

        if not (self.exception is None):
            raise self.exception

def do_checkpoint_vm(vm, ckpt_dir):
    vm.checkpoint(ckpt_dir)

def do_save_vm(vm, ckpt_dir):
    if not vm.image_dir is None:
        vm.save(vm.checkpoint_img_file(ckpt_dir),
                freeze=Hypervisor.VM_FREEZE_OPT.NO)

def do_quit_vm(vm):
    vm.quit()


class VM(object):
    def __init__(self, rank, template):
        self.rank = rank
        self._template = template
        self.eth_ifs = {}
        self.vfio_ifs = {}
        self.mounts = {}

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

    def run(self, ckpt_dir=None):
        Config().hyp.run(self, ckpt_dir)

    def exec_cmd(self, cmd, user):
        return Config().hyp.exec_cmd(self, cmd, user)

    def put_file(self, source, dest):
        return Config().hyp.put_file(self, source, dest)

    def checkpoint(self, ckpt_dir):
        Config().hyp.checkpoint(self, ckpt_dir)

    def save(self, dest_file, full=False, freeze=Hypervisor.VM_FREEZE_OPT.TRY):
        Config().hyp.save(self, dest_file, full, freeze)

    def quit(self):
        Config().hyp.quit(self)

    def reset(self):
        Config().hyp.reset(self)

    def human_monitor_cmd(self, cmd):
        return Config().hyp.human_monitor_cmd(self, cmd)

    def dump(self, dumpfile):
        Config().hyp.dump(self, dumpfile)

    def wait_start(self):
        Config().hyp.wait_vm_start(self)
    @property
    def networks(self):
        return self._template.rset.networks

    @property
    def image_path(self):
        image_file, _ = self._template.resolve_image(self)
        return image_file

    @property
    def image_dir(self):
        if self._template.image is None:
            return None

        return Config().resolve_path(self._template.image, self)

    @property
    def revision(self):
        _, revision = self._template.resolve_image(self)
        return revision

    @property
    def mount_points(self):
        return self._template.mount_points

    @property
    def serial_ports(self):
        return ['taskcontrolport', 'taskioport', 'taskinputport',
                Hypervisor.QEMU_GUEST_AGENT_PORT]

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
    def disk_cache(self):
        return self._template.disk_cache

    @property
    def persistent_drives(self):
        return self._template.persistent_drives

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
                    tpl_name, tpl_count = tpl_def.split(':')
                else:
                    tpl_name, tpl_count = tpl_def, 1

                if resource_only:
                    tpl_name = Config().tpls.resource_template(tpl_name)

                tpl_count = int(tpl_count)
                for i in xrange(tpl_count):
                    self.vms.append(
                        VM(count + i, Config().tpls[tpl_name]))

                count += tpl_count
                self.resource_definition += '%s:%d,' % (
                    Config().tpls[tpl_name].rset.name, tpl_count)
        except KeyError as err:
            raise InvalidClusterError(repr(self.definition))

        self.resource_definition = self.resource_definition[:-1]

    def alloc_node_resources(self):
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
            for net in Config().vnets.values():
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

        for net in Config().vnets.values():
            net.free_node_resources(self)

    def load_node_resources(self):
        for net in Config().vnets.values():
            net.load_node_resources(self)

    def get_license_list(self):
        license_list = []
        for net in Config().vnets.values():
            license_list += net.get_license(self)

        return license_list

    def run(self, ckpt_dir=None):
        self.vms[Config().batch.task_rank].run(ckpt_dir)

    def exec_cmd(self, vmid_list, cmd, user):
        #TODO: This should be launched in parallel ala clush
        ret=[]
        for vmid in vmid_list:
            ret.append(self.vms[vmid].exec_cmd(cmd, user))

        return ret

    def checkpoint(self, ckpt_dir):
        pool = ThreadPool(16)

        print "Checkpointing disks..."
        for vm in self.vms:
            pool.add_task(do_save_vm, vm, ckpt_dir)
        pool.wait_completion()

        print "Checkpointing memory..."
        for vm in self.vms:
            pool.add_task(do_checkpoint_vm, vm, ckpt_dir)
        pool.wait_completion()

        print "Checkpoint complete."
        for vm in self.vms:
            pool.add_task(do_quit_vm, vm)
        pool.wait_completion()


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

        for i in range(5):
            try:
                host_states, index = batch.read_dir_index(
                    'cluster',
                    self._host_state_dir())
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

        done, last_state = self._check_all_host_states(host_states)
        if done:
            return

        with click.progressbar(
            show_eta = False,
            show_percent = False,
            length = 2,
            label = 'Configuring hosts...',
            bar_template = '%(label)s (%(info)s)',
            item_show_func = lambda x: x['desc'] if x else '') as bar:

            bar.current_item = last_state
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
                bar.update(1)
                if done:
                    break
