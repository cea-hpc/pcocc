import os
import logging
import psutil
import yaml
import re
import jsonschema
import tempfile
import shutil
import stat
import signal

from .Config import Config
from .NetUtils import VFIOInfinibandVF
from .HostIBNetwork import VHostIBNetwork
from .Misc import IDAllocator
from .Error import PcoccError
from .NetUtils import NetworkSetupError, ibdev_get_guid

class VIBNetwork(VHostIBNetwork):
    _schema=yaml.load("""
properties:
  type:
      enum:
        - infiniband
        - ib

  settings:
    type: object
    properties:
      host-device:
       type: string
      min-pkey:
       type: string
       pattern: "^0x[0-9a-zA-Z]{4}$"
      max-pkey:
       type: string
       pattern: "^0x[0-9a-zA-Z]{4}$"
      license:
       type: string
      opensm-daemon:
       type: string
      opensm-partition-cfg:
       type: string
      opensm-partition-tpl:
       type: string
    additionalProperties: false
    required:
     - min-pkey
     - max-pkey
     - host-device
     - opensm-daemon
     - opensm-partition-cfg
     - opensm-partition-tpl

additionalProperties: false
""", Loader=yaml.CLoader)

    # Schema to validate individual pkey entries in the key/value store
    _pkey_entry_schema = yaml.load("""
type: object
properties:
  vf_guids:
    type: array
    items:
      type: string
      pattern: "^0x[0-9a-zA-Z]{16}$"
  host_guids:
    type: array
    items:
      type: string
      pattern: "^0x[0-9a-zA-Z]{16}$"
required:
    - vf_guids
    - host_guids
""", Loader=yaml.CLoader)

    def __init__(self, name, settings):
        super(VIBNetwork, self).__init__(name, settings)

        self._type = "ib"
        self._device_name = settings["host-device"]
        self._min_pkey   = int(settings["min-pkey"], 0)
        self._max_pkey   = int(settings["max-pkey"], 0)
        self._license_name = settings.get("license", None)
        self._opensm_partition_cfg = settings["opensm-partition-cfg"]
        self._opensm_partition_tpl = settings["opensm-partition-tpl"]
        self._opensm_daemon = settings["opensm-daemon"]

        self._ida = IDAllocator(self._get_type_key_path('pkey_alloc_state'),
                                self._max_pkey - self._min_pkey + 1)

    def alloc_node_resources(self, cluster):
        batch = Config().batch
        net_res = {}

        # First pass, find out which Hosts/VMs need to be managed
        net_hosts = set()
        node_vms = []
        for vm in self._net_vms(cluster):
            net_hosts.add(vm.get_host_rank())
            if vm.is_on_node():
                node_vms.append(vm)

        # No VM on node, nothing to do
        if not node_vms:
            return

        # First host becomes master for setting up this network
        master = min(net_hosts)

        # Master allocates a pkey and broadcasts to the others
        if batch.node_rank == master:
            logging.info("Node is master for IB network %s",
                         self.name)
        try:
            pkey_index = self._ida.coll_alloc_one(master, '{0}_pkey'.format(self.name))
        except PcoccError as e:
            raise NetworkSetupError('{0}: {1}'.format(
                    self.name,
                    str(e)
                    ))

        my_pkey = self._min_pkey + pkey_index
        logging.info("Using PKey 0x%04x for network %s",
                     my_pkey,
                     self.name)

        # Write guids needed for our host
        host_guid = ibdev_get_guid(self._device_name)
        batch.write_key(
            'cluster',
            self._get_net_key_path('guids/' + str(batch.node_rank)),
            host_guid)

        # Master waits until all hosts have written their guids
        # and updates opensm
        if batch.node_rank == master:
            logging.info("Collecting GUIDs from all hosts for %s",
                         self.name)
            global_guids = batch.wait_child_count('cluster',
                                                  self._get_net_key_path('guids'),
                                                  len(net_hosts))
            sm_config = {}
            sm_config['host_guids'] = [ str(child.value) for child
                                       in global_guids.children ]
            sm_config['vf_guids'] = [ vm_get_port_guid(vm, my_pkey) for vm
                                      in cluster.vms
                                      if self.name in vm.networks ]

            logging.info("Requesting OpenSM update for %s",
                         self.name)
            batch.write_key('global', 'opensm/pkeys/' + str(hex(my_pkey)),
                            sm_config)

        net_res['master'] = master
        net_res['pkey'] = my_pkey
        net_res['pkey_index'] = pkey_index

        # Setup VFs for our VMs
        for vm in node_vms:
            try:
                device_name = self._device_name

                dev = VFIOInfinibandVF.ibdev_find_free(device_name, batch.batchuser,
                                                       vm_get_port_guid(vm, my_pkey),
                                                       vm_get_node_guid(vm, my_pkey), my_pkey)

                Config().tracker.create_with_ref(batch.batchid, dev)

                vm_label = self._vm_res_label(vm)
                net_res[vm_label] = {'vf_addr': dev.dev_addr}
            except Exception as e:
                self.dump_resources(net_res)
                raise

        self.dump_resources(net_res)

    def free_node_resources(self, cluster):
        master = -1
        batch = Config().batch

        for _ in self._local_net_vms(cluster):
            net_res = self.load_resources()
            master = net_res['master']
            break

        if master == batch.node_rank:
            # Update opensm
            pkey_key =  'opensm/pkeys/' + str(hex(net_res['pkey']))
            batch.delete_key('global', pkey_key)

            # Free pkey
            try:
                self._ida.free_one(net_res['pkey_index'])
            except PcoccError as e:
                raise NetworkSetupError('{0}: {1}'.format(
                    self.name,
                    str(e)
                ))

            # Cleanup keystore
            batch.delete_dir(
                'cluster',
                self._get_net_key_path(''))

    def pkey_daemon(self):
        batch = Config().batch

        while True:
            pkeys = {}
            pkey_path = batch.get_key_path('global', 'opensm/pkeys')

            # Read config for all pkeys
            ret, last_index  = batch.read_dir_index('global', 'opensm/pkeys')
            while not ret:
                logging.warning("PKey path doesn't exist")
                ret, last_index  = batch.wait_key_index('global',
                                                        'opensm/pkeys',
                                                        last_index,
                                                        timeout=0)

            logging.info("PKey change detected: refreshing configuration")

            for child in ret.children:
                # Ignore directory key
                if child.key == pkey_path:
                    continue

                # Find keys matching a valid PKey value
                m = re.match(r'{0}/(0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f])$'.format(pkey_path), child.key)
                if not m:
                    logging.warning("Invalid entry in PKey directory: " +
                                    child.key)
                    continue
                pkey = m.group(1)

                # Load configuration and validate against schema
                try:
                    config = yaml.safe_load(child.value)
                    jsonschema.validate(config,
                                        self._pkey_entry_schema)
                    pkeys[pkey] = config
                except yaml.YAMLError as e:
                    logging.warning("Misconfigured PKey %s: %s",
                                    pkey, e)
                    continue
                except jsonschema.ValidationError as e:
                    logging.warning("Misconfigured PKey %s: %s",
                                    pkey, e)
                    continue

            tmp = tempfile.NamedTemporaryFile(delete=False)
            with open(self._opensm_partition_tpl) as f:
                lines = f.readlines()
                tmp.writelines(lines)

            tmp.write('\n')

            for pkey, config in pkeys.iteritems():
                partline = 'PK_{0}={0} , ipoib'.format(pkey)
                for vf_guids in chunks(config['vf_guids'], 128):
                    partline_vf = ', indx0 : ' + ', '.join(g + '=full'
                                                           for g in vf_guids)
                    tmp.write(partline + partline_vf + ' ; \n')

                partline += ': '

                for host_guids in chunks(config['host_guids'], 128):
                    tmp.write(partline +
                              ', '.join(g + '=full'
                                        for g in host_guids) +
                              ' ; \n')

            tmp.close()
            shutil.move(tmp.name, self._opensm_partition_cfg)
            os.chmod(self._opensm_partition_cfg,
                     stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH | stat.S_IRGRP)


            for proc in psutil.process_iter():
                if isinstance(proc.name, basestring):
                    procname = proc.name
                else:
                    procname = proc.name()

                if procname == self._opensm_daemon:
                    proc.send_signal(signal.SIGHUP)

            # Wait for next update
            batch.wait_key_index('global', 'opensm/pkeys', last_index,
                                 timeout=0)


def chunks(array, n):
    """Yield successive n-sized chunks from array."""
    for i in range(0, len(array), n):
        yield array[i:i+n]

def vm_get_port_guid(vm, pkey_id):
    pkey_high = pkey_id // 0x100
    pkey_low = pkey_id % 0x100
    vm_high = vm.rank // 0x100
    vm_low = vm.rank % 0x100

    return '0xc0cc{0:02x}{1:02x}00{2:02x}{3:02x}00'.format(pkey_high, pkey_low,
                                                        vm_high, vm_low)

def vm_get_node_guid(vm, pkey_id):
    pkey_high = pkey_id // 0x100
    pkey_low = pkey_id % 0x100
    vm_high = vm.rank // 0x100
    vm_low = vm.rank % 0x100

    return '0xd0cc{0:02x}{1:02x}00{2:02x}{3:02x}00'.format(pkey_high, pkey_low,
                                                            vm_high, vm_low)
