import os
import logging
import random

from .Networks import  VNetwork
from .Config import Config
from .NetUtils import VFIOInfinibandVF, ibdev_enable_vf_driver

class VHostIBNetwork(VNetwork):
    _schema = """
properties:
  type:
      enum:
        - host-infiniband
        - hostib

  settings:
    type: object
    properties:
      host-device:
       type: string
    additionalProperties: false
    required:
     - host-device
additionalProperties: false
"""

    def __init__(self, name, settings):
        super(VHostIBNetwork, self).__init__(name)

        self._type = "hostib"
        self._device_name = settings["host-device"]

    def init_node(self):
        # We can probably remove this once we get kernels with the
        # driver_override feature.  For now we need to use new_id but
        # this binds all unbound devices so we start by binding them
        # to pci-stub.
        ibdev_enable_vf_driver(self._device_name, 'pci-stub')
        ibdev_enable_vf_driver(self._device_name, 'vfio-pci')

    def cleanup_node(self):
        deleted_vfs = VFIOInfinibandVF.ibdev_cleanup(self._device_name)
        if deleted_vfs > 0:
            logging.warning(
                'Deleted {0} leftover VFs for {1} network'.format(
                    deleted_vfs, self.name))

    @staticmethod
    def _gen_guid_suffix():
        return ''.join(['%02x' % random.randint(0,0xff) for _ in xrange(6)])

    def alloc_node_resources(self, cluster):
        batch = Config().batch
        tracker = Config().tracker

        net_res = {}
        for vm in self._local_net_vms(cluster):
            try:
                port_guid = os.environ['PCOCC_NET_{0}_PORT_GUID'.format(
                                        self.name.upper())]
            except KeyError:
                port_guid ='0xc1cc' + self._gen_guid_suffix()

            try:
                node_guid = os.environ['PCOCC_NET_{0}_NODE_GUID'.format(
                                        self.name.upper())]
            except KeyError:
                node_guid ='0xd1cc' + self._gen_guid_suffix()

            try:
                dev = VFIOInfinibandVF.ibdev_find_free(
                    self._device_name,
                    batch.batchuser,
                    port_guid,
                    node_guid)

                tracker.create_with_ref(batch.batchid, dev)

                vm_label = self._vm_res_label(vm)
                net_res[vm_label] = {'vf_addr': dev.dev_addr}
            except Exception:
                self.dump_resources(net_res)
                raise

        self.dump_resources(net_res)

    def free_node_resources(self, cluster):
        pass

    def load_node_resources(self, cluster):
        net_res = None
        for vm in self._local_net_vms(cluster):
            if not net_res:
                net_res = self.load_resources()

            vm_label = self._vm_res_label(vm)
            vm.add_vfio_if(self.name,
                           net_res[vm_label]['vf_addr'])
