import logging

from .Networks import  VNetwork
from .Config import Config
from .NetUtils import VFIODev, pci_enable_driver


class VGenericPCI(VNetwork):
    _schema="""
properties:
  type:
      enum:
        - genericpci

  settings:
    type: object
    properties:
      host-device-addrs:
       type: array
       items:
         type: string
      host-driver:
       type: string
    additionalProperties: false
    required:
     - host-device-addrs
     - host-driver
additionalProperties: false
"""

    def __init__(self, name, settings):
        super(VGenericPCI, self).__init__(name)
        self._type = "genericpci"
        self._device_addrs = settings["host-device-addrs"]
        self._host_driver = settings["host-driver"]

    def init_node(self):
        for dev_addr in self._device_addrs:
            pci_enable_driver(dev_addr, self._host_driver)
            pci_enable_driver(dev_addr, 'vfio-pci')

    def cleanup_node(self):
        deleted_devs = VFIODev.list_cleanup(self._device_addrs,
                                            'root',
                                            self._host_driver)

        if deleted_devs > 0:
            logging.warning(
                'Deleted %s leftover PCI devices of type %s',
                len(deleted_devs), self.name)

    def alloc_node_resources(self, cluster):
        batch = Config().batch
        tracker = Config().tracker
        net_res = {}

        for vm in self._local_net_vms(cluster):
            try:
                dev = VFIODev.list_find_free(self._device_addrs,
                                             batch.batchuser,
                                             self._host_driver)
                tracker.create_with_ref(batch.batchid, dev)

                vm_label = self._vm_res_label(vm)
                net_res[vm_label] = {'dev_addr': dev.dev_addr}
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
                           net_res[vm_label]['dev_addr'])
