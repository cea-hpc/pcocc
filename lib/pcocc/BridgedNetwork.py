import os
import logging
import random
import yaml

from .Networks import  VNetwork
from .Config import Config
from .NetUtils import bridge_exists, TAP, NetworkSetupError


class VBridgedNetwork(VNetwork):
    _schema=yaml.load("""
properties:
  type:
      enum:
        - bridged
        - bridged-ethernet

  settings:
    type: object
    properties:
      host-bridge:
       type: string
      tap-prefix:
       type: string
      mtu:
       type: integer
       default-value: 1500
    additionalProperties: false
    required:
     - host-bridge
     - tap-prefix
additionalProperties: false
""", Loader=yaml.CLoader)
    def __init__(self, name, settings):
        super(VBridgedNetwork, self).__init__(name)
        self._type = "bridged"

        self._host_bridge = settings["host-bridge"]
        self._tap_prefix = settings["tap-prefix"]
        self._mtu = int(settings.get("mtu", 1500))


    def init_node(self):
        if not bridge_exists(self._host_bridge):
            raise NetworkSetupError("Host bridge {0} doesn't exist".format(
                self._host_bridge))

    def cleanup_node(self):
        self._cleanup_stray_taps()

    def alloc_node_resources(self, cluster):
        net_res = {}

        for vm in cluster.vms:
            if not vm.is_on_node():
                continue

            if not self.name in vm.networks:
                continue

            vm_label = self._vm_res_label(vm)
            net_res[vm_label] = self._alloc_vm_res(vm)

        self.dump_resources(net_res)

    def free_node_resources(self, cluster):
        net_res = None
        for vm in cluster.vms:
            if not vm.is_on_node():
                continue

            if not self.name in vm.networks:
                continue

            if not net_res:
                net_res = self.load_resources()

            vm_label = self._vm_res_label(vm)
            self._cleanup_vm_res(net_res[vm_label])

    def load_node_resources(self, cluster):
        net_res = None
        for vm in cluster.vms:
            if not vm.is_on_node():
                continue

            if not self.name in vm.networks:
                continue

            if not net_res:
                net_res = self.load_resources()

            vm_label = self._vm_res_label(vm)

            try:
                hwaddr = os.environ['PCOCC_NET_{0}_HWADDR'.format(
                              self.name.upper())]
            except KeyError:
                hwaddr = [ 0x52, 0x54, 0x00,
                           random.randint(0x00, 0x7f),
                           random.randint(0x00, 0xff),
                           random.randint(0x00, 0xff) ]
                hwaddr = ':'.join(map(lambda x: "%02x" % x, hwaddr))

            vm.add_eth_if(self.name,
                          net_res[vm_label]['tap_name'],
                          hwaddr)

    def _cleanup_stray_taps(self):
        # Look for remaining taps to cleanup
        count = TAP.prefix_cleanup(self._tap_prefix)
        if count:
            logging.warning('Deleted %s leftover TAP(s) for %s network',
                    count,
                    self.name)

    def _alloc_vm_res(self, vm):
        tracker = Config().tracker

        tap = TAP.prefix_find_free(self._tap_prefix)
        tracker.create_with_ref(Config().batch.batchid, tap)

        tap.enable()
        tap.set_mtu(self._mtu)
        tap.connect(self._host_bridge)

        return {'tap_name': tap.name}

    def _cleanup_vm_res(self, resources):
        pass
