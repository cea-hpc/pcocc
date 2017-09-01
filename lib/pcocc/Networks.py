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

import jsonschema
import yaml

from abc import ABCMeta, abstractmethod
from .Error import  InvalidConfigurationError
from .Config import Config
from .Misc import DefaultValidatingDraft4Validator
from .NetUtils import NetworkSetupError

network_config_schema = """
type: object
patternProperties:
  "^([a-zA-Z][a-zA-Z_0-9--]*)$":
    oneOf:
additionalProperties: false

definitions:
  additionalProperties: false
"""

class VNetworkConfig(dict):
    """Manages the network configuration"""
    def load(self, filename):
        """Loads the network config

        Instantiates a dict holding a VNetwork class for each configured
        network

        """
        try:
            stream = file(filename, 'r')
            net_config = yaml.safe_load(stream)
        except yaml.YAMLError as err:
            raise InvalidConfigurationError(str(err))
        except IOError as err:
            raise InvalidConfigurationError(str(err))

        try:
            validator = DefaultValidatingDraft4Validator(VNetwork.schema)
            validator.validate(net_config)
        except jsonschema.exceptions.ValidationError as err:
            #FIXME when err.path doesnt exist (error at top level)
            message = "failed to parse configuration for network {0} \n".format(err.path[0])
            sortfunc = jsonschema.exceptions.by_relevance(frozenset(['oneOf', 'anyOf', 'enum']))
            best_errors = sorted(err.context, key=sortfunc, reverse=True)
            for e in best_errors:
                if (len(e.schema_path) == 4 and e.schema_path[1] == 'properties' and
                    e.schema_path[2] ==  'type' and e.schema_path[3] == 'enum'):
                    continue
                else:
                    message += str(e.message)
                    break
            else:
                for e in best_errors:
                    message += '\n' + str(e.message)

            raise InvalidConfigurationError(message)

        for name, net_attr in net_config.iteritems():
            self[name] = VNetwork.create(net_attr['type'],
                                         name,
                                         net_attr['settings'])

class VNetworkClass(ABCMeta):
    def __init__(cls, name, bases, dct):
        if '_schema' in dct:
            VNetwork.register_network(dct['_schema'], cls)
        super(VNetworkClass, cls).__init__(name, bases, dct)

class VNetwork(object):
    __metaclass__ = VNetworkClass

    """Base class for all network types"""
    _networks = {}
    _type = None
    schema = ""

    @classmethod
    def register_network(cls, subschema, network_class):
        if not cls.schema:
            cls.schema = yaml.safe_load(network_config_schema)

        subschema = yaml.safe_load(subschema)

        types = subschema['properties']['type']['enum']

        for t in types:
            cls._networks[t] = network_class

        refs = cls.schema['patternProperties']\
            ['^([a-zA-Z][a-zA-Z_0-9--]*)$']

        if refs['oneOf']:
            refs['oneOf'].append({'$ref': '#/definitions/{0}'.format(types[0])})
        else:
            refs['oneOf'] = [{'$ref': '#/definitions/{0}'.format(types[0])}]

        cls.schema['definitions'][types[0]] = subschema

    @classmethod
    def create(cls, ntype, name, settings):
        """Factory function to create subclasses"""
        if ntype in cls._networks:
            return cls._networks[ntype](name, settings)

        raise InvalidConfigurationError("Unknown network type: " + ntype)

    def __init__(self, name):
        self.name = name

    def get_license(self, cluster):
        """Returns a list of batch licenses that must be allocated
        to instantiate the network"""
        return []

    def dump_resources(self, res):
        """Store config data describing the allocated resources
        in the key/value store

        Called when setting up a node for a virtual cluster

        """
        batch = Config().batch
        batch.write_key(
            'cluster',
            '{0}/{1}'.format(self.name, batch.node_rank),
            yaml.dump(res))

    def load_resources(self):
        """Read config data describing the allocated resources
        from the key/value store"""
        batch = Config().batch
        data = batch.read_key(
            'cluster',
            '{0}/{1}'.format(self.name, batch.node_rank))

        if not data:
            raise NetworkSetupError('unable to load resources for network '
                                    + self.name)

        return yaml.safe_load(data)

    @abstractmethod
    def init_node(self):
        pass

    @abstractmethod
    def cleanup_node(self):
        pass

    @abstractmethod
    def alloc_node_resources(self, cluster):
        pass

    @abstractmethod
    def free_node_resources(self, cluster):
        pass

    @abstractmethod
    def load_node_resources(self, cluster):
        pass

    def _net_vms(self, cluster):
        for vm in cluster.vms:
            if self.name in vm.networks:
                yield vm

    def _local_net_vms(self, cluster):
        for vm in self._net_vms(cluster):
            if vm.is_on_node():
                yield vm

    def _vm_res_label(self, vm):
        return "vm-%d" % vm.rank

    def _get_net_key_path(self, key):
        """Returns path in the key/value store for a per network instance
        key

        """
        return  'net/name/{0}/{1}'.format(self.name, key)

    def _get_type_key_path(self, key):
        """Returns path in the key/value store for a per network type
        key

        """
        return  'net/type/{0}/{1}'.format(self._type, key)


# At the end to prevent circular includes
import pcocc.EthNetwork  # pylint: disable=W0611
import pcocc.IBNetwork  # pylint: disable=W0611
import pcocc.HostIBNetwork  # pylint: disable=W0611
import pcocc.BridgedNetwork  # pylint: disable=W0611
import pcocc.DeprecatedNetworks  # pylint: disable=W0611
