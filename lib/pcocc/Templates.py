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

import yaml
import os
import re
import errno
import time
import logging
import pcocc.Image
from .scripts.Shine.TextTable import TextTable
from .Config import Config
from .Error import InvalidConfigurationError
from .Backports import OrderedDict


# For each valid setting, is it required, whats the default value and is it
# inheritable
template_settings = {'image': (False, None, True),
                     'resource-set': (True, None, True),
                     'ispod': (False, False, True),
                     'custom-args': (False, [], True),
                     'qemu-bin': (False, None, True),
                     'nic-model': (False, None, True),
                     'mount-points': (False, [], True),
                     'user-data': (False, None, True),
                     'instance-id': (False, None, True),
                     'inherits': (False, None, True),
                     'full-node': (False, False, True),
                     'emulator-cores': (False, 0, True),
                     'disk-cache': (False, 'unsafe', True),
                     'disk-model': (False, 'virtio', True),
                     'machine-type': (False, 'pc', True),
                     'remote-display': (False, None, True),
                     'description': (False, '', False),
                     'persistent-drives': (False, [], True),
                     'placeholder': (False, False, False)}

class TemplateConfig(dict):
    """Manages the VM template definitions"""
    def load(self, filename, required=True):
        """Loads a template configuration File

        Populates a dict holding a template class for each defined
        template

        """
        config = Config()

        try:
            stream = file(filename, 'r')
            tpl_config = yaml.safe_load(stream)
        except yaml.YAMLError as err:
            raise InvalidConfigurationError(str(err))
        except IOError as err:
            if required or err.errno != errno.ENOENT:
                raise InvalidConfigurationError(str(err))
            else:
                return

        # Define an empty template corresponding to each resource set
        for rset in config.rsets.iterkeys():
            name = self.resource_template(rset)
            if name not in self:
                self[name] = Template(name,
                                      {'resource-set': rset,
                                       'placeholder': True})

        if not tpl_config:
            return

        for name, tpl_attr in tpl_config.iteritems():
            if name[0] == '_':
                raise InvalidConfigurationError(
                    "template name \"%s\" is "
                    "restricted (starts with _)" % name)
            if name in self:
                raise InvalidConfigurationError(
                    "template name \"%s\" is "
                    "already in use" % name)

            for setting in tpl_attr:
                if not setting in template_settings:
                    raise InvalidConfigurationError(
                        "template \"%s\" has unknown setting \"%s\"" % (
                            name, setting))

            self[name] = Template(name, tpl_attr)

        # Finish validation once everything has been loaded
        for tpl in self.itervalues():
            if not tpl.placeholder:
                tpl.validate()

    def resource_template(self, tpl):
        return '___'+tpl


def extract_repo_revision(image):
    img_mgr = pcocc.Image.PcoccImage()
    img_path, img_meta = img_mgr.get_by_name(image)

    #First assume rev is 0
    rev=0
    # Do we rely on the KVS ?
    if img_path:
        # Were meta correctly loaded ?
        if img_meta:
            # Find all the images in the repo matching the rev pattern (if present)
            revs = img_mgr.find(img_meta['key'] + r"-rev(\d+)")
            # If there was some
            if len(revs):
                # Get the one with the highest name
                img_meta = sorted(revs, key=lambda k:int(k['key'].split("-rev")[-1]))[-1]
                # Retrieve its informations and replace the image
                img_path, _ = img_mgr.get_by_name(img_meta['repo'] + ":" + img_meta['key'])
                rev = img_meta['key'].split("-rev")[-1]
                logging.info("Retained " + img_meta['repo'] + ":" + img_meta['key'])
    return img_meta, img_path, rev



class Template(object):
    """Class holding a single template definition

    Template inheritance is automatically managed when accessing attributes

    """
    def __init__(self, name, settings):
        self.name = name
        self.settings = settings
        self.validated = False

    def __getattr__(self, attr):
        if attr == 'rset':
            resource_set = getattr(self, 'resource_set')
            try:
                return Config().rsets[resource_set]
            except KeyError:
                raise InvalidConfigurationError(
                    "template \"%s\" has an "
                    "invalid resource set: \"%s\"" % (self.name, resource_set))

        # Attributes cannot have dashes so we convert to underscore
        user_attr =  attr.replace('_','-')
        required, default, heritable = template_settings[user_attr]

        if user_attr in self.settings:
            if self.settings[user_attr] is None:
                return default
            else:
                return self.settings[user_attr]

        parent = self._parent_template()
        if heritable and parent:
            return getattr(parent, attr)
        else:
            if required:
                raise InvalidConfigurationError(
                    "template \"%s\" has no "
                    "%s setting" % (self.name, user_attr))
            else:
                return default

    def display(self):
        if self.placeholder:
            raise InvalidConfigurationError('restricted template name')

        tbl = TextTable("%attribute %inherited %value")
        tbl.header_labels = {'attribute': 'attribute',
                             'inherited': 'inherited',
                             'value': 'value'}

        for setting in template_settings:
            _, default, _ = template_settings[setting]

            # Dont show settings with default value
            if not setting in self.settings and getattr(self, setting) == default:
                continue

            if setting in self.settings:
                inherited = 'No'
            else:
                inherited = 'Yes'

            value = str(getattr(self, setting))

            tbl.append({'attribute': setting,
                        'inherited': inherited,
                        'value': value})

        try:
            image_file, revision = self.resolve_image()
            tbl.append({'attribute': 'image-revision',
                        'inherited': 'No',
                        'value': '%d (%s)' % (revision,
                                              time.ctime(
                            os.path.getmtime(image_file)))})
        except:
            tbl.append({'attribute': 'image-revision',
                        'inherited': 'No',
                        'value': 'N/A'})

        print tbl

    def resolve_image(self, vm=None):
        rev_list = []

        if getattr(self, 'image') is None:
            return None, 0

        # This is the repository-based image resolution
        img_meta, img_path, rev = extract_repo_revision(getattr(self, 'image'))

        if img_path:
            #Flag as found in a repository
            self.settings['fromrepo'] = True
            self.settings['image_repo'] = img_meta['repo']
            self.settings['image_key'] = img_meta['key']
            return img_path, int(rev)

        # This is the backward compatible file-system definition
        # of the pcocc images
        image = Config().resolve_path(getattr(self, 'image'),
                                    vm)
        try:
            for f in os.listdir(image):
                match = re.match(r'image-rev(\d+)', f)
                if match:
                    rev_list.append(int(match.group(1)))
        except OSError as err:
            raise InvalidConfigurationError(
                "template \"%s\" image directory is "
                "invalid: %s " % (self.name, str(err)))

        if rev_list:
            top_rev = sorted(rev_list)[-1]
            revision = top_rev
            image_file = os.path.join(image,
                                           'image-rev%d' % (top_rev))
        else:
            revision = 0
            image_file = os.path.join(image,
                                      'image')
            if not os.path.isfile(image_file):
                raise InvalidConfigurationError(
                    "template \"{}\" image directory "
                    "has no image ".format(self.name))

        #Flag as not coming from a pcocc repository
        self.settings['fromrepo'] = False
        return image_file, revision


    def from_repo(self):
        self.resolve_image()
        if "fromrepo" in self.settings:
            return self.settings['fromrepo']
        else:
            return False

    def image_repo_infos(self):
        if self.from_repo():
            return self.settings['image_repo'], self.settings['image_key']
        else:
            return None, None


    #TODO validate all template settings
    def validate(self):
        """Recursive validation of a template and his parent

        Should be called once all templates have been loaded

        """
        if self.validated:
            return

        parent = self._parent_template()
        if parent:
            parent.validate()

        # Validate that the resource set is valid
        _ = self.rset

        if 'persistent-drives' in self.settings:
            self._convert_drives_to_dict()

        # Convert mount-point option from string to newer dict format
        for mount in self.mount_points:
            if not isinstance(self.mount_points[mount], dict):
                path = self.mount_points[mount]
                self.mount_points[mount] = {'path': path}


        # Value for absent image is None but accept YAML representations
        # of False as well
        if 'image' in self.settings and self.settings['image'] is False:
            self.settings['image'] = None

        self.validated = True

    def _convert_drives_to_dict(self):
        # Convert drives to ordered dict format
        # and set default values
        ordered_drives = OrderedDict()

        for drive in self.settings['persistent-drives']:
            # Dict syntax
            if isinstance(drive, dict):
                path = drive.keys()[0]
                opts = drive.values()[0]

                if not 'mmp' in opts:
                    opts['mmp'] = True

                if not 'cache' in opts:
                    opts['cache'] = 'writeback'

                ordered_drives[path] = opts
            # String syntax
            else:
                ordered_drives[drive] = {
                    'mmp': True,
                    'cache': 'writeback'
                }

        self.settings['persistent-drives'] = ordered_drives


    def _parent_template(self):
        if 'inherits' in self.settings:
            try:
                parent = Config().tpls[self.settings['inherits']]
                return parent
            except KeyError:
                raise InvalidConfigurationError(
                    "template \"%s\" inherits from "
                    "invalid template \"%s\"" %(
                        self.name,
                        self.settings['inherits']))
        else:
            return None
