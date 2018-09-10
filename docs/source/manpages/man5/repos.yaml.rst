.. _repos.yaml:

|repos.yaml_title|
======================

Description
***********

:file:`/etc/pcocc/repos.yaml` is a YAML formatted file describing object repositories used to store VM images. This configuration can be read from several locations. System-wide definitions are read from :file:`/etc/pcocc/repos.yaml` while user-specific repositories are read from :file:`$HOME/.pcocc/repos.yaml`. A user has access to images located in both his personal repositories and in system-wide repositories.

.. note::
   The location of user configuration files, by default :file:`$HOME/.pcocc` can be changed to another directory by setting the **PCOCC_USER_CONF_DIR** environment variable.

To learn how to interact with image repositories, please refer to the :ref:`pcocc-image(1)<image>` documentation.


Syntax
******

:file:`/etc/pcocc/repos.yaml` contains a key/value mapping. At the top-level a key named *repos* is defined. The associated value is a list of repositories. Each repository is defined by a key/value mapping containing two keys: *path* the path to a directory holding the repository and *name* the name associated with the repository. The *path* must point to either an initialized repository or to a non-existing directory which will be automatically created and initialized to an empty repository on first use.
The repositories must appear in the list by order of priority: the first repository in the list is the first considered when looking up an image. Repositories defined in the user configuration file are considered before those defined in the system configuration file.

A second *optionnal* key *cache* can be used to specify where pcocc should store its temporary artifacts related to containers. This entry is a key/value mapping defining a path where the cache should be located. If the target directory does not exist it is created. This directory *should* be writable for the end-user.

Sample configuration file
*************************

This is the default configuration file for reference. Please note that indentation is significant in YAML::

 # This file defines a list of pcocc image repositories sorted by
 # priority (highest priority first). To define a new repository, add a
 # path to an non-existing directory

 repos:
   - name: user
     path: "%{env:HOME}/.pcocc/repo"
 # - name: global
 #   path: "/var/lib/pcocc/images"

 # This defines a cache directory in each user's home
 cache:
   path: "%{homedir}/.pcocc/cache"

See also
********

:ref:`pcocc-image(1)<image>`, :ref:`pcocc-template(1)<template>`, :ref:`pcocc-templates.yaml(5)<templates.yaml>`,  :ref:`pcocc-newvm-tutorial(7)<newvm>`
