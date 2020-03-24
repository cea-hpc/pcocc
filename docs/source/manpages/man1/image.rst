.. _image:

|image_title|
================

Synopsis
********

pcocc image [COMMAND] [ARG]

Description
***********

List and manage virtual machine and container images.

All the subcommands of *pcocc image* operate on images stored in pcocc repositories. The list of pcocc repositories is defined in *repos.yaml* (see :ref:`pcocc-repos.yaml(5)<repos.yaml>`).

Images in repositories are uniquely identified by a name and revision number. In all pcocc commands and configuration files, images in repositories are specified with the following URI syntax: [REPO:]IMAGE[@REVISION]. If REPO is omitted the command will look in all defined repositories by order of priority until it finds a matching image. If REVISION is omitted, the highest revision of the image is selected.

Images are made of a stack of layers with each layer containing the differences from the previous layers. Layers can be shared between images in a repository which allows to reduce the storage footprint and speeds up operations by avoiding unnecessary data movement.

Sub-Commands
************

Query Images
............

   list [-R repo] [REGEX]
                List images in repositories. The result can be filtered by repository and/or by image name with a regular expression.

   show [IMAGE]
                Show a detailed description of the specified image

Import and Export
.................

   import [-t fmt] [SOURCE] [DEST]
                Import the source image file to an image in the destination repository. The destination image name must not already be used in the destination repository and the revision is ignored since the import operation creates the first revision of a new image. See below for supported file formats.

   export [-t fmt] [SOURCE] [DEST]
                Export the source image file from a repository to the destination file.

Supported file formats
......................

The following VM image file formats can be imported or exported: *raw*, *qcow2*, *qed*, *vdi*, *vpc*, *vmdk*. By default, pcocc will try to guess the image format from its filename extension, or from the image content if possible. It can be specified with the -t option if needed.

Container images can be imported / exported from remote Docker registries or local files by specifying them as follows:
  * **docker:**//docker-reference : an image in a Docker registry.
  * **docker-archive**:path : an image stored in a file saved with docker save formatted file.
  * **oci**:path[:tag] an image *tag* in the *path* directory compliant with OCI Layout Specification.


Image Management
................

   copy [SOURCE] [DEST]
                Copy an image from a repository to another image in a repository. The destination image name must not already be used in the destination repository and the destination revision is ignored since a copy operation creates the first revision of a new image.

   delete [IMAGE]
                Delete an image from a repository. If a revision is specified, only the specified revision is deleted, otherwise all revisions of the image are deleted.

   resize [IMAGE] [NEW_SZ]
                Create a new image revision with the specified image size.

		.. warning::
                    This command is only available for VM images.

Repository Management
.....................

   repo list
                List configured repositories

   repo gc [REPO]
                Cleanup unnecessary data from a repository. This command should be run to free space used by data no longer referenced by any image.


Cache Management
................

Pcocc uses a cache to speedup container launch. The following commands can be used to manipulate and query this cache.

.. warning::
    Deleting an entry from the cache may yield unspecified behaviour if it is in use by a container instance.

   image cache list
                List cached items starting from the least recently used

   image cache delete [OBJECT NAME]
                Delete an item from the cache

   image cache gc
                Shrink the cache by removing data no longer referenced by any image

Examples
********

To list available images::

    pcocc image list

To import a VM image into a repository named *global*::

   pcocc image import $HOME/CentOS-7-x86_64-GenericCloud.qcow2 global:centos7-cloud

To import a container image into a repository named *user*::

   pcocc image import docker://centos user:centos

To copy an image between repositories::

   pcocc image copy global:centos7-cloud user:mycentos7

To get detailed information relative to an image::

    pcocc image show user:mycentos7

To delete a specific revision of an image::

    pcocc image delete user:mycentos7@5

To completely delete all revisions of an image::

    pcocc image delete myrepo:centos7-cloud


See also
********

:ref:`pcocc-save(1)<save>`, :ref:`pcocc-repos.yaml(5)<repos.yaml>`, :ref:`pcocc-templates.yaml(5)<templates.yaml>`
