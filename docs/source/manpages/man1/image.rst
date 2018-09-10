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
                List image in repositories. The result can be filtered by repository and/or by image name with a regular expression.

   show [IMAGE]
                Show a detailed description of the specified image

Import and Export
.................

   import [-t fmt] ([FORMAT]:)[SOURCE] [DEST]
                Import the source image file to an image in the destination repository. The destination image name must not already be used in the destination repository and the revision is ignored since the import operation creates the first revision of a new image. See below for supported image kinds and file formats.

   export [-t fmt] [SOURCE]  ([FORMAT]:)[DEST]
                Export the source image file from a repository to the destination file.

Image Management
................

   copy [SOURCE] [DEST]
                Copy an image from a repository to another image in a repository. The destination image name must not already be used in the destination repository and the destination revision is ignored since a copy operation creates the first revision of a new image.

   delete [IMAGE]
                Delete an image from a repository. If a revision is specified, only the specified revision is deleted, otherwise all revisions of the image are deleted.

   resize [IMAGE] [NEW_SZ]
                A new image revision is created with the new image size.
                
                .. warning::
                    This command is only available for VM images.

Repository Management
.....................

   repo list
                List configured repositories

   repo gc [REPO]
                Cleanup unnecessary data from a repository. This command should be run to free space used by data no longer used by any image.


Cache Management
................

When running containers with pcocc a cache is used to speedup container launch either extracting rootfs or squashfs image (depending on pcocc configuration). The following commands can be used to manipulate and query this cache.

.. warning::
    As running container may depend on this cache it should *never* be modified when a container is running. And it is user's responsibility to ensure that no containers are currently depending on the cache.
..

   image cache list
                List images in repositories in increasing order of last use

   image cache delete [IMAGE NAME]
                Delete all cached items for a given image

   image cache gc 
                Clean the cache by removing dangling object

Import and export file formats
******************************
pcocc handle both container images and virtual machine images in the same repos. When listing images their type is indicated as either ``cont`` for container and ``vm`` for virtual machines, for example below is an output excerpt of ``pcocc image list``::

    NAME              TYPE    REVISION    REPO    OWNER      DATE
    ----              ----    --------    ----    -----      ----
    centos            cont    0           user    johndoe    2019-07-15 11:16:57
    cloud-centos      vm      0           global  tomsmith   2018-09-04 10:13:14

.. note::
    The user is responsible for distinguising **by name** between various container and VM images as it is not possible to specify the "kind" of an image in the various commands.

By default, pcocc will try to guess the file format from the image file itself or from its extension. The file format of the imported / exported file can be forced either with the ``-t`` option or by specifying a format prefix (see example below).

Container Image formats
.......................

The following container image formats are supported by pcocc:

===================  ===========   ================================  
Name                 Extension     Description                     
===================  ===========   ================================ 
docker               NA            Interact with docker-hub
docker-archive       NA            Docker archive (docker save 
                                   https://docs.docker.com/engine/reference/commandline/save/)
docker-daemon        NA            Running docker daemon
oci                  NA            Open-Container Initiative (OCI)
ostree               NA            OSTree repository 
                                   https://ostree.readthedocs.io/en/latest/
simg                 .simg         Singularity image (export not supported) 
===================  ===========   ================================

.. note::
    The internal image storage for pcocc relies on the oci image format. therefore
    all images when imported are first converted to OCI. 

As most container image formats are not based on extensions (unlinke VM images) it is recommended ro rely on inline format specifiers. For example one can import a docker archive (as generated by ``docker save``) using the following command::

    # Will import the ubuntu.tar.gz as an image named ubuntu-cont
    pcocc image import docker-archive:ubuntu.tar.gz ubuntu-cont

In order to rely on the docker-hub, we also use an inline ``docker`` format::

    # Import busybox:latest from docer-hub and save it as busysbox
    pcocc image import docker://busybox:latest busybox

One can export an image to a docker archive as follows::

    # Export the container named mycont to the mycont.tar.gz docker archive
    pcocc image export mycont docker-archive:mycont.tar.gz

And as a last example the only container format which can be identified by extension, singularity::

    # Import singularity image lolcow.simg as lolcow
    pccoc image import lolcow.simg lolcow


Virtual Machine Image formats
.............................

The following VM image formats are supported by pcocc:

===================  ===========   ================================  
Name                 Extension     Description                     
===================  ===========   ================================ 
raw                  .raw          Raw disk image
qcow2                .qcow2        Qcow2 image format
qed                  .qed          QED image format 
vdi                  .vdi          VirtualBox disk images
vmdk                 .vmdk         VMWare images         
===================  ===========   ================================

.. note::
    The prefered image format for pcocc is .qcow2 as it can be layered. All imported
    images are therefore converted to .qcow2. It is therefore recommended to use this 
    format for exchange.


All images imported with this type will be considered unambiguously as VM images.

It is then possible to import VM images using following syntaxes::

    # Import vmimage in RAW format as myvm
    pcocc image import -t raw ./vmimage myvm
    # Equivalent to previous command
    pcocc image import raw:./vmimage myvm
    # And to illustrate extension resolution
    # format specifier would not be needed
    # with the right extension
    pcocc image import ./vmimage.raw myvm

.. warning::
    Pcocc tries to check the parameters which are passed relative to VM image
    formats. However, in some cases it is not possible to fully ensure the actual
    image format matches parameters. Users should be careful to use the correct
    format specifier to unambiguously specify formats.

Examples
********

To list available images::

    pcocc image list

To import an image into a repository named *global*::

   pcocc image import vm $HOME/CentOS-7-x86_64-GenericCloud.qcow2 global:centos7-cloud

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
