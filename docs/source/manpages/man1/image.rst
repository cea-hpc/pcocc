.. _image:

|image_title|
================

Synopsis
********

pcocc image [COMMAND] [ARG]

Description
***********

List and manage virtual machine images.

All the subcommands of *pcocc image* operate on images stored in pcocc repositories. The list of pcocc repositories is defined in *repos.yaml* (see :ref:`pcocc-repos.yaml(5)<repos.yaml>`).

Images in repositories are uniquely identified by a name and revision number. In all pcocc commands and configuration files, images in repositories are specified with the following URI syntax: [REPO:]IMAGE[@REVISION]. If REPO is omitted the command will look in all defined repositories by order of priority until it finds a matching image. If REVISION is omitted, the highest revision of the image is selected.


Sub-Commands
************

   list [-R repo] [REGEX]
                List image in repositories. The result can be filtered by repository and/or by image name with a regular expression.

   show [IMAGE]
                Show a detailed description of the specified imagge

   import [-t fmt] [KIND] [SOURCE] [DEST]
                Import the source image file to an image in the destination repository. The destination image name must not already be used in the destination repository and the revision is ignored since the import operation creates the first revision of a new image. See below for supported image kinds and file formats.

   export [-t fmt] [KIND] [SOURCE] [DEST]
                Export the source image file from a repository to the destination file. See below for supported image kinds and file formats.

   copy [SOURCE] [DEST]
                Copy an image from a repository to another image in a repository. The destination image name must not already be used in the destination repository and the destination revision is ignored since a copy operation creates the first revision of a new image.

   delete [IMAGE]
                Delete an image from a repository. If a revision is specified, only the specified revision is deleted, otherwise all revisions of the image are deleted.

   repo list
                List configured repositories

Import and export file formats
******************************
pcocc repositories currently only manage VM images so the only valid value for KIND is *vm*. The following VM image file formats are supported: *raw*, *qcow2*, *qed*, *vdi*, *vpc*, *vmdk*. By default, pcocc will try to guess the file format from the image file itself or from its extension. The file format of the imported / exported file can be forced with the -t option.

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
