|save_title|
============
.. _save:

Synopsis
********

pcocc save [OPTIONS] [VM]

Description
***********

Save the disk of a VM to a new disk image.

By default, only the differences between the current state of the VM disk and the image from which it was instantiated are saved in an incremental file to form a new revision of the image. When a VM is instantiated it uses the latest revision of the image defined in its template. Incremental save files are stored in the image directory and all incremental saves leading to the latest revision have to be kept. A user needs to have write permissions on the image directory to be able to create new revisions. New full and independant images can be saved using the **-d** flag which creates a new image directory with the initial revision of the newly created image.

.. warning::
    It is recommended to have the *qemu-guest-agent* package installed in the guest (see next section).


Recommendations
***************

Saving a running VM may lead to corruption if the filesystem is being accessed. To ensure a consistent filesystem image, pcocc tries to contact the Qemu guest agent in the VM to freeze the filesystems before creating a new image from this disk. Therefore, it is recommended to make sure that the qemu guest agent is running in the guest (see : :ref:`pcocc-newvm-tutorial(7)<newvm>`).

If pcocc cannot contact the agent, it will emit a warning message but it will try to save the VM anyway. If installing the agent is not possible, you should freeze the filesystems by hand or simply shutdown your VM before calling pcocc save. In a Linux guest, you can use, as root *shutdown -H now* to shutdown a VM without powering it off (as you want to keep your resource allocation).


Options
*******

  -j, \-\-jobid INTEGER
            Jobid of the selected cluster

  -J, \-\-jobname TEXT
            Job name of the selected cluster

  -d, \-\-dest DIR
            Make a full copy in a new directory

  -s, \-\-safe
            Wait indefinitely for the Qemu agent to freeze filesystems

  -h, \-\-help
            Show this message and exit.

Examples
********

In these examples, we consider that the *qemu-guest-agent* is installed.

Create a new image revision
...........................

If you have write permissions on the image directory used by your VMs, you can create new image revisions. For example to create a new revision of the image used by first VM of your virtual cluster use::

    $ pcocc save vm0
    Saving image...
    vm0 frozen
    vm0 thawed
    vm0 disk successfully saved to ./.pcocc/images/centos7-cloud/image-rev1

A new file is created in the image directory ::

    $ ls ./.pcocc/images/centos7-cloud/image-rev1
    image  image-rev1

The next VM instantiated with this image will use the new revision. You can undo saves by removing the latest revisions. However removing an intermediate revision will corrupt all subsequent revisions.

Create a new independent images
...............................

If you want to create a new full image or do not have write permissions on the image directory use by your VM you can to use the "-d" flag to save to an VM image in a new directory::

    $ pcocc save vm0 -d $HOME/my-centos7
    Saving image...
    vm0 frozen
    vm0 thawed
    Merging snapshot with backing file to make it standalone...
    vm0 disk successfully saved to /home/user/my-centos7/image

You can now create a template inheriting from the original one, but using the new image image, by editing your :file:`templates.yaml` file::

    mycentos:
        inherits: centos7-cloud
        image: ~/my-centos7/

See also
********

:ref:`pcocc-templates.yaml(5)<templates.yaml>`, :ref:`pcocc-newvm-tutorial(7)<newvm>`, :ref:`pcocc-ckpt(1)<ckpt>`, :ref:`pcocc-dump(1)<dump>`


