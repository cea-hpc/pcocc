|save_title|
============
.. _save:

Synopsis
********

pcocc save [OPTIONS] [VM]

Description
***********

Save the disk of a VM to a new disk image.

By default, only the differences between the current state of the VM disk and the image from which it was instantiated are saved in an incremental file to form a new revision of the image. When a VM is instantiated it uses the latest revision of the image defined in its template. The *-d* option allows to create a new image instead of a new revision of the current image. If the destination is in another repository, a full image is created instead of an incremental image. The *--full* flag allows to force this behaviour in other cases.

.. warning::
    It is recommended to have the *qemu-guest-agent* package installed in the guest (see next section).

.. note::
   In previous releases, pcocc images were saved in standalone directories. While this style of images is still properly handled by pcocc save, it is now considered deprecated and support will be removed in a future version.

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

  -d, \-\-dest URI
            Make a full copy in a new directory

  -s, \-\-safe
            Wait indefinitely for the Qemu agent to freeze filesystems

  \-\-full
            Save a full image even if not necessary

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
    vm0 disk successfully saved to centos7-cloud revision 1

A new image revision is created ::

   $ pcocc image show centos7-cloud
   [..]

   REVISION    SIZE       CREATION DATE
   --------    ----       -------- ----
   0           958  MB    2018-08-03 16:04:12
   1           44.0 MB    2018-08-03 16:09:54

The next VM instantiated with this image will use the new revision. You can undo saves by removing the latest revisions (see :ref:`pcocc-image(1)<image>`) or specify a specific revision in your template image URI.

Create a new independent images
...............................

If you want to create a new image or do not have write permissions on the image repository used by your VM you can use the *-d* flag to save to a new VM image::

    $ pcocc save vm0 -d user:mycentos7
    Saving image...
    vm0 frozen
    vm0 thawed
    Merging snapshot with backing file to make it standalone...
    vm0 disk successfully saved to user:mycentos revision 1

You can now create a template inheriting from the original one, but using the new image, by editing your :file:`templates.yaml` file::

    mycentos:
        inherits: centos7
        image: user:mycentos

See also
********

o:ref:`pcocc-image(1)<image>`, :ref:`pcocc-templates.yaml(5)<templates.yaml>`, :ref:`pcocc-newvm-tutorial(7)<newvm>`, :ref:`pcocc-ckpt(1)<ckpt>`, :ref:`pcocc-dump(1)<dump>`


