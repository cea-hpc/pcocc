.. _9pmount:

|9pmount-tutorial_title|
========================

In this guide we detail how to mount host directories from VMs thank to 9p over virtio.

.. warning::
    CentOS and RHEL guests lack of built-in support for the 9p filesystem in the kernel. You'll have to compile the 9p modules from the kernel sources before being able to use this guide.

Defining host directories to export
***********************************

First, you have to define host directories to export as mount-points inside the VM template in :ref:`templates.yaml <templates.yaml>`.

A mount-point named *optmount* for :file:`/opt` can be defined as follows::

    mount-points:
        optmount:
            path: /opt/
            readonly: true

.. note::
    The **readonly** parameter defaults to *false* and therefore can be omitted for RW mounts

In this definition *optmount* is the tag of the 9p export which will be exposed to the VM. This tag has to be unique and will be referred to when mounting the export (see next section). */opt/* is the host path that is associated to this tag.

Mounting exports in the guest
*****************************

To mount a 9p export in the guest, you can use the following command::

    mount -t 9p -o trans=virtio [mount tag] [mount point] -oversion=9p2000.L,msize=262144

With the previous example this gives::

    mount -t 9p -o trans=virtio optmount /opt/ -oversion=9p2000.L,msize=262144

The :file:`/opt` directory from the host should now be mounted on :file:`/opt` inside the guest. Note that Qemu act as the 9p server and performs the actual I/O on the host filesystem with the permissions of the user launching the virtual cluster.

To mount the directory automatically at boot time you may put it in your fstab. This can be done with the following cloud-config snippet (see :ref:`pcocc-cloudconfig-tutorial(7)<configvm>`)::

   mounts:
     - [ optmount, /opt, 9p, 'trans=virtio,version=9p2000.L,msize=262144,nofail', '0', '0']

Mirroring UIDs
**************

Since I/O is performed with permissions of the user launching the virtual cluster, the best way to avoid permission issues is to access 9p mounts in your VM with a user having the same uid as your user on the host.

For example let's assume your user on the host is user1, you may retrieve it's numeric id with::

    id user1

Which would give, for example::

    uid=1023(user1) gid=1023(user1) groups=1023(user1)

Therefore, you would need to create a 'user1' in your VM with uid 1023. This may be done with the following cloud-config snippet (see :ref:`pcocc-cloudconfig-tutorial(7)<configvm>`)::

          users:
          - name : user1
            uid: 1023

If applicable, another solution is to configure your VMs to access the same directory sever as your hosts.


Mounting your home directory
****************************

Mounting one's own home directory is a common use-case for this feature. It makes it easy to share files and facilitates SSH key deployment. To export your home directory, set the following parameter in the VM template::

    mount-points:
        myhome:
            path: %{env:HOME}

Define the mount point in the VM fstab with a cloud-config file, for example::

   mounts:
     - [ myhome, /home/user1, 9p, 'trans=virtio,version=9p2000.L,msize=262144', '0', '0']


With a shared home directory, one can simply generate a private SSH key on the host and add the corresponding public key to the host's :file:`~/.ssh/authorized_keys` file to enable SSH connexion from host to VMs as well as between VMs.

