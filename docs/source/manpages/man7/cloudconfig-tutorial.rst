|cloudconfig-tutorial_title|
============================
.. _configvm:

This tutorial shows how to configure a cloud-init enabled VM image, that is, a VM image where the cloud-init service has been enabled to run a boot time. Cloud-init is a multi-distribution package that handles early initialization of a VM instance. It can perform various tasks such as configuring users and access credentials, installing packages or setting up mount points. These tasks are defined in a cloud-config file that can be passed to a pcocc VM using the **user-data** template parameter.

Many distributions provide cloud-init enabled VM images that you can easily import as pcocc templates. More information about downloading and importing these images can be found in :ref:`pcocc-newvm-tutorial(7)<newvm>`.

.. note::
    By default it is not possible to login to cloud-enabled VMs, you must first specify a cloud-config file to setup a SSH key or other authentication mechanism.

This tutorial provides a quick overview of some cloud-config directives which can be used to configure pcocc VMs. The complete documentation of cloud-init capabilities can be found at https://cloudinit.readthedocs.io/en/latest/.


Using cloud-config files with pcocc
***********************************

A cloud-config file is a YAML formatted file beginning with the *#cloud-config* pragma and followed by various configuration directives, some of which we will cover in the next sections. It can be passed to pcocc VMs by adding the **user-data** template parameter, for example::

    mycentos:
        inherits: centos7-ci
        user-data: ~/conf

Where :file:`~/conf` is the cloud-config file which will be passed to cloud-init at VM boot.

Most cloud-config directives are *per-instance*, which means they are applied once per instanciated VM, when it first boots. This mechanism relies on the value of **instance-id** which defaults to a random uuid generated for each instanciated pcocc VM. Alternatively, the **instance-id** can be set to a fixed value in the VM template definition (see :ref:`pcocc-templates.yaml(5)<templates.yaml>`). Each time cloud-init runs, it records the current **instance-id**  in the VM filesysterm and only applies *per-instance* directives if it differs from what was previously recorded.

Setting up user credentials
***************************

With cloud-init enabled VMs the first configuration task is often to define user credentials to login to the VM. This can be done with the following syntax::

    users:
      - name : demo1
        ssh-authorized-keys:
          - <ssh pub key 1>
          - <ssh pub key 2>
      - name : demo2
        ssh-authorized-keys:
          - <ssh pub key 3>

This defines two demo users, with their respective public SSH keys which have to be copy/pasted in the appropriate fields. You can also provide sudo privileges to a user with the **sudo** parameter or define its numerical id with the **uid** parameter::

    users:
        - name: demo1
          sudo: ['ALL=(ALL) NOPASSWD:ALL']
          uid: 1247
          ssh-authorized-keys:
            - <ssh pub key 1>

Hostname considerations
***********************

By default, cloud-init stores the VM hostname in /etc/hostname which makes it persistent across reboots. This may not be what you want if you plan to instantiate many VMs from the same disk image and need them to find out their hostname dynamically from DHCP. You can inhibit this behaviour with the preserve hostname option::

   preserve_hostname: true

This option must also be set in the cloud-init configuration file in the VM to be persistent (see :ref:`writing_files_label`)::

  write_files:
    - path: /etc/cloud/cloud.cfg.d/99_hostname.cfg
      permissions: '0644'
      content: |
        preserve_hostname: true


Running early boot commands
***************************

Boot commands are executed first in the configuration process. They are run as root. In contrast to other directives, they are run on each boot instead of only once. The *cloud-init-per* wrapper command can be used to run these boot commands only once. For example, if you are relying on local mirrors of package repositories you may want to disable those configured by default in the cloud-init image. For a CentOS guest you may add::

  bootcmd:
   - [ cloud-init-per, instance, yumcleanbase, yum-config-manager, --disable, base]
   - [ cloud-init-per, instance, yumcleanupdates, yum-config-manager, --disable, updates]
   - [ cloud-init-per, instance, yumcleanextras, yum-config-manager, --disable, extras]



Installing packages
*******************

You can provide a list of packages to install, for example::

    packages:
        - qemu-guest-agent
        - vim
        - gcc
        - gdb

You can also setup additional package repositories for yum::

    yum_repos:
       epel_mirror:
        baseurl: http://local-mirror.mydomain/pub/epel/testing/7/$basearch
        enabled: true

Or for apt::

   apt:
      primary:
        - arches: [default]
          search:
            - http://local-mirror.mydomain/pub/debian/

You can also ask for packages to be upgraded first::

  package_update: false

.. _writing_files_label:

Writing files
*************

You can write arbitrary files in the VM filesystem. Files are written after packages have been installed which allows for customizing configuration files. For example to write a simple :file:`/etc/hosts` file for VMs on a private network::

  write_files:
    - path: /etc/hosts
      permissions: '0644'
      content: |
        #Host file
        127.0.0.1   localhost localhost.localdomain

        10.252.0.1 vm0-ib0
        10.252.0.2 vm1-ib0
        10.252.0.3 vm2-ib1

Mounting filesystems
*********************

You can add entries to the VM fstab to mount filesystems. For example, to mount a 9p filesystem::

    mounts:
     - [ optmount, /opt, 9p, 'trans=virtio,version=9p2000.L,msize=262144,nofail', '0', '0']

Running commands
****************

You can run arbitrary commands as root once at the end of the configuration process. Commands will run once all packages have been installed and files written. It can be used to reload a service that you just reconfigured or amend a configuration file::

    runcmd:
        - sed -i 's/a/b' /etc/config-file
        - sytemctl restart service


To go further
*************

We only briefly covered part of the capabilities of cloud-init. Please refer to https://cloudinit.readthedocs.io/en/latest/index.html for an exhaustive documentation.
