.. _newvm:

|newvm-tutorial_title|
======================


This tutorial details how VM templates can be added to pcocc. It shows how to import cloud VM images provided by various Linux distributions which can be customized using cloud-init. More detailed information on how to configure such images is provided in the tutorial dealing with the :ref:`configuration of VMs with cloud-init<configvm>`.

VM templates
************

pcocc is built around the notion of templates which define the main attributes of the VMs that can be instantiated. In a :ref:`template<templates.yaml>`, you can define, among other things:

* The reference image for the VM boot disk
* The network resources provided to the VM
* A cloud-config file to configure a cloud image (see :ref:`pcocc-cloudconfig-tutorial(7)<configvm>`)
* Host directories to expose in the VM

Two types of templates can be configured:

* System-wide templates in :file:`/etc/pcocc/templates.yaml`
* Per-user templates in :file:`~/.pcocc/templates.yaml` (by default)

A user has access to both his personal templates and the system-wide templates. Note that a per-user template can inherit from a system-wide template.

.. _getimgs:

Importing VM images
*******************

pcocc runs standard VM images in the Qemu qcow2 format. Many Linux distributions provide handy cloud images in this format which can be configured at instantiation time thanks to cloud-init.

* For Ubuntu you may get images from `https://cloud-images.ubuntu.com/ <https://cloud-images.ubuntu.com/>`_
* For Debian from `https://cdimage.debian.org/cdimage/openstack/ <https://cdimage.debian.org/cdimage/openstack/>`_
* For CentOS from `https://cloud.centos.org/centos/ <https://cloud.centos.org/centos/>`_
* For Fedora from `https://alt.fedoraproject.org/cloud/ <https://alt.fedoraproject.org/cloud/>`_

In this guide, we use the following images (x86_64):

* Ubuntu Server (Artful): `https://cloud-images.ubuntu.com/artful/current/artful-server-cloudimg-amd64.img <https://cloud-images.ubuntu.com/artful/current/artful-server-cloudimg-amd64.img>`_
* CentOS 7: `https://cloud.centos.org/centos/7/images/CentOS-7-x86_64-GenericCloud.qcow2 <https://cloud.centos.org/centos/7/images/CentOS-7-x86_64-GenericCloud.qcow2>`_

You may now download these images or those that you want to install. Note that the import process below is the same whether you use cloud-init enabled VMs or regular qcow2 images that you have already configured.

In this guide, we use :file:`$VMDIR` as the base directory holding our VM images. It should be on a shared filesystem accessible from all front-end and compute nodes and ideally on a fast parallel filesystem for best scalability. If you are the system administrator, you may want to provide these base distribution images to all your users by creating system-wide templates. In that case :file:`$VMDIR` (and its content) should be readable by all pcocc end-users but write protected.

We will now create directories in :file:`$VMDIR`, one for each image::

    mkdir $VMDIR/ubuntu-server-artful-cloud
    mkdir $VMDIR/centos7-cloud

.. note::
    We used the "-cloud" suffix as a convention to identify cloud-init enabled images.

Now simply move the images to their respective directories, naming them :file:`image`::

    mv artful-server-cloudimg-amd64.img $VMDIR/ubuntu-artful-cloud/image
    mv CentOS-7-x86_64-GenericCloud.qcow2 $VMDIR/centos7-cloud/image

At this point you should have the following file hierarchy::

    $VMDIR/centos7-cloud:
        image

    $VMDIR/ubuntu-artful-cloud:
        image

Defining VM templates
*********************

Now that we have copied the images to our shared filesystem, we can define templates for them within the pcocc :ref:`templates.yaml <templates.yaml>` configuration file. A system administrator can define them as system-wide templates in :file:`/etc/pcocc/templates.yaml` to make them avaialable to all users. Otherwise, define them in :file:`~/.pcocc/templates.yaml`. We first define basic templates which only make the image available. We can then inherit from them to create custom VMs.

Here is the content of :file:`templates.yaml` for these three VMs (don't forget to replace :file:`$VMDIR` with the actual PATH)::

    centos7-cloud:
        image: "$VMDIR/centos7-cloud"
        resource-set: "cluster"
        description: "Cloud enabled CentOS 7"

    ubuntu-artful-cloud:
        image: "$VMDIR/ubuntu-artful-cloud"
        resource-set: "cluster"
        description: "Cloud enabled Ubuntu 17.10"

We selected the *cluster* configuration as a **resource-set** for these VMs. It should reference one of the resource sets defined in the :file:`/etc/resources.yaml` file. Please refer to the :ref:`resources.yaml <resources.yaml>` and :ref:`networks.yaml <networks.yaml>` configuration files for more informations on this option.

Following this step, you should be able to list your new virtual machines::

    $ pcocc template list
    NAME                 DESCRIPTION                 RESOURCES    IMAGE
    ----                 -----------                 ---------    -----
    ubuntu-artful-cloud  Cloud enabled Ubuntu 17.10  cluster      /shared/vms/ubuntu-artful-cloud
    centos7-cloud        Cloud enabled CentOS 7      cluster      /shared/vms/centos7-cloud

Basic VM configuration
**********************

Cloud-init enabled VMs such as the ones we installed in the previous section must be configured with a cloud-config file. If you imported a regular image which was already configured to be accessible by SSH you can skip this step.

.. note::
    The cloud-init enabled images used in this guide don't have default login credentials. This is by design to prevent anyone from accessing the VM before you would be able to change the password. The cloud-config file will allow creating a user with proper authentication credentials such as a SSH public key.

The most basic cloud-config file which you can use is as follows::

        #cloud-config
        users:
           - name: demo
	     sudo: ['ALL=(ALL) NOPASSWD:ALL']
             ssh-authorized-keys:
              - <your ssh public key>

It creates a user named *demo* able to use sudo without password and which can login via SSH with the specified key.

.. warning::
    Please note that indentation levels are significant in YAML and that tabs are not allowed. If you run into trouble you can use a validator at https://coreos.com/validate/.

For a simple cluster, we don't want to deploy a DHCP or DNS server to manage addresses on the private network. Instead, we define an :file:`/etc/hosts` file and use a simple script which configures the Ethernet interface on the private Ethernet network with an IP derived on from the interface's MAC address. Append the following to your cloud-config file::

    write_files:
      - path: /sbin/ifup-local
        permissions: '0755'
        content: |
          #!/bin/bash
          VM_ID0=$(printf "%d\n" 0x$(cat /sys/class/net/eth1/address | cut -d : -f 6))
          VM_ID1=$(printf "%d\n" 0x$(cat /sys/class/net/eth1/address | cut -d : -f 5))
          VM_ID=$(( 256 * $VM_ID1 + $VM_ID0 ))
          BYTE0=$((  $VM_ID / 255 ))
          BYTE1=$(( ( $VM_ID % 255 ) + 1 ))

          ifconfig eth1 "10.252.${BYTE0}.${BYTE1}/16" mtu 1450
          hostname vm"${VM_ID}"

       - path: /etc/hosts
         permissions: '0644'
         content: |
           #Host file
           127.0.0.1   localhost localhost.localdomain

           10.252.0.1 vm0
           10.252.0.2 vm1
           10.252.0.3 vm2
           10.252.0.4 vm3
           10.252.0.5 vm4
           10.252.0.6 vm5
           10.252.0.7 vm6
           10.252.0.8 vm7
           10.252.0.9 vm8

.. note::
    The MTU is set to 1450 compared to 1500 on the host network to account for encapsulation headers. More entries in /etc/hosts could be defined to account for more VMs.

Moreover, we will also install the Qemu guest agent in our VMs. The Qemu guest agent is a daemon running in VMs allowing to interact with the guest in a network indepenant and OS agnostic fashion. pcocc makes use of this agent when it is available, most notably to freeze guest filesystems and obtain consistent snapshots when using the ref:`pcocc-save(1)<save>` command. We also make sure that the eth1 interface (corresponding to the private network) is up. Append the following content to your cloud-config file::

    packages:
        - qemu-guest-agent

    runcmd:
        # Make sure that the service is up on all distros
        - systemctl start qemu-guest-agent
        - ifup eth1

To pass this cloud-config file to our VMs, we can specialize the generic templates. As a regular user you can then add the fllowing content to the :file:`~/.pcocc/templates.yaml` configuration file::

    mycentos:
        inherits: centos7-cloud
        user-data: ~/my-cloud-config
        description: "Custom CentOS 7"

    myubuntu:
        inherits: ubuntu-artful-cloud
        user-data: ~/my-cloud-config
        description: "Custom Ubuntu"

.. note::
    This configuration file assumes that you saved the previous cloud-config file as :file:`~/my-cloud-config` in your home directory. Please adapt the path to what you have used.


Launching a virtual cluster
***************************
We can now instantiate VMs::

    pcocc alloc -c2 mycentos:3,myubuntu:1

Using this command, you will launch four VMs with two cores each:

* three *mycentos*
* one *myubuntu*

VMs are numbered in order so they will be as as follows:

==== ===========
ID   Type
==== ===========
vm0  CentOS (1)
vm1  CentOS (2)
vm2  CentOS (3)
vm3  Ubuntu (1)
==== ===========

The pcocc alloc command puts you in a subshell which controls your allocation. If you exit this shell, your virtual cluster will be terminated and the temporary disks of the VMs will be destroyed.

If you used the cloud-config file described in the previous steps, you now should be able to login as the demo user (this assumes your default SSH private key matches the public key you specified in the cloud-config file, otherwise, specify the correct private key with the *-i* option) ::

    pcocc ssh vm0 -l demo

You should be logged into one of the CentOS VM::

    [demo@vm0 ~]$ cat /etc/redhat-release
    CentOS Linux release 7.3.1611 (Core)

Note that, since you are in the aforementioned subshell, pcocc commands such as *pcocc ssh* automatically target the current virtual cluster, but you can  target a specific cluster by jobid/jobname from any shell using the -j/-J pcocc options.

To reach the Ubuntu VM::

    pcocc ssh vm3 -l demo

    $ cat /etc/lsb-release
    DISTRIB_ID=Ubuntu
    DISTRIB_RELEASE=17.10
    DISTRIB_CODENAME=artful
    DISTRIB_DESCRIPTION="Ubuntu Artful Aardvark (development branch)"

You can connect to the serial consoles using the following command::

    pcocc console vm1

.. note::
    Hit CTRL+C three times to leave the serial console.

You can also look back at the serial console log with::

    pcocc console -l

.. note::
    The console is very helpful to follow the VM boot and cloud-init progress. Installing packages can take some time, and in this example, the Qemu guest agent will only be available once the configuration process is complete. If you run into any issue, check the serial console log for error messages and make sure your YAML syntax is correct.

Saving VM images
****************

Instead of configuring your VMs with cloud-init each time you instantiate them, you may want to create templates from pre-configured images which already contain the necessary packages, configuration files, user defintions etc. pcocc allows you to create new images from a running VM with the ref:`pcocc-save(1)<save>` command.
