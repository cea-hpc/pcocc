Getting Started
===============

This tutorial explains how to deploy pcocc and configure basic features, define VM templates, and start a virtual cluster.


Installation
____________


Deployment
""""""""""

* Pcocc has to be deployed on all compute and submit nodes. The easiest way to achieve this is to build a package for your Linux distribution, which can be done on RHEL7 based distributions using::

   $ python setup.py bdist_rpm

In addition to the pcocc python package, the generated RPM installs pcocc configuration files in ``/etc/pcocc``, a SLURM lua plugin in ``/etc/slurm/lua.d/``, and systemd init scripts. For virtual Infiniband support, this package also needs to be deployed on the nodes running the OpenSM daemon. It has a few dependencies on packages outside of the standard repositories, most of which can be satisfied from EPEL. Notable exceptions are, as of this writing, the `slurm-spank-plugins <https://code.google.com/archive/p/slurm-spank-plugins/>`_ package from LLNL for the lua SLURM plugin and `python-etcd <https://github.com/jplana/python-etcd>`_.

* The kvm module must be loaded on all compute nodes and accessible (rw permissions) by all users of pcocc. You can use a udev rule such as:

.. code-block:: text
   :caption: /etc/udev/rules.d/80-kvm.rules

   KERNEL=="kvm", GROUP=="xxx", MODE="xxx"


* For best results, you should configure SLURM to manage memory and cpu affinity. You can use the following settings in your SLURM configuration:

.. code-block:: text

  SelectTypeParameters=CR_Core_Memory
  TaskPlugin=task/cgroup
  ConstrainCores=yes
  TaskAffinity=yes

* The lua SPANK plugin must be enabled in the SLURM configuration on all submit and compute nodes. This the case with the default configuration:

.. code-block:: text
  :caption: /etc/slurm/plugstack.conf

  include /etc/slurm/plugstack.conf.d/*.conf

* Make sure that the openvswitch service is running on all compute nodes.

* Pcocc requires access to a working etcd cluster with authentication enabled. Since pcocc will dynamically create users and permissions, you may want to deploy a dedicated instance. Etcd is very simple to deploy, in its most basic form you just need to start the daemon on a server without any specific configuration. For more robust deployments, you should deploy multiple servers and add TLS encryption as described in the etcd `documentation <https://coreos.com/etcd/docs/latest/>`_. Authentication can be enabled with the following commands (you'll have to define a root password)::

  $ etcdctl user add root
  $ etcdctl auth enable
  $ etcdctl -u root:<password> role revoke guest -path '*' -write
  $ etcdctl -u root:<password> role revoke guest -path '*' -read

Basic configuration
"""""""""""""""""""

The sample network configuration in ``/etc/pcocc/networks.yaml`` defines two networks, a NAT Ehernet network which connects each VM to the host network via NAT routing, and allows to SSH into VMs, and a private Ethernet network which provides an isolated network for each virtual cluster.

For the NAT network, most parameters can be kept as-is for the purpose of this tutorial, except *domain-name* which will generally have to be set to the domain name of the host cluster and *dns-server* which must be set to the IP of a DNS server that VMs may query to resolve services from the host cluster.

.. code-block:: yaml
  :caption: /etc/pcocc/networks.yaml

  nat-rssh:
    # Provides acces to the host network via NAT
    type: nat
    settings:
    [..]
      # Domain name and DNS server to provide to VMs via DHCP
      domain-name: "domain.name.com"
      dns-server: "0.0.0.0"
    [..]

The private network configuration should also require little to no change. The *host-if-suffix* parameter can be used if compute nodes have specific hostnames to address each network interface. For example, if a compute node known by SLURM as computeXX can reached more efficiently via IPoIB at the computeXX-ib address, the *host-if-suffix* parameter can be set to *-ib* so that the Ethernet tunnels between hypervisors transit over IPoIB. Raising the MTU may also help improve performance.

.. code-block:: yaml
  :caption: /etc/pcocc/networks.yaml

  [..]
  # Define a private ethernet network isolated from the host
  pv:
    # Private ethernet network isolated from the host
    # Ethernet (Layer 2) inter-VM packets are relayed between hosts
    # via a Layer 3 tunnel
    type: pv
    settings:
      [...]
      # Network mtu
      mtu: "1500"
      # Suffix to append to remote hostnames when tunneling
      # Ethernet packets
      host-if-suffix: ""


The ``/etc/pcocc/resources.yaml`` configuration file defines sets of resources, currently only networks, that templates may reference. The default configuration is also sufficient for this tutorial. Two resource sets are defined, *standalone* for an isolated VM which only needs the NAT network and *cluster* for VMs which are part of a virtual cluster and require a private Ethernet network to communicate with one another.

.. code-block:: yaml
  :caption: /etc/pcocc/resources.yaml

  [...]
  cluster:
    networks:
      - nat-rssh
      - pv

The ``/etc/pcocc/templates.yaml`` configuration file contains globally defined templates which will be avalaible to all users. It does not need to be modified intially.

The ``/etc/pcocc/batch.yaml`` configuration file contains configuration pertaining to the batch environment. Define the addresses and client port of your etcd servers and select a CA certificate if needed (for https protocol). For password authentication to etcd, create a root-owned file named ``/etc/pcocc/etcd-password`` with 0600 permissions containing the etcd root password in plain text.

To validate this configuration, you may launch the following command on a compute node as *root*::

  pcocc internal setup init

It must run without error, and a bridge interface named according to the configuration of the NAT network must appear in the list of network interfaces on the node. You may then launch as *root*, on the same node::

  pcocc internal setup cleanup

The bridge interface should then have disappeared.

Building a template and launching a virtual cluster
___________________________________________________

This tutorial demonstrates how to build VM images with cloud-init to instantiate virtual clusters. Cloud-init is a configuration tool which allows to configure a VM, typically at first boot, using a set of directives and parameters provided by the user through the VM management tool. Most Linux distributions provide cloud images which are pre-built disk images with the cloud-init service enabled at boot so that a VM booting on such a disk image will configure itself on first boot.

For this tutorial, we'll use a CentOS 7 cloud image which can been downloaded from the CentOS repositories (`direct link <http://cloud.centos.org/centos/7/images/CentOS-7-x86_64-GenericCloud.qcow2.xz>`_).

To create a pcocc image template from this archive, create a new directory for the template, extract the image inside and rename it to the name *image*. The directory must be accessible from submit and compute nodes.

For example, as a regular user, on an interactive node::

   $ 7za e CentOS-7-x86_64-GenericCloud.qcow2.xz
   $ mkdir -p ~/images/ci-centos
   $ mv CentOS-7-x86_64-GenericCloud.qcow2 ~/images/ci-centos/image

Add the matching minimal template definition in your personal pcocc configuration:

.. code-block:: yaml
   :caption: ~/.pcocc/templates.yaml

   ci-centos:
     image: "~/images/ci-centos"
     resource-set: "cluster"

Notice that this template references the *cluster* resource set which was defined in the Installation section.

Verify that the template is properly defined::

   pcocc template list

You can now instantiate a VM from this template with the *pcocc alloc* command. Options to this command are passed to SLURM which allows to select a partition, account, or to specifiy the number of core per task (VM), as in the example below which allocates a VM on 4 cores::

   $ pcocc alloc -c 4 ci-centos

This command places the user in a shell which allows to interact with the virtual cluster without having to designate it explicitely (this is by analogy with the *salloc* SLURM command, there is also a *pcocc batch* command which mimics SLURM's sbatch). The virtual cluster is automatically destroyed when the shell is terminated.

From this shell connect to the console of the VM using::

  pcocc console vm0

Note that, since you are in the aforementioned shell, pcocc commands will automatically target the current virtual cluster, but you can always target a specific cluster by jobid/jobname using the -j/-J pcocc options. You should now see the boot process of the VM (use *pcocc console -l* to view the logs if you missed it). Once the boot process completes, you end up with the login prompt which you cannot use since you did not define any user for your VM. Exit the console by pressing Ctrl-C three times.

The next step is to configure your virtual machine by providing a cloud-config file (see the `cloud-config documentation <http://cloudinit.readthedocs.org/en/latest/topics/examples.html>`_). For this tutorial, you may use the sample configuration provided below. It disables the standard repositories (to prevent timeouts in case you don't have direct access to the Internet), creates the specified user and adds the public key to its list authorized keys. It also generates a public/private key pair for the root user which will be used to connect from one VM to the other. For this simple cluster, we don't want to deploy a DHCP or DNS server to manage addresses on the private network. Instead, we use a simple script which configures the Ethernet interface on the private Ethernet network with an IP derived on from the interface's MAC address. It also setups ARP entries to reduce broadcast traffic on large virtual clusters and populates entries in /etc/hosts.

.. literalinclude:: ./cloud-config-example

Copy this configuration file to your home directory and fill in the *user* and *ssh_authorized_keys* values with your desired username and public key. Edit your personal configuration to reference this cloud-config file:

.. code-block:: yaml
   :caption: ~/.pcocc/templates.yaml

   ci-centos:
     image: "~/images/ci-centos"
     resource-set: "cluster"
     user-data: "~/cloud-config-example"

Instantiate a new VM from this template as in the previous step. You can follow the cloud-init configuration process in the console output. Once the process completes, you should be able to connect to the VM via SSH using the username and key defined in the cloud-config file::

 $ pcocc ssh <user>@vm0

You can now save a new revison of your image with the configuration applied::

  login-node$ pcocc ssh <user>@vm0
  vm0$ sudo shutdown -H now
  login-node$ pcocc save vm0

Next time you instantiate a VM from this template, the new revision will be used. Only the differences between two consecutive revisions are saved which means you need to keep all the intermediate revisions in the image template folder. You can now start a cluster with several VMs. For example to start eight quad-core VMs::

 $ pcocc alloc -c 4 ci-centos:8

You should now be able to connect to any of the 8 VMs with pcocc ssh and VMs should be able to ping one another on their private network.
