.. _installation_guide:

Installing pcocc
================

This guide describes the installation of pcocc on a CentOS / RHEL 7 distribution or derivative. Installation on other distributions is not supported at this time even though it should work with minor adaptations.

Requirements and dependencies
*****************************

pcocc makes use of several external components or services among which:

* A Slurm cluster with the Lua SPANK plugin
* Open vSwitch
* An etcd database and the etcd python bindings
* Qemu and KVM

For virtual Infiniband networks:

* Mellanox adapters and drivers supporting SRIOV
* Mellanox OFED is recommended (especially for adapters based on the mlx5 driver)
* Linux kernel with VFIO support (CentOS / RHEL 7 kernels support this feature)

pcocc makes a few assumptions about the configuration of the host clusters such as:

* Users have home directories shared between front-end and compute nodes
* Users may ssh to allocated compute nodes without a password (using GSSAPI or public key authentication for example)
* Slurm manages task affinity and memory allocation

On a CentOS / RHEL 7 distribution, most dependencies are provided with a combination of the standard repositories and EPEL.

This guide also assumes that you already have a working Slurm cluster. The following guidelines should help you install other dependencies which are not available from standard repositories:

.. toctree::
   :maxdepth: 1

   deps/openvswitch
   deps/slurm-spank
   deps/python-etcd

RPM based installation
**********************

The easiest way to install pcocc on a RPM based distribution is to build a package and install it on all your compute and front-end nodes. Starting from the source distribution, you can go to the root directory of the sources and run the following command to build a RPM:

    python setup.py bdist_rpm

You may need to install the *rpm-build* package first. The resulting pcocc RPM should be installed with the package manager which will pull all the necessary dependencies from your configured repositories. If you are missing something, please have a look at the guidelines provided in the previous section.


Setup compute nodes and required services
*****************************************

Hardware virtualization support
-------------------------------

Check that your compute nodes processors have virtualization extensions enabled, and if not (and possible) enable them in the bios::

    #This command should return a match
    grep -E '(vmx|svm)' /proc/cpuinfo


The kvm module must be loaded on all compute nodes and accessible (rw permissions) by all users of pcocc. You can use a udev rule such as:

.. code-block:: text
   :caption: /etc/udev/rules.d/80-kvm.rules

   KERNEL=="kvm", GROUP=="xxx", MODE="xxx"

Adjust the GROUP and MODE permissions to fit your needs. If virtualization exetensions are not enabled or access to kvm is not provided, pcocc will run Qemu in emulation mode which will be slow.


Slurm setup
-----------
It is recommended that Slurm is confitured to manage process tracking, CPU affinity and memory allocation with cgroups. Set the following parameters in your Slurm configuration files:

.. code-block:: text
    :caption: /etc/slurm/slurm.conf

    TaskPlugin=task/cgroup
    Proctracktype=proctrack/cgroup
    SelectTypeParameters=CR_Core_Memory

.. code-block:: text
    :caption: /etc/slurm/cgroup.conf

    ConstrainCores=yes
    TaskAffinity=yes

Make sure that your node definitions have coherent memory size et CPU count parameters for example:

.. code-block:: text
    :caption: /etc/slurm/slurm.conf

    DefMemPerCPU=2000
    NodeName=Node1 CPUs=8 RealMemory=16000 State=UNKNOWN
    ...

Note how DefMemPerCPU times CPUs equals RealMemory. As described in the requirements section, you need to enable Lua SPANK plugins. Follow this guide if you haven't done it yet:

.. toctree::
   :maxdepth: 1

   deps/slurm-spank

etcd setup
----------

pcocc requires access to a working etcd cluster with authentication enabled. Since pcocc will dynamically create users and permissions, you will probably want to deploy a dedicated instance. In its most basic setup, etcd is very simple to deploy. You just need to start the daemon on a server without any specific configuration. Authentication can be enabled with the following commands (you'll have to define a root password which you'll reference later in the pcocc onciguration files)::

  $ etcdctl user add root
  $ etcdctl auth enable
  $ etcdctl -u root:<password> role remove guest

This configuration can be used for a quick evaluation of pcocc. For a more reliable and secure setup you may refer to this guide:

.. toctree::
   :maxdepth: 1

   deps/etcd-production

Basic configuration
*******************

The configuration of pcocc itself consists in editing YAML files in :file:`/etc/pcocc/`. These files must be present on all front-end and compute nodes.

First, create a root-owned file named :file:`/etc/pcocc/etcd-password` with 0600 permissions containing the etcd root password in plain text.

The :file:`/etc/pcocc/batch.yaml` configuration file contains configuration pertaining to Slurm and etcd. Define the hostnames and client port of your etcd servers:

.. code-block:: yaml
   :caption: /etc/pcocc/batch.yaml

   type: slurm
   settings:
     etcd-servers:
       - node1
       - node2
       - node3
     etcd-client-port: 2379
     etcd-protocol: http
     etcd-auth-type: password

If you enabled TLS, select the *https* etcd-protocol and define the **etcd-ca-cert** parameter to the path of the CA certificate created for etcd (see :ref:`Deploy a secure etcd cluster <etcd-production>`).

The sample network configuration in :file:`/etc/pcocc/networks.yaml` defines two networks, a NAT Ehernet network which connects each VM to the host network via NAT routing, and allows to SSH into VMs, and a private Ethernet network which provides an isolated L2 Ethernet network for each virtual cluster.

For the NAT network, most parameters can be kept as-is for the purpose of this tutorial, as long as the default network ranges do not conflict with your existing addressing plan. You have to define the **domain-name** parameter which can be set to the domain name of the host cluster and the **dns-server** parameter which should be set to the IP of a DNS server that VMs may query to resolve services from the host cluster. You may also provide a **ntp-server**:

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

The private network configuration should also require little to no change. The **host-if-suffix** parameter can be used if compute nodes have specific hostnames to address each network interface. For example, if a compute node known by Slurm as computeXX can reached more efficiently via IPoIB at the computeXX-ib address, the **host-if-suffix** parameter can be set to *-ib* so that the Ethernet tunnels between hypervisors transit over IPoIB. Raising the MTU may also help improve performance if your physical network allows it.

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

The :file:`/etc/pcocc/resources.yaml` configuration file defines sets of resources, currently only networks, that templates may reference. The default configuration is also sufficient for this tutorial. By default, two resource sets are defined, *standalone* for an isolated VM which only needs the NAT network and *cluster* for VMs which are part of a virtual cluster and require a private Ethernet network to communicate with one another.

The :file:`/etc/pcocc/templates.yaml` configuration file contains globally defined templates which will be avalaible to all users. It does not need to be modified intially.


Network configuration verification
**********************************

To validate this configuration, you may launch the following command on a compute node as root::

  pcocc internal setup init

It must run without error, and a bridge interface named according to the configuration of the NAT network must appear in the list of network interfaces on the node::

 # ip a
 [..]
 5: natbr: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
    link/ether 52:54:00:c0:c0:c0 brd ff:ff:ff:ff:ff:ff
    inet 10.254.0.1/16 brd 10.254.255.255 scope global natbr
       valid_lft forever preferred_lft forever

You may then launch as root, on the same node::

  pcocc internal setup cleanup

It should also run without error and the bridge interface should have disappeared. You should now be able to run VMs with pcocc. Please follow the :ref:`pcocc-newvm-tutorial(7)<newvm>` tutorial to learn how to define VM templates an run your first VMs.
