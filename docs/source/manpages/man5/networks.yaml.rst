.. _networks.yaml:

|networks.yaml_title|
=====================

Description
***********

:file:`/etc/pcocc/networks.yaml` is a YAML formatted file defining virtual networks available to pcocc VMs. Virtual networks are referenced through VM resource sets defined in the :file:`/etc/pcocc/resources.yaml` configuration file. For each virtual cluster, private instances of the virtual networks referenced by its VMs are created, which means each virtual network instance is only shared by VMs within a single virtual cluster.

A network is defined by its name, type and settings, which are specific to each network type. Two types of networks are supported: Ethernet and Infiniband.

.. warning::
  Before editing this configuration file on a compute node, you should first make sure that no VMs are running on the node and execute the following command, as root::

   pcocc internal setup cleanup


Syntax
******

:file:`/etc/pcocc/networks.yaml` contains a key/value mapping. Each key defines a network by its name and the associated value must contain two keys: **type** which defines the type of network to define, and **settings** which is a key/value mapping defining the parameters for this network.  This is summed up in the example below::

    # Define a network named 'network1'
    network1:
        # Select the network type
        type: ethernet
        # Define settings for ethernet networks
        settings:
            setting1: 'foo'
            setting2: 'bar'

The following networks are supported:

Ethernet network
****************
A virtual Ethernet network is defined by using the network type *ethernet*. A VM connected to a network of this type receives an Ethernet interface linked to an isolated virtual switch. All the VMs of a virtual cluster connected to a given network are linked to the same virtual switch. Connectivity is provided by encapsulating Ethernet packets from the VMs in IP tunnels between hypervisors. If the **network-layer** parameter is set to *L2* pcocc only provides Ethernet layer 2 connectivity between the VMs. The network is entirely isolated and no services (such as DHCP) are provided, which means the user is responsible for configuring the VM interfaces as he likes. If the **network-layer** is set to *L3* pcocc also manages IP addressing and optionally provides access to external networks through a gateway which performs NAT (Network Address Translation) using the hypervisor IP as source. Reverse NAT can also be setup to allow connecting to a VM port such as the SSH port from the outside. DHCP and DNS servers are automatically setup on the private network to provide IP addresses for the VMs. The available parameters are:

**dev-prefix**
 Prefix to use when assigning names to virtual devices such as bridges and TAPs created on the host.
**network-layer**
 Whether pcocc should provide layer 3 services or only a layer 2 Ethernet network (see above). Can be set to:

   * *L3* (default): Manage IP layer and provide services such as DHCP
   * *L2*: Only provide layer 2 connectivity

**mtu**
 MTU of the Ethernet network. (defaults to 1500)

.. warning::
 Please note that the MTU of the Ethernet interfaces in the VMs has to be set 50 bytes lower than this value to account for the encapsulation headers. The DHCP server on a L3 network automatically provides an appropriate value.

**mac-prefix**
 Prefix to use when assigning MAC addresses to virtual Ethernet interfaces. MAC addresses are assigned to each VM in order starting from the MAC address constructed by appending zeros to the prefix. (defaults to 52:54:00)
**host-if-suffix**
 Suffix to append to hostnames when establishing a remote tunnel if compute nodes have specific hostnames to address each network interface. For example, if a compute node known by SLURM as computeXX can reached more efficiently via IPoIB at the computeXX-ib address, the **host-if-suffix** parameter can be set to *-ib* so that the Ethernet tunnels between hypervisors transit over IPoIB.

The following parameters only apply for a *L3* network:

**int-network**
 IP network range in CIDR notation reserved for assigning IP addresses to VM network interfaces via DHCP. This network range should be unused on the host and not be routable. It is private to each virtual cluster and VMs get a fixed IP address depending on their rank in the virtual cluster. (defaults to 10.200.0.0/16)
**ext-network**
 IP network range in CIDR notation reserved for assigning unique VM IPs on the host network stack. This network range should be unused on the host and not be routable. (defaults to 10.201.0.0/16)
**dns-server**
 The IP of a domain name resolver to forward DNS requests. (defaults to reading resolv.conf on the host)
**domain-name**
 The domain name to provide to VMs via DHCP. (defaults to pcocc.<host domain name>)
**dns-search**:
 Comma separated DNS search list to provide to VMs via DHCP in addition to the domain name.
**ntp-server**
 The IP of a NTP server to provide to VMs via DHCP.
**allow-outbound**
 Set to *none* to prevent VMs from establishing outbound connections.
**reverse-nat**
 A key/value mapping which can be defined to allow inbound connections to a VM port via reverse NAT of a host port. It contains the following keys:

 **vm-port**
  The VM port to make accessible.
 **min-host-port**
  Minimum port to select on the host for reverse NATing.
 **max-host-port**
  Maximum port to select on the host for reverse NATing.


The example below defines a managed network with reverse NAT for SSH access:

.. code-block:: yaml

  # Define an ethernet network NAT'ed to the host network
  # with a reverse NAT for the SSH port
  nat-rssh:
    type: ethernet
    settings:
      # Manage layer 3 properties such as VM IP adresses
      network-layer: "L3"

      # Name prefix used for devices created for this network
      dev-prefix: "nat"

      # MTU of the network
      mtu: 1500

      reverse-nat:
        # VM port to expose on the host
        vm-port: 22
        # Range of free ports on the host to use for reverse NAT
        min-host-port: 60222
        max-host-port: 60322

The example below defines a private layer 2 network ::

  # Define a private ethernet network isolated from the host
  pv:
    # Private ethernet network isolated from the host
    type: ethernet
    settings:
      # Only manage Ethernet layer
      network-layer: "L2"

      # Name prefix used for devices created for this network
      dev-prefix: "pv"

      # MTU of the network
      mtu: 1500

IB network
**********

A virtual Infiniband network is defined by using the type *infiniband*. An Infiniband partition is allocated for each virtual Infiniband network instantiated by a virtual cluster. VMs connected to Infiniband networks receive direct access to an Infiniband SRIOV virtual function restricted to using the allocated partition as well as the default partition, as limited members, which is required for IPoIB.

.. warning::
 This means that, for proper isolation of the virtual clusters, physical nodes should be set as limited members of the default partition and/or use other partitions for their communications.

pcocc makes use of a daemon on the OpenSM node which dynamically updates the partition configuration (which means pcocc has to be installed on the OpenSM node). The daemon generates the configuration from a template holding the static configuration to which it appends the dynamic configuration. Usually, you will want to copy your current configuration to the template file (/etc/opensm/partitions.conf.tpl in the example below) and have pcocc append its dynamic configuration to form the actual partition file referenced in the OpenSM configuration. The following parameters can be defined:

**host-device**
 Device name of a physical function from which to map virtual functions in the VM.
**min-pkey**
 Minimum pkey value to assign to virtual clusters.
**max-pkey**
 Maximum pkey value to assign to virtual clusters.
**opensm-daemon**
 Name of the OpenSM process (to signal from the pkeyd daemon).
**opensm-partition-cfg**
 The OpenSM partition configuration file to generate dynamically.
**opensm-partition-tpl**
 The file containing the static partitions to include in the generatied partition configuration file.

The example below sums up the available parameters::

    ib:
      # Infiniband network based on SRIOV virtual functions
      type: infiniband
      settings:
        # Host infiniband device
        host-device: "mlx5_0"
        # Range of PKeys to allocate for virtual clusters
        min-pkey: "0x2000"
        max-pkey: "0x3000"
        # Name of opensm process
        opensm-daemon: "opensm"
        # Configuration file for opensm partitions
        opensm-partition-cfg: /etc/opensm/partitions.conf
        # Template for generating the configuration file for opensm partitions
        opensm-partition-tpl: /etc/opensm/partitions.conf.tpl

As explained above, pcocc must be installed on the OpenSM node(s) and the *pkeyd* daemon must be running to manage the partition configuration file::

   systemctl enable pkeyd
   systemctl start pkeyd

Sample configuration file
*************************

This is the default configuration file for reference::

    # Define an ethernet network NAT'ed to the host network
    # with a reverse NAT for the SSH port
    nat-rssh:
      type: ethernet
      settings:
        # Manage layer 3 properties such as VM IP adresses
        network-layer: "L3"

        # Private IP range for VM interfaces on this ethernet network.
        int-network: "10.251.0.0/16"

        # External IP range used to map private VM IPs to unique VM IPs on the
        # host network stack for NAT.
        ext-network: "10.250.0.0/16"

        # Name prefix used for devices created for this network
        dev-prefix: "nat"

        # MTU of the network
        mtu: 1500

        reverse-nat:
          # VM port to expose on the host
          vm-port: 22
          # Range of free ports on the host to use for reverse NAT
          min-host-port: 60222
          max-host-port: 60322

        # Suffix to append to remote hostnames when tunneling
        # Ethernet packets
        host-if-suffix: ""


    # Define a private ethernet network isolated from the host
    pv:
      # Private ethernet network isolated from the host
      type: ethernet
      settings:
        # Only manage Ethernet layer
        network-layer: "L2"

        # Name prefix used for devices created for this network
        dev-prefix: "pv"

        # MTU of the network
        mtu: 1500

        # Suffix to append to remote hostnames when tunneling
        # Ethernet packets
        host-if-suffix: ""


    # Define a private Infiniband network
    ib:
      # Infiniband network based on SRIOV virtual functions
      type: infiniband
      settings:
        # Host infiniband device
        host-device: "mlx5_0"
        # Range of PKeys to allocate for virtual clusters
        min-pkey: "0x2000"
        max-pkey: "0x3000"
        # Resource manager token to request when allocating this network
        license: "pkey"
        # Name of opensm process
        opensm-daemon: "opensm"
        # Configuration file for opensm partitions
        opensm-partition-cfg: /etc/opensm/partitions.conf
        # Template for generating the configuration file for opensm partitions
        opensm-partition-tpl: /etc/opensm/partitions.conf.tpl


See also
********

:ref:`pcocc-template(1)<template>`, :ref:`pcocc-templates.yaml(5)<templates.yaml>`, :ref:`pcocc-resources.yaml(5)<resources.yaml>`, :ref:`pcocc-newvm-tutorial(7)<newvm>`, :ref:`pcocc-configvm-tutorial(7)<configvm>`
