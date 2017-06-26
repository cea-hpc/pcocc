.. _networks.yaml:

|networks.yaml_title|
=====================

Description
***********

:file:`/etc/pcocc/networks.yaml` is a YAML formatted file defining virtual networks which can be provided to pcocc VMs within resource sets defined in the :file:`/etc/pcocc/resources.yaml` configuration file. pcocc virtual networks are instantiated for each virtual cluster, which means that private virtual networks link a subset of the VMs within a virtual cluster (those instantiated from templates referencing the private virtual network).

A network is defined by its name, type and settings, which are specific to each network type. Three types of networks are supported: NAT Ethernet, private Ethernet and private Infiniband.

Syntax
******

:file:`/etc/pcocc/networks.yaml` contains a key/value mapping. Each key defines a network by its name and the associated value must contain two keys: **type** which defines the type of network to define, and **settings** which is a key/value mapping defining the parameters for this network.  This is summed up in the example below::

    # Define a network named 'network1'
    network1:
        # Select the network type
        type: nat
        # Define settings for nat networks
        settings:
            setting1: 'foo'
            setting2: 'bar'

The following networks are supported:

NAT network
***********
A NAT Ethernet network is defined by using the type *nat*. A VM connected to a network of this type receives an Ethernet interface connected to an isolated Ethernet network where it can only reach its host compute node which acts as a default gateway. The host will route outgoing packets from the VM using NAT and optionally route incoming packets from a host port to a selected port of the VM. For the pcocc ssh command to work, the VM must be connected to a NAT network which exposes the SSH port. A DHCP server is automatically started on the host to provide the network configuration to the VM on boot. The following parameters can be defined:

**nat-network**
 IP range reserved for this network on the host network stack in CIDR notation. This network range should be unused on the host and not be routable.
**vm-network**
 IP range which will be assigned to VMs network interface in CIDR notation. on the host network in CIDR notation. This network range should be unused on the host and not be routable.
**vm-network-gw**
 IP which will be assigned to the host on the VM network to act as a default gateway and route VM packets to the outside via NAT.
**vm-ip**
 IP on the VM network to assign to the VM via DHCP.
**vm-hwaddr**
 MAC address of the Ethernet device exposed in the VM.
**bridge**
 Name of the bridge device to create on nodes for this network.
**bridge-hwaddr**
 MAC address for the host bridge device.
**tap-prefix**
 Prefix to use when assigning name to TAP devices created on the host.
**mtu**
 MTU for the VM network.
**domain-name**
 The domain name to provide to VMs via DHCP.
**dns-server**
 The IP of a domain name resolver to provide to VMs via DHCP.
**ntp-server**
 The IP of a NTP server to provide to VMs via DHCP.
**allow-outbound**
 Set to *none* to disallow VMs from establishing outbound connections.
**reverse-nat**
 A key/value mapping which can be defined to allow inbound connections to a VM port via reverse NAT of a host port. It contains the following keys:

 **vm-port**
  The VM port to make accessible.
 **min-host-port**
  Minimum port to select on the  host for reverse NATing.
 **max-host-port**
  Maximum port to select on the  host for reverse NATing.

The example below sums up the available parameters::

  # Provides acces to the host network via NAT
  type: nat
  settings:
    # Network for VM packets from the host point of view
    # Select a free network range from the host side
    nat-network: "10.255.0.0/16"
    # Network for VM packets from the VMs point of view
    # Select a free network range from VMs and host side
    vm-network: "10.254.0.0/16"
    # IP of the default gateway for VMs
    # Select an IP in the VM network
    vm-network-gw: "10.254.0.1"
    # IP of VM interface
    # Select an IP in the VM network
    vm-ip: "10.254.0.2"
    # MAC addr of the VM interface
    vm-hwaddr: "52:54:00:44:AE:5E"
    # Name of a bridge which will be created on hosts
    bridge: "natbr"
    # Prefix for TAP devices created on hosts
    tap-prefix: "nattap"
    # MTU of the network
    mtu: 5000
    # Domain name and DNS server to provide to VMs via DHCP
    domain-name: "vm.mydomain.com"
    dns-server: "10.19.213.2"
    reverse-nat:
      # VM port to expose on the host
      vm-port: 22
      # Range of free ports on the host to use for reverse NAT
      min-host-port: 60222
      max-host-port: 60322

Private Ethernet network
************************

A private Ethernet network is defined by using the type *pv*. A VM connected to a network of this type receives an Ethernet interface connected to an isolated Ethernet network where it can reach all the other VMs of its virtual cluster connected to the network. Connectivity is provided by encapsulating Ethernet packets from the VM in IP tunnels between hypervisors. The network is entirely isolated and no services (such as DHCP) are provided, which means the user is responsible for configuring the VM interfaces as he likes. See :ref:`pcocc-newvm-tutorial(7)<newvm>` for a simple way to perform this configuration without setting up services. The available parameters parameters are:

**mac-prefix**
 Prefix for the MAC address assigned to virtual Ethernet devices. MAC adresses are assigned to each VM in order starting from the MAC adress constructed by appending zeros to the prefix.
**bridge-prefix**
 Prefix to use when assigning names to bridge devices created on the host.
**tap-prefix**
 Prefix to use when assigning names to TAP devices created on the host.
**mtu**
 MTU to use on this network. This should be set to the MTU of the host network used to relay packets between hypervisors.

.. warning::
 Please note that the MTU of the Ethernet interfaces in the VMs have to be set 50 bytes lower than this value to account for the encapsulation headers.

**host-if-suffix**
 Suffix to append to hostnames when establishing a remote tunnel if compute nodes have specific hostnames to address each network interface. For example, if a compute node known by SLURM as computeXX can reached more efficiently via IPoIB at the computeXX-ib address, the **host-if-suffix** parameter can be set to *-ib* so that the Ethernet tunnels between hypervisors transit over IPoIB.

The example below sums up the available parameters::

    # Define a private ethernet network isolated from the host
    pv:
      # Private ethernet network isolated from the host
      # Ethernet (Layer 2) inter-VM packets are relayed between hosts
      # via a Layer 3 tunnel
      type: pv
      settings:
        # Prefix for bridge devices created on the host
        bridge-prefix: "pvbr"
        # Prefix for TAP devices created on the host
        tap-prefix: "pvtap"
        # Network mtu
        mtu: 5000
        # Suffix to append to remote hostnames when tunneling
        # Ethernet packets
        host-if-suffix: ""


IB network
**********

A private Infiniband network is defined by using the type *ib*. An Infiniband partition is allocated for each virtual Infiniband network instantiated by a virtual cluster. VMs connected to Infiniband networks receive direct access to an Infiniband SRIOV virtual function restricted to using the allocated partition as well as the default partition, as limited members, which is required for IPoIB. This means that, for proper isolation of the virtual clusters, physical nodes should be set as limited members of the default partition and/or use other partitions for their communications.

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
      type: ib
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


Sample configuration file
*************************

This is the default configuration file for reference::

    # Define a NAT Ethernet network named 'nat-ssh'
    nat-ssh:
      # Select the NAT network type
      type: nat
      settings:
        # Network for VM packets from the host point of view
        # Select a free network range from the host side
        nat-network: "10.255.0.0/16"

        # Network for VM packets from the VMs point of view
        # Select a free network range from VMs and host side
        vm-network: "10.254.0.0/16"

        # IP of the default gateway for VMs
        # Select an IP in the VM network
        vm-network-gw: "10.254.0.1"

        # IP of VM interface
        # Select an IP in the VM network
        vm-ip: "10.254.0.2"

        # MAC addr of the VM interface
        vm-hwaddr: "52:54:00:44:AE:5E"

        # Name of a bridge which will be created on hosts
        bridge: "natbr"

        # Prefix for TAP devices created on hosts
        tap-prefix: "nattap"

        # MTU of the network
        mtu: 1500

        # Domain name and DNS server to provide to VMs via DHCP
        domain-name: "domain.name.com"
        dns-server: "0.0.0.0"

        # Allow outbound connections
        # Uncomment to prevent the VM from initiating connections
        # allow-outbound: "none"

        # Optional directive: expose a VM port to the host
        reverse-nat:
          # VM port to expose on the host
          vm-port: 22
          # Range of free ports on the host to use for reverse NAT
          min-host-port: 60222
          max-host-port: 60322

    # Define a private Ethernet network named 'internal' isolated from the host
    internal:
      # Private Ethernet network isolated from the host
      # Ethernet (Layer 2) inter-VM packets are relayed between hosts
      # via a Layer 3 tunnel
      type: pv
      settings:
        # Prefix for bridge devices created on the host
        bridge-prefix: "pvbr"
        # Prefix for TAP devices created on the host
        tap-prefix: "pvtap"
        # Network mtu
        mtu: 1500
        # Suffix to append to hostnames of remote hypervisors when
        # tunneling Ethernet packets
        host-if-suffix: ""
        # Prefix for Ethernet interface MAC addresses
        mac-prefix: "52:54:00"

    # Define a private ifiniband network named 'ib'
    ib:
      # Infiniband network based on SRIOV virtual functions
      type: 'ib'
      settings:
        # Host infiniband device
        host-device: 'mlx4_0'
        # Range of PKeys to allocate for virtual clusters on this network
        min-pkey: '0x2000'
        max-pkey: '0x3000'
        # Name of the opensm process
        opensm-daemon: 'opensm'
        # Configuration file for opensm partitions
        opensm-partition-cfg: '/etc/opensm/partitions.conf'
        # Template for generating the configuration file for opensm partitions
        opensm-partition-tpl: '/etc/opensm/partitions.conf.tpl'


See also
********

:ref:`pcocc-template(1)<template>`, :ref:`pcocc-templates.yaml(5)<templates.yaml>`, :ref:`pcocc-networks.yaml(5)<networks.yaml>`, :ref:`pcocc-resources.yaml(5)<resources.yaml>`, :ref:`pcocc-newvm-tutorial(7)<newvm>`, :ref:`pcocc-configvm-tutorial(7)<configvm>`
