Networks
========

Networks are defined in the ``/etc/pcocc/networks.yaml`` configuration file and are referenced by VM templates through resource sets. When a virtual cluster is launched, pcocc creates new instances of all the virtual networks which are included in at least one of the VM templates' resource sets and connects the resulting VMs to these new networks.

A network is defined by its name, type and settings, which are specific to each network type. Three types of networks are supported: NAT Ethernet, private Ethernet and private Infiniband.

NAT Ethernet
____________

A NAT Ethernet network is defined by using the type *nat*. A VM connected to a network of this type receives an Ethernet interface connected to an isolated Ethernet network where it can only reach its host compute node which acts as a default gateway. The host will route outgoing packets from the VM using NAT and optionally route incoming packets from a host port to a selected port of the VM. For the *pcocc ssh* command to work, the VM must be connected to a NAT network which exposes the SSH port. A DHCP server is automatically started on the host to provide the network configuration to the VM on boot. The example below describes the available parameters:

.. code-block:: yaml
  :caption: /etc/pcocc/networks.yaml

  # Define an NAT Ethernet network named 'nat-ssh'
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



Private Ethernet
________________

A private Ethernet network is defined by using the type *pv*. A VM connected to a network of this type receives an Ethernet interface connected to an isolated Ethernet network where it can reach all the other VMs of its virtual cluster connected to the network. Connectivity is provided by encapsulating Ethernet packets from the VM in IP tunnels between hypervisors. The example below describes the available parameters:

.. code-block:: yaml
  :caption: /etc/pcocc/networks.yaml

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

Since the current implementation has poor performance for broadcast packets, you may want to prevent broadcast traffic on large virtual clusters by setting permanent ARP entries for the IPs of each VM (see the cloud-config example in the Getting Started section).

Private Infiniband
__________________

A private Infiniband network is defined by using the type *ib*. An Infiniband partition is allocated for each virtual Infiniband network instanciated by a virtual cluster. VMs connected to Infiniband networks receive direct access to an Infiniband SRIOV virtual function restricted to using the allocated partition as well as the default partition, as limited members, which is required for IPoIB. This means that, for proper isolation of the virtual clusters, physical nodes should be set as limited members of the default partition and/or use other partitions for their communications.

Pcocc makes use of a daemon on the OpenSM node which dynamically updates the partition configuration (which means pcocc has to be installed on the OpenSM node). The daemon generates the configuration from a template holding the static configuration to which it appends the dynamic configuration. Usually, you will want to copy your current configuration to the template file (``/etc/opensm/partitions.conf.tpl`` in the example below) and have pcocc append its dynamic configuration to form the actual partition file referenced in the OpenSM configuration.

The configuration parameters for an Infiniband network are described in the following example:

.. code-block:: yaml
  :caption: /etc/pcocc/networks.yaml

  # Define a private ifiniband network named 'ib-mlx4'
  ib-mlx4:
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

A systemd unitfile is provided to start the pkeyd daemon on the OpenSM node::

  $ systemctl start pkeyd

Resource sets
=============

The ``/etc/pcocc/resources.yaml`` configuration file defines sets of resources, currently only networks, that templates may reference. The syntax is described in the examples below:

.. code-block:: yaml
  :caption: /etc/pcocc/resources.yaml

  # Define a resource set named 'cluster'
  cluster:
    # List of networks defined in networks.yaml
    networks:
      - 'nat-ssh'
      - 'internal'

  # Define a resource set named 'cluster-ib'
  cluster-ib:
    # List of networks defined in networks.yaml
    networks:
      - 'nat-ssh'
      - 'ib-mlx4'
