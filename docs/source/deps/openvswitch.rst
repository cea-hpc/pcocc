#######################
Installing Open vSwitch
#######################

pcocc relies on Open vSwitch to provide the VMs with private virtual networks. Open vSwitch can be downloaded from `official website <http://openvswitch.org/download/>`_. The official `installation guide <http://docs.openvswitch.org/en/latest/intro/install/general/>`_ can be used as an additional source for this process.

****************
Building the RPM
****************

Get tarball and specfile from latest stable Open vSwitch release (2.5.3 at the time of this writing) and build the RPM::

    curl -O http://openvswitch.org/releases/openvswitch-2.5.3.tar.gz
    tar xzf openvswitch-2.5.3.tar.gz openvswitch-2.5.3/rhel/openvswitch.spec -O openvswitch.spec
    yum-builddep openvswitch.spec
    rpmbuild -ba --define "_sourcedir $PWD" openvswitch.spec

******************************
Installation and configuration
******************************

Install the RPM on all compute nodes or wait for it to be pulled as a dependency by pcocc. You'll also want to enable the service and start it (or reboot your compute nodes)::

    # On all compute nodes as root
    systemctl enable openvswitch
    systemctl start openvswitch

