#######################
Installing Open vSwitch
#######################

pcocc relies on Open vSwitch to provide the VMs with private virtual networks. Open vSwitch can be downloaded from `official website <http://openvswitch.org/download/>`_. The official `installation guide <http://docs.openvswitch.org/en/latest/intro/install/general/>`_ can be used as an additional source for this process.

****************
Building the RPM
****************

First, download the latest stable Open vSwitch release (2.5.3 at the time of this writing)::

    mkdir -p ~/rpmbuild/SOURCES
    wget http://openvswitch.org/releases/openvswitch-2.5.3.tar.gz
    cp openvswitch-2.5.3.tar.gz ~/rpmbuild/SOURCES/
    tar xfz openvswitch-2.5.3.tar.gz
    sed 's/openvswitch-kmod, //g' openvswitch-2.5.3/rhel/openvswitch.spec > openvswitch-2.5.3/rhel/openvswitch_no_kmod.spec

Install required dependencies and compile the RPM::

    yum-builddep ~/openvswitch-2.5.3/rhel/openvswitch_no_kmod.spec
    rpmbuild -ba --nocheck ~/openvswitch-2.5.3/rhel/openvswitch_no_kmod.spec

******************************
Installation and configuration
******************************

Install the RPM on all compute nodes or wait for it to be pulled as a dependency by pcocc. You'll also want to enable the service and start it (or reboot your compute nodes)::

    # On all compute nodes as root
    systemctl enable openvswitch
    systemctl start openvswitch

