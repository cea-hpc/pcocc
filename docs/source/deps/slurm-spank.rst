#####################################
Installing the Slurm SPANK Lua plugin
#####################################

pcocc uses the Slurm SPANK plugin infrastructure, and in particular, its LUA interface to setup compute nodes for running VMs. This interface is provided by the slurm-spank-plugins-lua package. pcocc will install a LUA script in the :file:`/etc/slurm/lua.d` directory, :file:`vm-setup.lua`.

****************
Installing SPANK
****************

You may download the SPANK plugins from their `Github <https://github.com/chaos/slurm-spank-plugins>`_. In this example download the latest tarball from the `releases page <https://github.com/chaos/slurm-spank-plugins/releases>`_ to build a RPM: ::

    wget https://github.com/chaos/slurm-spank-plugins/archive/0.37.tar.gz
    mkdir -p $HOME/rpmbuild/SOURCES/
    cp 0.37.tar.gz $HOME/rpmbuild/SOURCES/slurm-spank-plugins-0.37.tgz
    tar xvf 0.37.tar.gz

In the source directory, edit the RPM specfile as follows (adapt to the current version number):

.. code-block:: text
    :caption: ./slurm-spank-plugins.spec

    Name:  slurm-spank-plugins
    Version: 0.37
    Release: 1

Proceed to building the RPM after installing required dependencies::

    yum-builddep ./slurm-spank-plugins.spec
    yum install lua-devel
    rpmbuild -ba ./slurm-spank-plugins.spec --with lua --with llnl_plugins

Put the resulting packages in your repositories and install slurm-spank-plugins-lua on your front-end and compute nodes or wait for pcocc to pull it as a dependency.

*****************
Configuring SPANK
*****************

For the pcocc plugin to be properly loaded, we have to instruct the Slurm SPANK infrastructure to load all LUA addons in the standard :file:`/etc/slurm/lua.d` directory by setting the following content inside :file:`/etc/slurm/plugstack.conf`:

.. code-block:: text
    :caption: /etc/slurm/plugstack.conf

    required /usr/lib64/slurm/lua.so /etc/slurm/lua.d/*
