.. _nc:

|nc_title|
==========

Synopsis
********

pcocc nc [OPTIONS] [NC_OPTS]...

Description
***********

Connect to a VM via nc

.. warning::
    This requires the VM to have the selected port reverse NAT'ed to the host in its NAT network configuration.

Options
*******

    -j, \-\-jobid INTEGER
            Jobid of the selected cluster

    -J, \-\-jobname TEXT
                Job name of the selected cluster

    \-\-user TEXT
                Select cluster among jobs of the specified user

    -h, \-\-help
                Show this message and exit.

Example
*******

To open a connection to the SSH server running in the first VM of the xjob called *ubuntu*::

    pcocc nc -J ubuntu vm0 22

This is can be useful to simplify connections to pcocc VMs using SSH ProxyCommands. For example by adding the following content to the *~.ssh/config* file::

    Host ubuntu-vm0
    ProxyCommand pcocc nc -J ubuntu vm0 22

It is possible to connect to the first VM of the job named *ubuntu* without relying on pcocc ssh::

    ssh ubuntu-vm0

See also
********

:ref:`pcocc-ssh(1)<ssh>`, :ref:`pcocc-scp(1)<scp>`, :ref:`pcocc-run(1)<run>`, :ref:`pcocc-networks.yaml(5)<networks.yaml>`

