.. _scp:

|scp_title|
===========

Synopsis
********

pcocc scp [OPTIONS] [SCP_OPTIONS]...

Description
***********

Transfer files to a VM via scp. See the scp(1) manpage for documentation on scp options.

.. warning::
    This requires the VM to have its ssh port reverse NAT'ed to the host in its NAT network configuration.

Options
*******

    -j, \-\-jobid [INTEGER]
                Jobid of the selected cluster

    -J, \-\-jobname [TEXT]
                Job name of the selected cluster
    \-\-user [TEXT]
                Select cluster among jobs of the specified user

    -h, \-\-help
                Show this message and exit.

Examples
********

To copy a directory to vm0 of the job named *centos*::

  pcocc scp -J centos -r dir vm0:

.. note::
    By default, scp(1) uses the host username to log in. Depending on the VM configuration, it may be necessary to specify another username.

To copy a file to vm1 of the default job as the demo user::

  pcocc scp ./foo demo@vm1:~/foo

To copy a file from vm2 of the default job as root::

  pcocc scp root@vm2:~/data ./data


See also
********

scp(1), :ref:`pcocc-ssh(1)<ssh>`, :ref:`pcocc-nc(1)<nc>`, :ref:`pcocc-exec(1)<exec>`, :ref:`pcocc-networks.yaml(5)<networks.yaml>`, :ref:`pcocc-9pmount-tutorial.yaml(7)<9pmount>`
