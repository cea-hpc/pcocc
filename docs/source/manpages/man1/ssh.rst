.. _ssh:

|ssh_title|
===========

Synopsis
********

pcocc ssh [OPTIONS] [SSH_OPTIONS]...

Description
***********

Connect to a VM via ssh. See the ssh(1) manpage for documentation on ssh options.

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

To log in to vm0 of the job named *centos*::

    pcocc ssh -J centos vm0

.. note::
    By default, ssh(1) uses the host username to login. Depending on the VM configuration, it may be necessary to specify another username.

To log in to vm4 of the default job as root::

    pcocc ssh root@vm4

See also
********

ssh(1), :ref:`pcocc-scp(1)<scp>`, :ref:`pcocc-console(1)<console>`, :ref:`pcocc-nc(1)<nc>`, :ref:`pcocc-display(1)<display>`, :ref:`pcocc-run(1)<run>`, :ref:`pcocc-networks.yaml(5)<networks.yaml>`, :ref:`pcocc-9pmount-tutorial.yaml(7)<9pmount>`
