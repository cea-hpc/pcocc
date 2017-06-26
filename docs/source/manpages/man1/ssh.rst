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

To login on vm0 of the job named *centos*::

    pcocc ssh -J centos vm0

.. note::
    As no user was specified to ssh, it logs in as the current user on the host. Make sure it is defined in your VM.

To login on vm4 of the default job as root::

    pcocc ssh root@vm4

See also
********

:ref:`pcocc-scp(1)<scp>`, :ref:`pcocc-console(1)<console>`, :ref:`pcocc-nc(1)<nc>`, :ref:`pcocc-display(1)<display>`, :ref:`pcocc-exec(1)<exec>`, :ref:`pcocc-networks.yaml(5)<networks.yaml>`, :ref:`pcocc-9pmount-tutorial.yaml(7)<9pmount>`
