.. _exec:

|exec_title|
============

Synopsis
********

pcocc exec [OPTIONS] [CMD]...

Decription
**********

Execute commands through the guest agent

For this to work, the pcocc guest agent must be started in the guest. This is mostly available for internal use where we do not want to rely on a network connexion/ssh server. 

.. note::
    It is possible to detach from the output by typing *Escape + Enter*.
    In this case you may end the execution with *pcocc command release*.

Options
*******

    -i, \-\-index [INTEGER]
                Index of the VM on which the command should be executed

    -j, \-\-jobid [INTEGER]
                Jobid of the selected cluster

    -J, \-\-jobname [TEXT]
                Job name of the selected cluster

    -w, \-\-rng [TEXT]
                Rangeset or vmid on which to run the command

    -c, \-\-cores [TEXT]
                Number of cores on which to run the command

    -u, \-\-user [TEXT]
                User id to use to execute the command

    -g, \-\-gid
                Group id to use to execute the command

    -h, \-\-help
                Show this message and exit.

Examples
********

Execute a command
.................

To run a command in the first VM of the default job as the current user::

    pcocc exec "hostname"

To run the same command on all VMs (the "-" rangeset means all VM)::
    
    pcocc exec -w - "hostname"

To run a command as root in the third VM of the job named *centos*::

    pcocc exec -J centos -u root -i 2 cat /etc/shadow

See also
********

:ref:`pcocc-ssh(1)<ssh>`, :ref:`pcocc-scp(1)<scp>`, :ref:`pcocc-exec(1)<console>`, :ref:`pcocc-nc(1)<nc>`
