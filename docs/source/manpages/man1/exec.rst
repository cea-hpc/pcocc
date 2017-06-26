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


Options
*******

    -i, \-\-index [INTEGER]
                Index of the VM on which the command should be executed

    -j, \-\-jobid [INTEGER]
                Jobid of the selected cluster

    -J, \-\-jobname [TEXT]
                Job name of the selected cluster

    -u, \-\-user [TEXT]
                User id to use to execute the command

    -s, \-\-script
                Cmd is a shell script to be copied to /tmp and executed in place

    -h, \-\-help
                Show this message and exit.

Examples
********


Execute a command
.................

To run a command in the first VM of the default job as the current user::

    pcocc exec "hostname"

To run a command as root in the third VM of the job named *centos*::

    pcocc exec -J centos -u root -i 2 cat /etc/shadow


Send and execute a script
.........................

pcocc exec can copy a script to the target machine and execute it. Assuming  :file:`./script.sh` contains ::

    #!/bin/sh
    echo "Hello from $(hostname)"

To execute it on the second VM of the default job as the current user::

    $ pccoc exec -i 1 -s ./script.sh
    Hello from vm1

See also
********

:ref:`pcocc-ssh(1)<ssh>`, :ref:`pcocc-scp(1)<scp>`, :ref:`pcocc-exec(1)<console>`, :ref:`pcocc-nc(1)<nc>`
