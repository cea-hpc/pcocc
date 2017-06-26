.. _monitor-cmd:

|monitor-cmd_title|
===================

Synopsis
********

pcocc monitor-cmd [OPTIONS] [VM] [CMD]...

Description
***********

Send a command to the Qemu monitor of a VM. The commands are not interpreted by pcocc and are directly passed to the Qemu monitor. It allows to use specific Qemu features not exposed by pcocc. For detailed documentation on the available commands, refer to the Qemu documentation: https://www.qemu.org/documentation/.

Options
*******

-j, \-\-jobid [INTEGER]
            Jobid of the selected cluster

-J, \-\-jobname [TEXT]
            Job name of the selected cluster

-h, \-\-help
            Show this message and exit.

Examples
********

Obtain help on available Qemu monitor commands::

    $ pcocc monitor-cmd help
    acl_add aclname match allow|deny [index] -- add a match rule to the access control list
    acl_policy aclname allow|deny -- set default access control list policy
    ..
    xp /fmt addr -- physical memory dump starting at 'addr'

Get help on a specific Qemu monito command (here the info command)::

    $ pcocc monitor-cmd help info
    info balloon  -- show balloon information
    info block [-v] [device] -- show info of one block device or all block devices
    ..
    info version  -- show the version of QEMU
    info vnc  -- show the vnc server status

Run a command::

    $ pcocc monitor-cmd vm0 info version

See also
********

:ref:`pcocc-dump(1)<dump>`
