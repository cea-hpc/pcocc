.. _reset:

|reset_title|
=============

Synopsis
********

pcocc reset [OPTIONS] [VM]


Description
***********

Reset a VM. The effect is similar to the reset button on a physical machine.

.. note::
    When you reset a VM, it is not returned to it's initial state and modifications to its ephemeral disks are kept. Cloud-init enabled VMs will not replay instantiation-time configuration directives.

Options
*******

    -j, \-\-jobid [INTEGER]
                Jobid of the selected cluster

    -J, \-\-jobname [TEXT]
                Job name of the selected cluster

    -h, \-\-help
                Show this message and exit.

Example
*******

To power cycle vm1::

    pcocc reset vm1

See also
********

:ref:`pcocc-console(1)<console>`, :ref:`pcocc-dump(1)<dump>`
