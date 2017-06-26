.. _console:

|console_title|
===============

Synopsis
********

pcocc console [OPTIONS] [VM]

Description
***********

Connect to a VM console.

.. note::
    In order to leave the interactive console, hit CTRL+C three times.

Options
*******

  -j, \-\-jobid [INTEGER]
            Jobid of the selected cluster

  -J, \-\-jobname [TEXT]
            Job name of the selected cluster

  -l, \-\-log
            Show console log

  -h, \-\-help
            Show this message and exit.

Examples
********

Connect to a VM console
.......................

To connect to vm3 console in the default job::

    pcocc console vm3

* If you log while the VM is booting, you should see the startup messages appear in the interactive console. In this case, wait until the login prompt appears.
* If the VM has already booted, you may need to push enter a few times for the login prompt to appear, as only new console output is displayed.


See the console log
...................

The *-l* flag allows looking at past output::

    pcocc console -l vm0

This produces a paged output of vm0 logs.

.. note::
    When using cloud-init debug information can be found in the console, which allows to check the configuration process.

See also
********

:ref:`pcocc-ssh(1)<ssh>`, :ref:`pcocc-scp(1)<scp>`, :ref:`pcocc-exec(1)<exec>`, :ref:`pcocc-nc(1)<nc>`, :ref:`pcocc-reset(1)<reset>`
