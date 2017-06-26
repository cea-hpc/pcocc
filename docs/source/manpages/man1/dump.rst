.. _dump:

|dump_title|
============

Synopsis
********

pcocc dump [OPTIONS] VM DUMPFILE

Decription
***********

Dump the memory of a VM to a file. The file is saved as ELF and includes the guest's memory mappings. It can be processed with crash or gdb.

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

To dump the memory of the first VM in the :file:`ouptut.bin` file::

    pcocc dump vm1 output.bin

See also
********

:ref:`pcocc-ckpt(1)<ckpt>`, :ref:`pcocc-reset(1)<reset>`
