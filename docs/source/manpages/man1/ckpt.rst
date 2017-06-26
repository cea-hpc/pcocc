.. _ckpt:

|ckpt_title|
============

Synopsis
********

pcocc ckpt [OPTIONS] CKPT_DIR

Description
***********

Checkpoint the current state of a cluster. Both the disk image and memory of all VMs of the cluster are saved and the cluster is terminated. It is then possible to restart from this state using the \-\-restart-ckpt option of the alloc and batch commands.

CKPT_DIR should not already exist unless -F is specified. In that case, make sure you're not overwriting the checkpoint from which the cluster was restarted.

.. warning::
    Qemu does not support checkpointing all types of virtual devices. In particular, it is not possible to checkpoint a VM with 9p exports mounted or attached to host devices such as an Infiniband virtual function.


Options
*******
    -j, \-\-jobid [INTEGER]
            Jobid of the selected cluster

    -J, \-\-jobname [TEXT]
                Job name of the selected cluster

    -F, \-\-force
                Overwrite directory if exists

    -h, \-\-help
                Show this message and exit.

Example
*******

To checkpoint the cluster with jobid 256841 in the :file:`$HOME/ckpt1/` directory::

    pcocc ckpt -j 256841 $HOME/ckpt1/

This produces a disk and a memory image for each VM::

    ls ./ckpt1/
    disk-vm0  disk-vm1  memory-vm0  memory-vm1

To restore a virtual cluster, see :ref:`pcocc-alloc(1)<alloc>` or :ref:`pcocc-batch(1)<batch>`.

See also
********

:ref:`pcocc-alloc(1)<alloc>`, :ref:`pcocc-batch(1)<batch>`, :ref:`pcocc-dump(1)<dump>`
