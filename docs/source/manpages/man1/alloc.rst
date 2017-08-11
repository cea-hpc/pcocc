.. _alloc:

|alloc_title|
=============

Synopsis
********

pcocc alloc [OPTIONS] [BATCH_OPTIONS]... CLUSTER_DEFINITION

Descrition
***********

Instantiate or restore a virtual cluster in interactive mode. A cluster definition is expressed as a list of templates and counts. For example, pcocc alloc *tpl1:6,tpl2:2* instantiates a cluster with 6 VMs from template *tpl1* and 2 VMs from template *tpl2*.

By default, an interactive shell is launched which allows to easily interact with the virtual cluster as all pcocc commands launched from the shell implicitly target the related virtual cluster. Resources are relinquished when either the VMs are powered off or the interactive shell exits (see below). Any data stored on ephemeral disks is lost after the allocation completes.

Batch options are passed on to the underlying batch manager (see salloc(1)). By default allocations are created with the name *pcocc* unless specified otherwise in the batch options. From outside the interactive shell, pcocc commands look for a job named *pcocc* and will target it if there is only one match. Otherwise, the id or name of the allocation hosting the cluster must be specified.

Instead of launching an interactive shell, it is possible to execute a script on the front-end node with the *-E* option. The cluster will be terminated once the script exits. As in the in interactive shell, pcocc commands launched within the script implicitely target the current cluster.

Options
*******

  -r, \-\-restart-ckpt [DIR]
            Restart cluster from the specified checkpoint

  -E, \-\-alloc-script [SCRIPT]
            Execute a script on the allocation node

  -h, \-\-help
            Show this message and exit.

Examples
********

Instanciate a new virtual cluster
.................................

To allocate eight VMs with four cores each with the *test* SLURM qos, six from template *tpl1* and two from *tpl2*::

    pcocc alloc -c 4 --qos=test -J ubuntu tpl1:6,tpl2:2

Restore a checkpointed cluster
..............................

The :ref:`pcocc-ckpt(1)<ckpt>` command allows to save the state of a whole cluster (disks and memory) in a checkpoint. Assuming a cluster was submitted and checkpointed as follows::

    pcocc alloc -c 8 myubuntu:3
    pcocc ckpt ./savedalloc

To restore it from the checkpoint in interactive mode::

    pcocc alloc -c 8 -r $PWD/savedalloc myubuntu:3

.. warning::
    * Make sure that the parameters in the restore command (core count, template types, ...) are the same that were used when the cluster was first allocated. The cluster also has to be restored on the same model of physical nodes as when it was first allocated.
    * The restore path must be an absolute path


See also
********

:ref:`pcocc-batch(1)<batch>`, :ref:`pcocc-ckpt(1)<ckpt>`, :ref:`pcocc-template(1)<template>`, :ref:`pcocc-templates.yaml(5)<templates.yaml>`
