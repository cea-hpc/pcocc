.. _batch:

|batch_title|
=============


Synopsis
********

pcocc batch [OPTIONS] [BATCH_OPTIONS]... CLUSTER_DEFINITION

Description
***********

Instantiate or restore a virtual cluster in batch mode. A cluster definition is expressed as a list of templates and counts e.g.: pcocc batch tpl1:6,tpl2:2 instantiates a cluster with 6 VMs from template tpl1 and 2 VMs from template tpl2

Batch options are passed on to the underlying batch manager.

By default batch jobs are submitted with the name *pcocc* unless specified otherwise in the batch options

pcocc commands which target a virtual cluster look for a job named *pcocc* and will select it if there is only one match. Otherwise, the id or name of the batch job hosting the cluster must be specified.

Options
*******

    -r, \-\-restart-ckpt [DIR]
              Restart cluster from the specified checkpoint

    -b, \-\-batch-script [FILENAME]
              Launch a batch script in the first VM

    -E, \-\-host-script [FILENAME]
              Launch a batch script on the first host

    -h, \-\-help
              Show this message and exit.

Examples
********

Instanciate a new virtual cluster
.................................

For example to allocate eight VMs with four cores each with the *ubuntu* job name, six from template *tpl1* and two from *tpl2*::

    pcocc batch -J ubuntu -c 4 tpl1:6,tpl2:2

Restore a checkpointed cluster
..............................

The :ref:`pcocc-ckpt(1)<ckpt>` command allows to save the state of a whole cluster (disks and memory) in a checkpoint. Assuming a cluster was submitted and checkpointed as follows::

    $ pcocc batch -c 8 myubuntu:3
    Submitted batch job 311244
    $ pcocc ckpt -j 311244 ./savedbatch

To restore it from the checkpoint in batch mode::

    pcocc batch -c 8 -r $PWD/savedbatch myubuntu:3


.. warning::
    * Make sure that the parameters in the restore command (core count, template types, ...) are the same that were used when the cluster was first submitted. The cluster also has to be restored on the same model of physical nodes as when it was first submitted.
    * The restore path must be an absolute path


See also
********

:ref:`pcocc-alloc(1)<alloc>`, :ref:`pcocc-ckpt(1)<ckpt>`, :ref:`pcocc-template(1)<template>`, :ref:`pcocc-templates.yaml(5)<templates.yaml>`
