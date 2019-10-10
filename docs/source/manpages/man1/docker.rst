.. _docker:

|docker_title|
==============

Synopsis
********

pcocc docker [COMMAND] [ARG]

Description
***********

Use a docker daemon running in a VM

The *pcocc docker* subcommands allow to provision a remote docker daemon running in a VM managed by pcocc and to use it as if it was running on a local node.



Allocate a Docker VM
....................

*pcocc docker alloc* and *pcocc docker batch* allow to allocate Docker VMs. Their behaviour mirror the :ref:`pcocc-alloc(1)<alloc>` and :ref:`pcocc-batch(1)<batch>` commands. Batch options are transferred to the batch manager so as to select, for example, a partition or a core count for the VM.

In interactive mode (*pcocc docker alloc*), an interactive shell is launched where environment variables are defined to tell clients of the Docker API to target the remote virtualized daemon. The *docker* CLI or other tools such as *docker-compose* can then be used as if the daemon was running locally. Once the interactive shell exits, the Docker VM is terminated.

Instead of starting an interactive shell, a script can be executed on the front-end node using the *-E* option. The same environment variables will be set for remote Docker access, and the VM is terminated once the script exits.

*pcocc docker batch* provides the same functionnality in batch mode instead of interactive mode.

*pcocc docker shell* and *pcocc docker env* allow to set the environment variables required to communicate with the remote Docker daemon in other shells or tasks.


   alloc [-E script] [BATCH OPTIONS]
                Allocate a docker Pod and start a docker shell

   batch [-E script] [BATCH OPTIONS]
                Allocate a docker VM (but do not start a shell)

   shell [-j JOBID] [-J jobname] [-E script] [-T timeout]
                Start a docker shell

   env [-j JOBID] [-J jobname]

Container image management
..........................

*pcocc docker import* imports an image from a pcocc repository to the Docker daemon container storage, while *pcocc docker export* exports an image from the Docker daemon container storage to a pcocc repository.

*pcocc docker build* creates a new image in a pcocc repository from a Dockerfile. The Dockerfile image is first built by the Docker daemon before being transferred to the pcocc repository.

   import SRC DEST
                Import an image from a pcocc repository

   export SRC DEST
                Export an image to a pcocc repository

   build PATH DEST
                Build a pcocc image from a Dockerfile

Examples
********

Allocate a Docker VM and start an interactive shell:

.. code-block:: bash

    pcocc docker alloc -c 16

Build an image from a Dockerfile:

.. code-block:: bash

    pcocc docker build . newcontainer

Import an image from a pcocc repository and run it with Docker:

.. code-block:: bash

    pcocc docker import busybox busybox
    docker run -ti --rm busybox

See also
********

:ref:`pcocc-image(1)<image>`, :ref:`pcocc-run(1)<run>`
