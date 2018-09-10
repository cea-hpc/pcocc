.. _docker:

|docker_title|
================

Synopsis
********

pcocc docker [COMMAND] [ARG]

Description
***********

pcocc can interact with a docker daemon running inside a virtual machine. To do so, it provides a set of commands which enable seamless interaction from and to docker. In addition, the docker environment enable the reproducible building of images ``docker build`` and the modification of image (``docker run`` followed by ``docker commit``). When pcocc load docker, the user is provided with the docker CLI with **full** functionalities, the only subtlety being that the docker daemon is not local but provisioned in a remote virtual machine.

As a consequence, users willing to use commands which solely begin with docker (without being prefixed by pcocc) should refer to the docker documentation which is available online https://docs.docker.com/.

We will now cover the docker related commands provided by pcocc. Such commands can be gathered in four categories that we are now going to detail.

Sub-Commands
************

Allocate a Docker VM
....................

As docker cannot be considered safe to run natively on an HPC cluster (https://docs.docker.com/engine/security/security/) pcocc allocate a dedicated virtual machine hosting this daemon. This mitigates the security issues with only minor changes in interfaces. As such, pcocc can provide a shell where well known docker commands are fully available, except that they interface with a remote daemon. There are two ways of allocating a docker vm.

   alloc [BATCH OPTIONS]
                Allocate a docker Pod and start a docker shell

   batch [BATCH OPTIONS]
                Allocate a docker VM (but do not start a shell)

   shell [OPTIONS]
                Start a docker shell

   env [OPTIONS]
                Retrieve the docker configuration from pcocc  you can do "eval $(pcocc docker env)" to start a valid docker shell in pcocc

When a shell is allocated it looks as follows:

.. code-block:: bash

    $ pcocc docker alloc -p sandy -c 16

    Starting the docker VM ...
    salloc: Granted job allocation 1756494
    Configuring hosts... (done)
    Waiting for docker VM to start ...

    (pcocc/1756494) johndoe@loginnode:~ $ docker version

    Client: Docker Engine - Community
    Version:           18.09.5
    (...)

    Server:
    Engine:
    Version:          18.06.0-ce
    (...)

After the VM starts, the user is redirected to a shell which is configured such as the local docker command refer to the remote docker-daemon, inside the VM. When leaving the docker shell (exit or CTRL+D, the VM is automatically released).

If we now consider the batch workflow, the shell as to be started manually, for example:

.. code-block:: bash

    $ pcocc docker batch -p sandy -c 16
    # The VM is now starting in the background
    Submitted batch job 1756495

    # We can now manually attach a shell to the corresponding job
    $ pcocc docker shell -j 1756495
    Waiting for docker VM to start ...
    Starting the docker shell ...

    (pcocc/1756495) johndoe@loginnode:~ $ docker version

    Client: Docker Engine - Community
    Version:           18.09.5
    (...)

    Server:
    Engine:
    Version:          18.06.0-ce
    (...)

.. note::
    Notice how the jobid is passed to the docker shell in order to attach to the corresponding VM. Additionally, unlike for ``pcocc docker alloc`` the VM is not stopped when leaving the manually attached shell.

Instead of starting a new shell it is also possible to convert local shell using the ``pcocc docker env`` command, for example:

.. code-block:: bash

    $ pcocc docker batch -p sandy -c 16
    # The VM is now starting in the background
    Submitted batch job 1756495

    # pcocc docker env simply exports docker
    # related configuration
    $ pcocc docker env -j 1756495
    export PATH=XX
    export DOCKER_HOST=tcp://192.168.190.1:60222
    export DOCKER_TLS_VERIFY=1
    export DOCKER_CERT_PATH=~/.pcocc/job_1756496/vmcerts/client

    # It can be sourced in local shell to make docker available
    eval $(pcocc docker env -j 1756495)
    # This done docker can be used
    $ docker version

    Client: Docker Engine - Community
    Version:           18.09.5
    (...)

    Server:
    Engine:
    Version:          18.06.0-ce
    (...)

Exchange Image with Docker
..........................

In order to simplify image exchange with docker pcocc provides some helper commands which are the following:

   export [SRC PCOCC] [DEST DOCKER]
                Send an image from the pcocc repo to the docker daemon

   import [SRC DOCKER] [DEST PCOCC]
                Import an image from docker to the pcocc repo

.. note::
    Unlike ``pcocc image import`` there is no need to provide formats, they are implied by both pccoc and docker default formats.

For example one could send an image from pcocc to docker:

.. code-block:: bash

    # Allocate a docker shell
    $ pcocc docker alloc -p sandy -c 16

    # Export a container image to docker
    $ pcocc docker export cont-busybox bb
    Getting image source signatures
    Copying blob sha256:8e674ad76dcef6f6d0398bc25550f680f8751876064a87a15347f00687492090
    744.86 KB / 744.86 KB [====================================================] 0s
    Copying config sha256:a9388c1d12cd6a964b19120700d167b2008a7b93ba0976de01a0fafe01b91e27
    575 B / 575 B [============================================================] 0s
    Writing manifest to image destination
    Storing signatures

    # List docker images
    $ docker image list
    REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
    bb                  latest              a9388c1d12cd        7 weeks ago         1.22MB

And import it back:

.. code-block:: bash

    $ pcocc docker import bb newbb
    Getting image source signatures
    Copying blob sha256:6194458b07fcf01f1483d96cd6c34302ffff7f382bb151a6d023c4e80ba3050a
    1.37 MB / 1.37 MB [========================================================] 0s
    (...)
    Generating OCI bundle ...

    Listed files for 1 layers
    Maximum layer extraction parallelism is 1
    Extracting layer group 1/1 (archived size 744.857421875 KB) ...
            - layer 0 has been extracted
    Generating squashfs image ...

Modify Images with Docker
.........................

Docker allows container to be modified, unlike regular execution of containers with pcocc. In addition, these modified containers can be transparently imported back to be run outside of docker. The following commands are related to image build and modification:


   edit [SRC IMAGE PCOCC] [DEST IMAGE PCOCC]
                Edit a pcocc image inside docker

   build [PATH TO DOCKERFILE DIR] [DEST IMAGE PCOCC]
                Build a pcocc image inside docker

It is then possible to alter an existing image using docker, note that it is not possible to modify "in-place" and that a new image is to be created. For example:

.. code-block:: bash

    $ pcocc docker edit cont-centos new-centos
    (..)
    ###########################################
    # You are now editing your image          #
    # Hit CTRL + D to save your modifications #
    ###########################################
    $ touch /newfile
    $ exit
    ###########################################
    # Saving modified image ...               #
    ###########################################
    (...)

In previous example the ``centos`` image is modified arbitrarily by the user through the dedicated shell. This, done the modified image is stored as ``new-centos``, this image can the be run normally, for example:

.. code-block:: bash

    $ pcocc run -s --cwd / -I new-centos ls /newfile
    /newfile

Build images with Docker
.........................

As part of container reproducibility, the ability to build a container using a Dockerfile is of interest. Relying on Docker, pcocc is capable of directly building pcocc images trough a single command. Consider the followign Dockefile:

.. code-block:: docker

    from busybox
    CMD ["echo", "Hello Pcocc"]

We simply inherit from a busybox image and set the default command to a welcome print. Building this image with pcocc is trivial:

.. code-block:: bash

    # We consider that our dockerfile is in the ./hello directory
    # the name of the new image is hello
    $ pcocc docker build ./hello hello
    Sending build context to Docker daemon  2.048kB
    Step 1/2 : from busybox
    ---> a9388c1d12cd
    Step 2/2 : CMD ["echo", "Hello Pcocc"]
    ---> Running in 362c79b6eb58
    Removing intermediate container 362c79b6eb58
    ---> 0d41a818c517
    Successfully built 0d41a818c517
    Successfully tagged 289b9950e9064a2b855f56422026625e:latest
    (...)

.. note::
    It is possible to use a pcocc image as FROM import as long as it has been exported to docker using ``pcocc docker export``

This done it is possible to run the container:

.. code-block:: bash

    $ pcocc run -s --cwd / -I hello
    Hello Pcocc

Producing the expected output.

Examples
********

Allocate a docker vm and shell:

.. code-block:: bash

    # All options are passed to slurm
    # -p partition name -c number of cores
    pcocc docker alloc -p sandy -c 16

Export an image to docker and run it:

.. code-block:: bash

    pcocc docker export busybox bb
    docker run -ti --rm bb

Build a dockerfile:

.. code-block:: bash

    pcocc docker build ./mycontdef/ newcontainer

Modify a pcocc container:

.. code-block:: bash

    pcocc docker edit odlcontainer newcontainer


See also
********

:ref:`pcocc-image(1)<image>`, :ref:`pcocc-containers.yaml(5)<containers.yaml>`
