.. _run:

|run_title|
============

Synopsis
********

pcocc run [OPTIONS] [CMD]...

Description
***********

Execute a command in a VM or container. If executed within the context of a virtual cluster (in an allocation shell or by specifying the  *-j* or *-J*) option, the command is executed within VMs of the cluster. This requires the pcocc guest agent to be installed in the VMs. Otherwise, the command is run on compute nodes through the batch manager. The *-I* option then allows to specify a container image that will be used for running the task.

Container images
****************

Container images are mounted read-only. A tmpfs is mounted on the user's home directory, unless a host directory is already bind-mounted on this PATH with the **--mount** command line option or with an option set in `containers.yaml`.

User
****

Tasks are executed as the current user by default. When running tasks within a VM this can be overriden with the **--user** option.

Environment variables
*********************

Local environment variables are not propagated to the launched tasks by default. When using a container image, default environment variables are set from the source image and from configurations defined in `containers.yaml`. These variables can be overriden with the **--env** option described below which take arguments of the form:

   - VAR[=VALUE]: if VALUE is specified, set the task environment VAR to VALUE, otherwise, propagate VAR from the host

   - re([REGEX]): propagate all environment variables matching REGEX

The **--mirror-env** option allows to propagate all environment variables.

Working directory
*****************

If a working directory is defined in the image it is used by default. Otherwise, the current working directory is propagated. This behaviour can be overriden with the **--cwd** option.

Modules
*******

Modules allow to import sets of environment variables and bind-mounts defined in `containers.yaml`. The list of modules used when running a container image can be specified with the **-M** option.


Options
*******

Options:

    -j, \-\-jobid [INTEGER]
                Jobid of the selected cluster

    -J, \-\-jobname [JOBNAME]
                Job name of the selected cluster

    -u, \-\-user [USER]
                User id to use to execute the command

    \-w \-\-nodelist [NODESET]
                Nodeset on which to run the command

    \-I \-\-image [IMAGE]
                Spawn a container to run the command

    \-\-mirror\-env
                Propagate all local environment variables

    \-\-cwd [PATH]
                Work directory for the target executable

    \-\-no\-defaults
                Do not apply default container configuration

    \-\-no\-user
                Do not inject the user inside the container or VM

    \-e \-\-env [ENVSPEC]
                Environment variables to propagate

    \-\-path\-prefix [VARIABLE]=[VALUE]
                Prepend VALUE to a PATH type VARIABLE

    \-\-path\-suffix [VARIABLE]=[VALUE]
                Append VALUE to a PATH type VARIABLE

    \-\-mount [SRC[:DST]]
                Mount a host directory in the container

    \-M \-\-module [MODULE]
                Container configuration modules to apply

    \-\-entry\-point [CMD]
                Override entry point of a Docker container

    \-n \-\-process [INTEGER]
                 Number of processes to launch in parallel

    \-c \-\-core [INTEGER]
                Number of cores to allocate per process

    \-N \-\-node [INTEGER]
                Number of nodes to allocate in total

    \-s \-\-singleton
                Run a single task locally

    \-p \-\-partition [PARTIION]
                Partition on which to run

    \-\-script [PATH]
                Execute a script stored on the host

Examples
********

Execute a command
.................

To run fives tasks as root in 2 VMs::

    pcocc run -n 5 -N 2 --user root hostname

To run a task in a container image on the local node::

    pcocc run -sI ubuntu cat /etc/os-relase

To run a container on a remote node using the nvidia module::

    pcocc run -I tensorflow --pty -M nvidia -n 1 -c 5 -p gpu

See also
********

:ref:`pcocc-ssh(1)<ssh>`, :ref:`pcocc-scp(1)<scp>`, :ref:`pcocc-console(1)<console>`, :ref:`pcocc-nc(1)<nc>`
