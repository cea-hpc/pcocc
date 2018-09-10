.. _run:

|run_title|
============

Synopsis
********

pcocc run [OPTIONS] [CMD]...

Decription
**********

Run commands in various configurations supported by pcocc. This includes:

    - Running locally (singleton mode)
    - Running inside a slurm allocation
    - Running inside a container
    - Running in a virtual machine
    - Running inside a container running in a virtual machine (POD)

In the rest of this documentation we will first present common options before
moving on to specificities linked with some configurations such as containers.
Eventually, we will recall how parameters and current environment affects "where"
the command is launched according to the previously listed configurations.

.. note::
    Configurations involving a VM suppose that you correctly configured
    the pcocc agent inside your image.

Configuration Matrix
********************

The *pcocc run* command is versatile the following table presents the resulting
configuration in function of both flags and current environment.

The following flags play a role:


    -s, \-\-singleton
                Run without batch manager or VM support

    -I, \-\-image [TEXT]
                Container image to launch


===========  ===========  ================================  ===========================================
Singleton    Image        No allocation                     Inside a pcocc allocation
===========  ===========  ================================  ===========================================
N            N            Allocate with Slurm               Run inside the VM
Y            N            Run locally                       Run locally
N            Y            Container on Slurm                Container inside VM
Y            Y                 Run container locally             Run container locally
===========  ===========  ================================  ===========================================

.. note::
    When running over Slurm ressources and inside VMs, the *resource set* flags are considered
    (see below) when running as a singleton, only a single process is started per invocation.

Options
*******

Common Options
--------------

    -h, \-\-help
                Show this message and exit.

    -t, \-\-tty
                Wether to launch in a TTY (forces n=1)

    -s, \-\-singleton
                Run without batch manager or VM support

    -I, \-\-image [TEXT]
                Container image to launch

Pcocc Allocation Options
------------------------

    -j, \-\-jobid [INTEGER]
                Jobid of the selected cluster when reffering to a pcocc allocation

    -J, \-\-jobname [TEXT]
                Job name of the selected cluster

.. note::
    These parameters can be used to define the target allocation (pcocc alloc)

Resource Set
------------

Supported options to define ressources on which to run are the following:

    -N, \-\-node [INTEGER]
                Number of nodes to launch on

    -n, \-\-process [INTEGER]
                Number of process to launch

    -c, \-\-core [INTEGER]
                Number of core(s) per process

    -p, \-\-partition [TEXT]
                Partition on which to run (only when allocating)

    -w, \-\-nodelist [TEXT]
                Nodelist on which to run (only when allocating)

.. note::
    These parameters are not meaningful in singleton mode.

Environment Control
-------------------

.. _environment_control:

By default commands run with *pcocc run* do not propagate the local environment it is therefore possible to manually specify what is to be propagated using the following flags.

    -m, \-\-mirror-env
                Propagate local environment variables (default False)

    -e, \-\-env [TEXT]
                Environment variables passed to the target program (see syntax below)

    -P, --path-prefix [TEXT]
                Prepend variables in $PATH fashion (see syntax below)

    -S, --path-suffix [TEXT]
                Append variables in $PATH fashion (see syntax below)

The following syntax is supported for environment variables:

=================  =============================================================
Syntax             Description
=================  =============================================================
VAR=VALUE          Set variable 'VAR' to value 'VALUE'
VAR                Set variable 'VAR' to current env value
re(REGEXPR)        Propagate all variables matching REGEXPR regular expression
                   **only** valid for environment variable and not path manipulation
=================  =============================================================

To better illustrate supported syntax, consider the following environment between a container and the host system:

=================  ================  ===========================================
Variable           Host System       Container
=================  ================  ===========================================
PATH               /usr/hostpath/    /sbin
PREFIX             host_prefix       container_prefix
=================  ================  ===========================================

We can now illustrate the effect of the previous flags as follows, presenting the resulting PATH variable in function of the passed flags.

.. note::
    In the following table we consider each flag independently, it is of course
    possible to combine multiple flags in practice.

=================  ===========================  ================================
Flag               PATH in target environment   PREFIX in target environment
=================  ===========================  ================================
-m                 /usr/hostpath/               host_prefix
-e PATH=/sbin      /sbin                        container_prefix
-e PATH            /usr/hostpath/               container_prefix
-P PATH            /usr/hostpath/:/sbin         container_prefix
-S PATH            /sbin:/usr/hostpath/         container_prefix
-P PATH=/foobar    /foobar:/sbin                container_prefix
-S PATH=/foobar    /sbin:/foobar                container_prefix
-e PREFIX          /sbin                        host_prefix
-e re(P.*)         /usr/hostpath/               host_prefix
-P PREFIX=/test    /sbin                        /test:container_prefix
-P PREFIX          /sbin                        host_prefix:container_prefix
-S PREFIX          /sbin                        container_prefix:host_prefix
=================  ===========================  ================================

Process Configuration
---------------------

These parameters affect how the target process is run.

    -u, \-\-user [TEXT]
                Username to run the command

.. warning::
    Running as another user is only possible inside virtual machines.
..

    \-\-script [TEXT]
                Script to run (substitutes the command)

    \-\-cwd [TEXT]
                    Work directory for the target executable, If not set
                    host PWD is propagated. If the container defines a
                    workdir different than "/" this value supersedes the
                    transparent propagation. In order to use the
                    container default you can specify "-"

.. warning::
    There are cases where the current working directory (CWD) is not present in the container. As pcocc tries to mirror current CWD in the container it may lead to errors such as ``bwrap: Can't chdir to /XXX: No such file or directory``. In this case the solution is simply to specify manually a cwd, for example ``--cwd /``.

.. _pcocc_run_module:

Container Related Options
-------------------------
.. note::
    The following options are only meaningful for containers i.e. for commands
    involving the *\-\-image* flag.
..

    -v, \-\-mount [TEXT]
                Mount a directory in target env (vm or cont) format
                src=/XX,dest=/XX,type=XX,opt=A,B=X,C or src:dest

    -M, \-\-module [TEXT]
                Define a list of module configuration to inject in
                the container/VM (can be comma separated list)

    -E, \-\-entry-point [TEXT]
                Changes container entry point (in docker semantics)

    \-\-no-defaults
                Do not apply the default container configuration.
                See :ref:`container templates<container_templates>`.

    \-\-no-user
                Do not inject the user inside the container

For example, to bind mount *a.out* as */test* in the container::

    -v ./a.out:/test
    -v src=./a.out,dest=/test

Examples
********

Execute a command
-----------------

Run a container on the local node using a TTY and default command::

    pcocc run -s --image centos -t

Run a container on the local node using a TTY and '/bin/sh'::

    pcocc run -s --image centos -t /bin/sh

Allocate ressources to run 24 instances of the container on the *compute* partition::

    pcocc run -p compute -n 24 --image centos

See also
********

:ref:`pcocc-containers(5)<containers.yaml>`, :ref:`pcocc-docker(1)<docker>`
