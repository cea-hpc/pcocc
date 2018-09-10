.. _containers.yaml:

|containers.yaml_title|
=======================

Description
***********

:file:`containers.yaml` is a YAML formatted file defining container templates that can be instantiated with pcocc. This configuration can be read from several locations. System-wide definitions are read from :file:`/etc/pcocc/containers.yaml` while user-specific templates are read from :file:`$HOME/.pcocc/containers.yaml`. A user has access to both his personal templates and the system-wide templates.

.. note::
   The location of user configuration files, by default :file:`$HOME/.pcocc` can be changed to another directory by setting the  **PCOCC_USER_CONF_DIR** environment variable.

Syntax
******

The :file:`containers.yaml` contains three main key/value mappings defining the following elements:
  * ``containers`` define container templates (somehow similar to VM templates)
  * ``modules`` define additionnal modules to be applied to templates
  * ``config`` defines global configuration parameters relative to containers

We are now going to describe each of these turn by turn.

.. _container_templates:

Containers Templates
--------------------

Elements in this section are relative to the ``containers`` entry of :file:`containers.yaml`. It may contains configuration targetting containers by name. Each configuration is a key/value entry which key is the name of the image. In addition, a ``default`` template is applied to all containers. Leading to the following initial layout :

.. code-block:: yaml

    containers:
      # Applies to all containers (by default)
      default:
        env:
          - DEFAULT_VARIABLE=1
      # Will only apply to the 'busybox' container
      busybox:
        env:
          - BUSYBOX_VARIABLE=2

In previous configuration, a container which name is ``busybox`` should have the two templates trigerred, busybox *and* default. If the default configuration is to be disabled the ``--no-defaults`` option of ``pcocc run`` can be used. In addition, any other container lets say ``centos`` would have a single environment variable from default.

Container templates support multi-inheritance, it means that common configurations can be regrouped for convenience in a single arbitrary group. Consider the following file:

.. code-block:: yaml

    containers:
      my_conf:
        env:
          - DEFAULT_VARIABLE=1

      busybox:
        inherits:
          - my_conf

      centos:
        inherits:
          - my_conf

With previous configuration, both ``centos`` and ``busybox`` should have the parameters from ``my_conf``, in this example an environment variable ``DEFAULT_VARIABLE`` with a value of ``1``. Note that multi-inheritance (one to N, and transitive) is supported as long as it does not create dependency loops. Each entry is called a *container template* and it gathers the following parameters:

**inherits**
 (array of strings), for example, ``["centos", "myconf"]``

 Define a list of templates to by applied to the current template. A given template may inherit one or several templates either transitively or directly. Note that dependency loops are forbidded and lead to a configuration error. Inherited templates are merged in reverse order of resolution (depth first search), parent templates being applied before the intial template.

.. _cont_temp_env:

**env**
 (array of strings), for example, ``["AA=8", "PATH", "re(OMPI.*)"]``

 Insert environment variables in the target container. Either by directly reading the environment, using a variable name or a regular expresion, or by passing ``KEY=VALUE`` to progagate explicitly a given variable. This can be done using the following syntax:

 =================  =================================================================
 Syntax             Description
 =================  =================================================================
 VAR=VALUE          Set variable 'VAR' to value 'VALUE'
 VAR                Set variable 'VAR' to current env value
 re(REGEXPR)        Propagate all variables matching REGEXPR regular expression
 =================  =================================================================

.. _cont_temp_pp:

**pathprefix**
 (array of strings), for example, ``["PATH=/mybin", "LD_LIBRARY_PATH"]``

 Prefix a PATH-like variable in the target container, concatenating with ":". If only the variable name is provided, for example ``PATH`` it means that host ``PATH`` (as retrived from current environment) will be prefixed to the container default ``PATH``. Otherwise, if a value is provided, it will be added to the target variable. For example, ``LD_LIBRARY_PATH=/mylib/`` adds ``/mylib`` at the beginning of the ``LD_LIBRARY_PATH`` inside the container. See the :ref:`pcocc-run(1)<environment_control>` command for some example relative to prefixing.

 .. note::
   Regular expression such as ``re(OMPI.*)`` are not supported (unlike in env). The same variable can be prefixed several times, for example to add various directories. Internally, pcocc uses ":" to concatenate paths as conventionally done in UNIX systems.

.. _cont_temp_ps:

**pathsuffix**
 (array of strings), for example, ``["PATH=/mybin", "LD_LIBRARY_PATH"]``

 This has the same behavior than ``pathprefix`` except that it appends (instead of prefixing) to the given variables. See the :ref:`pcocc-run(1)<environment_control>` command for some example relative to suffixing.

**mounts**
 (key/values), for example ``rootfs: {"source":"/", "destination":"/rootfs"}``

  This is a key/value defining mountpoints inside the container according to the OCI mountpoint specifications https://github.com/opencontainers/runtime-spec/blob/master/config.md#mounts. The souce is the only required field, if the other entries are not defined, it defaults to same destination and type is set to rbind in read-write.

  Each mount is defined as follows:

  **source**
   (string)
   The host path to export.
  **destination**
   (string)
   Path of where to export in the containers
  **type**
   (string)
   Type of mount for example ``rbind``
  **options**
   (array of strings)
   Options to be passed to mount (for example ``["ro"]``).

  For example if you want to define two mounts:

  .. code-block:: yaml

    containers:
      my_conf:
        mounts:
            # Mounts /compute at /compute in container
            # Mount is rbind in read-write
            compute:
                source: /compute/
            # Mount /data at /rodata in read-only
            data:
                source: /data/
                destination: /rodata/
                options:
                    - ro

**ns**
  (array of strings), for example ``["mount", "uts"]``

  This is the list of namespaces to be enabled inside the containers.

  The following namespaces are defined (following Linux namespaces):

    * *uts* : Hostname and NIS domain name namespaces
    * *pid* : Process IDs namespaces
    * *ipc* : System V IPC, POSIX message queues namespace
    * *mount* : Mount points namespace
    * *network* : Network namespace

  See ``man namespaces`` for more details.

 .. note::
    Some program may not operate correctly if you isolate your container too much, for example MPI generally operates with only the ``mount`` namespace as it requires IPC and Network access. A recommended default is ``["mount", "uts"]``

**hooks**
  (key/value) example ``{"prestart":{"path": "/usr/bin/myhook"}``

  This entry defines the OCI hooks as implemented in the OCI standard https://github.com/opencontainers/runtime-spec/blob/master/config.md#posix-platform-hooks.

  .. note::
    OCI hooks can be enabled using the configuration see :ref:`enable_oci_hooks<enableocihooks>`.

  Such hooks are run at various steps of the container execution, including:

    * *prestart*: just before the container runs
    * *poststart*: just after the container started
    * *poststop*: just after the container stopped

  Each hook is a key/value entry in a list indexed by one of the aforementionned key. (See the example below).

  Each hook is defined as follows (only ``path`` is required):

    **path**
    (string), for example ``/bin/hook``

    The absolulte path of the command to be run

    **args**
    (array of strings), for example ``["-t", "-u"]``

    Arguments to be passed to the ``path`` program.

    **env**
    (array of strings), for example ``["MYVAR=8"]``

    List of environment variables to be passed to the command.

    **timeout**
    (integer), for exampe ``25``

    Max execution time in seconds for the hook


  The following example illustrates the use of hooks:

  .. code-block:: yaml

    containers:
      my_conf:
        hooks:
            prestart:
                - path: /bin/echo
                  args: "prestart1"
                - path: /bin/echo
                  args: "prestart2"
            poststart:
                - path: /bin/echo
                  args: "poststart"
            poststop:
                - path: /bin/container_stopped
                  args: "-u"
                  env:
                    - STOPPED_CONT=1
                  timeout: 32

**generator**
    (array of strings), for example ``["gen_mounts -t", "inject_my_home"]``

    Use a command to generate mounts dynamically for this configuration. Parameters are parsed from the standard output of the called program with the following syntax:

    =================  =================================================================
    Keyworkd           Description
    =================  =================================================================
    ENV                Export an environment variable (same as :ref:`env<cont_temp_env>`:)
    PATHPREFIX         Prefix an environment variable (same as :ref:`pathprefix<cont_temp_pp>`)
    PATHSUFFIX         Suffix an environment variable (same as :ref:`pathsuffix<cont_temp_ps>`)
    MOUNT              src[:target] mount a path in a container with an optionnal target
    MODULE             Link to a runtime module (see :ref:`runtime templates<runtime_templates>`)
    =================  =================================================================

    .. warning::
        Pcocc will append two parameters to the generator command:

          * the path to the config.json for this container
          * the path to the rootfs of the container

        Such as for example ``mygenerator -t 'genmounts'`` is invoked as:
        ``mygenerator -t 'genmounts' /tmp/xxxx/config.json /tmp/xxxx/rootfs/``

    Sample generator definition:

    .. code-block:: yaml

        containers:
            generator:
                # Will invoke the command and parse its output
                - "mygenerator -t 'genmounts'"
                - "mygenerator -t 'genenv'"

    Sample generator output::

        # Export MYVAR
        ENV MYVAR
        # Mount /mydata to /contdata
        MOUNT /mydata:/contdata
        # Mount /compute to /compute
        MOUNT /compute
        # Add /compute/lib in LD_LIBRARY_PATH
        PATHPREFIX LD_LIBRARY_PATH=/compute/lib/
        # Activate the MPI module
        MODULE mpi

.. _runtime_templates:

Runtime Templates
--------------------


Elements in this section are relative to the ``modules`` entry of :file:`containers.yaml`. Such configurations are strictly identical in structure to the ones of :ref:`container templates<container_templates>`, they only differ in the way they are applied to the container. Indeed, unlike container configurations which are applied by name, these configurations can be enabled through the :ref:`module<pcocc_run_module>` command switch of the run command. This allows a more dynamic configuration of a given run on a per-invocation basis, instead of on a per-image one. Conside the following configuration:

.. code-block:: yaml

    modules:
        hydro:
            generator:
                - "injecthydro"
        exporta:
            env:
                - A=1337

Here we defined two configurations, ``hydro`` and ``exporta``. Note that such configurations also support inheritance. These templates can then be applied by two means:

    * Passing the :ref:`-M/--module<pcocc_run_module>` flag to the :ref:`pcocc-run(1)<run>` command.
    * Using the *MODULE* command from generators in templates

For example to invoke the ``centos`` container using these templates:

.. code-block:: bash

    # Pass each template turn by turn
    pcocc run -I centos -M hydro -M exporta
    # Use comma separated lists
    pcocc run -I centos -M hydro,exporta

Container Config
----------------

Elements in this section are relative to the ``config`` entry of :file:`containers.yaml`.
It may contains the following *optionnal* entries:

**docker_path**
 (string), for example, ``"/opt/docker"``

 A path to the docker command line tools installation on the system. Note that Docker is available in the form of static binaries here : https://download.docker.com/linux/static/stable/. One may download and deploy these binaries on the system before pointing ``docker_path`` to the corresponding path to sucessfully install docker tools for pcocc as far as the client-side aspects are concerned.

**docker_pod**
 (string), for example, ``"docker-pod"``

 Name of the VM template to use as docker pod when allocating docker vms with ``pcocc docker alloc``. This VM should host the pcocc agent and a docker daemon.

**docker_mounts**
 (array of strings), for example, ``["/compute", "/userhomes"]``

 A list of docker mounts to make visible to the docker daemon running inside the virtual machine. Due to implementation constraints some paths cannot be added as they are already present in the target file-system.

.. _enableocihooks:

**enable_oci_hooks**
 (boolean), for example, ``True``

 Whether OCI hooks should be enabled in pcocc as defined in the OCI specifications : https://github.com/opencontainers/runtime-spec/blob/master/config.md#posix-platform-hooks. This setting defaults to ``True``.

**use_squashfs**
 (boolean), for example, ``True``

 Enable squashfs support in pcocc, avoiding full image extraction in the file-system. Note that not enabling this feature impact on features, it provides performance gains when manipulating images (importing, deleting, ...). This setting defaults to ``False``.

 .. warning::
    In order to enable squashfs you need to provide dependencies on the system. In particular ``squashfs-tools`` and ``squashfuse`` which is used to mount images.

**container_tmp_path**
 (string), for example, ``/dev/shm``

 Where to temporarily extract container images. ``/dev/shm`` is generally the fastest, however it can have limited ressources. It is therefore possible to change this parameter. By default, pcocc will use ``/dev/shm``. Note that when needed one can temporarilly change this setting using an environment variable ``PCOCC_CONT_TMP_DIR``.

**container_tmp_path_trsh_mb**
 (integer), for example, ``100``

 The maximum size of images to extract inside the *container_tmp_path* directory in mega-bytes. Note that this size is measured on **compressed** object prior to decompressing, it therefore should be conservative. Default is ``100`` MB. Note that when the compressed object is larger pcocc will rely on the standard temporary directory, usually ``/tmp``.

**squashfs_image_mountpoints**
 (advanced)
 (array of strings), for example, ``["/compute/", "/userhomes/"]``

 A list of paths to be inserted in the squashfs images to optimize launch time. Indeed, as squashfs images are read-only, pcocc relies on a "reverse mount" technique which is less optimal when iserting mounts in populated directories. Pre-creating directories which are known to exist enables potential optimization a launch time.

 .. note::
    If the path ends with a "/" it creates a directory, otherwise it create an empty file.

**docker_test_path**
 (advanced)
 A path to a docker-related path *inside* the docker_pod vm to watch for docker strartup.

**docker_use_ip_address**
 (advanced)
 Instruct pcocc not to use domain names to contact the docker enabled VM but instead to rely on IP adresses.


Sample configuration file
*************************

This is a sample template definition. Please note that indentation is significant in YAML:

.. code-block:: yaml

    config:
        # Path to a docker-cli as imported for example from static
        # binaries https://download.docker.com/linux/static/stable/
        docker_path: /opt/docker-cli/
        # If the connection to Docker should us an IP instead of a hostname
        docker_use_ip_address: true
        # Name of the docker VM pod image
        docker_pod: docker-pod
        # List of mountpoints to expose inside the Docker environment
        # they SHOULD not conflict with existing directories or files
        docker_mounts:
            # A mountpoint is {src: XX, dest: XX} and dest can
            # be ommited it then implies src=dest
            - src: /usr/
              dest: /test/usr
            - src: /mydir
        # Define if pcocc has to interpret OCI hooks in container configuration files
        # see https://github.com/opencontainers/runtime-spec/blob/master/config.md#posix-platform-hooks
        enable_oci_hooks: false
        # Define if pcocc has to use squashfs images or rootfs images
        use_squashfs: true
        # Some files are known to be systematically mounted in containers
        # in order to speedup launch time it is possible to pre-populate them
        # when generating the squashfs images. In this case, empty files / dirs
        # are created, avoiding possibly expensive mounts later on
        # NOTE : if the path ends with a "/" it will create a directory
        squashfs_image_mountpoints:
            - "/ect/passwd"
            - "/etc/resolv.conf"
            # - "/sharedworkspace/"
        # Where to temporarilly extract container images
        # this value can be overriden manually with the "PCOCC_CONT_TMP_DIR"
        # environment variable
        container_tmp_path: /dev/shm
        # What is the maximum **estimated** size in MB of a container using *container_tmp_path*
        # if the container to be extracted is larger it will head to /tmp
        # as the exact size cannot be known before actually extracting the image prefer
        # conservative values
        container_tmp_path_trsh_mb: 100


    # Per container environment (when being run by pcocc)
    containers:
        # The "default" key applies to all containers
        example:
          mounts: # What is mounted inside the container
              example: # Follows OCI mountpoint semantics
                source: "/example"
                destination: "/example"
                type: "bind"
          ns: # Which namespaces to activate
              - "uts"
              - "mount"
          env:
              - EXPORT_THIS_VARIABLE=1
              - PWD
          hooks:
              # OCI hooks
              # see https://github.com/opencontainers/runtime-spec/blob/master/config.md#posix-platform-hooks
              prestart:
                  # Before starting the command
                  - path: /usr/bin/ls
                    env:
                        - AA=8
                        - BB=azery
                    args:
                        - -la
                    timeout: 120
              #poststart:
                  # Same layout
              #poststop:
                  # Same layout

    # Configuration for modules (-M flag of pcocc run)
    # content is similar to container config and overlap
    # with the initial container config except that inheritance is supported
    # -M flags can be put multiple times or comma separated
    # for example -M nvidia,pmi is equivalent to -M nvidia -M pmi
    modules:
        pmienv:
            # What is needed to inject the host PMI from SLURM
            env:
                - 're(SLURM*)'
                - 're(PMI*)'
            mounts:
                libpmi2:
                    source: /usr/lib64/libpmi2.so.0
                    destination: /pcocc/lib/pmi/libpmi2.so.0
                libpmi:
                    source: /usr/lib64/libpmi.so.0
                    destination: /pcocc/lib/pmi/libpmi.so.0
                libslurm:
                    source: /usr/lib64/libslurm.so.32
                    destination: /pcocc/lib/pmi/libslurm.so.32
            pathprefix:
                - LD_LIBRARY_PATH=/pcocc/lib/pmi/

        verbs:
            # What is needed to inject host IB configuration
            mounts:
                verbsconfdir:
                    source: "/etc/libibverbs.d"
                verbs_rdmacm:
                    source: "/usr/lib64/librdmacm.so.1.0.0"
                    destination: "/pcocc/lib/verbs/librdmacm.so.1"
                verbs_mlx5:
                    source: "/usr/lib64/libmlx5.so.1.0.0"
                    destination: "/pcocc/lib/verbs/libmlx5-rdmav2.so"
                verbs_mlx4:
                    source: "/usr/lib64/libmlx4-rdmav2.so"
                    destination: "/pcocc/lib/verbs/libmlx4-rdmav2.so"
                verbs:
                    source: "/usr/lib64/libibverbs.so.1.0.0"
                    destination: "/pcocc/lib/verbs/libibverbs.so.1"
                libnl:
                    # This is a dependency lib to IBVERBS
                    source: "/lib64/libnl.so.1"
                    destination: "/pcocc/lib/verbs/libnl.so.1"
                devices:
                    source: /dev/infiniband/
                    options: ["dev"]
            pathprefix:
                - LD_LIBRARY_PATH=/pcocc/lib/verbs/

        pmi:
            inherits:
                - "pmienv"
                - "verbs"
            env:
                - "OMPI_MCA_btl_openib_allow_ib=1"

    #
    # In this last example we present command-based configurations
    #
    # pcocc can process the output of a program to generate a configuration
    # on the fly with a line-based syntax:
    #
    # MOUNT [SRC](:[DEST])
    # ENV [VAR] or [VAR=B] or re(XX.*)
    # PATHPREFIX [VAR] or [VAR=X]
    # PATHSUFFIX [VAR] or [VAR=X]
    # MODULE [MOD]
    #
    # Each command is passed the following extra arguments:
    # [PATH TO config.json] [PATH to rootfs]
    #
        nvidia:
            generator:
                - nvidia_container_list


See also
********

:ref:`pcocc-run(1)<run>`, :ref:`pcocc-template(1)<template>`, :ref:`pcocc-image(1)<image>`, :ref:`pcocc-batch(1)<batch>`, :ref:`pcocc-alloc(1)<alloc>`, :ref:`pcocc-save(1)<save>`, :ref:`pcocc-resources.yaml(5)<resources.yaml>`, :ref:`pcocc-networks.yaml(5)<networks.yaml>`, :ref:`pcocc-newvm-tutorial(7)<newvm>`
