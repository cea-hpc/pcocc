.. _templates.yaml:

Template configuration file
===========================


Description
***********

:file:`templates.yaml` is a YAML formatted file defining VM templates that can be instantiated with pcocc. This configuration can be read from several locations. System-wide definitions are read from :file:`/etc/pcocc/templates.yaml` while user-specific templates are read from :file:`$HOME/.pcocc/templates.yaml` or from the directory referenced in the environment variable **PCOCC_USER_CONF_DIR** if it is set. A user has access to both his personal templates and the system-wide templates.

Syntax
******

The :file:`templates.yaml` file contains a key/value mapping. Each key represents a template whose parameters are defined in the associated value. The only mandatory parameter is **resource-set**. It can however be inherited from a parent template.

Template parameters
-------------------

**image**
 Path to a directory containing a boot disk image. VMs instantiated from this template will boot from an ephemeral private copy of this image. This location must be available on both front-end and compute nodes. See :ref:`pcocc-newvm-tutorial(7)<newvm>` for importing existing images and :ref:`pcocc-save(1)<save>` for creating new images or revisions from running VMs.
**resource-set**
 Resources to provide to VMs instantiated from this template. This must reference a resource set defined in :ref:`resources.yaml<resources.yaml>`.
**inherits**
 Name of a "parent" template from which to inherit parameters. Parameters defined in the template will override parameters inherited from the parent. User-defined templates can inherit from other user-defined templates or system-wide templates. System-wide templates can only inherit from other system-wide templates.
**description**
 A string describing the VM template. This parameter is not inheritable.
**user-data**
 A cloud-config file to configure a VM image with cloud-init (see :ref:`pcocc-configvm-tutorial(7)<configvm>`)
**instance-id**
 Instance ID to provide to cloud-init (defaults to a randomly generated uuid).
**mount-points**
 A key/value mapping defining directories to export as 9p mount points (see :ref:`pcocc-9pmount-tutorial(7)<configvm>`). Each key defines a 9p mount tag and the associated value defines the directory to export. The following parameters are supported:

  **path**
   The host directory to export.
  **readonly**
   If set to *true* the export will be read-only.

**persistent-drives**
 A list of persistent drives to provide to the VMs. Each element of the list is a single key/value mapping where the key is the path to the VM disk file (in raw format), and the value defines parameters for the drive. VMs have direct access to the source data which means changes are persistent and the template should usually only be instantiated once at a time. When a virtual cluster contains VMs instianciated from templates with persistent drives, pcocc will try to properly shutdown the guest operating when the user relinquishes the resource allocation. For each drive, the following parameters can be configured:

  **cache**
   Qemu cache policy to apply to the drive (defaults to *writeback*)
  **mmp**
   Type of Multi-mount protection to apply to the drive (note that these guarantees do not hold if multiple users try to access the same drive file). The following parameters are available:

   * *yes* (default): Only allow the drive to be attached once.
   * *cluster*: Allow the drive to be attached to multiple VMs of a single cluster.
   * *no*: Disable this feature.

**remote-display**
  A protocol for exporting the graphical console of the VMs. The only supported value is *spice*.
**custom-args**
  A list of arguments to append to the Qemu command line.
**qemu-bin**
  Path to the Qemu binary to use to run the VMs (defaults to searching for qemu-system-x86 in the user's PATH)
**nic-model**
  Model of Qemu virtual Ethernet network card to provide to VMs (defaults to "virtio-net").
**disk-model**
  Model of Qemu virtual drive to provide to VMs. Valid parameters are *virtio* (default) or *ide*.
**emulator-cores**
  Number of cores to reserve for Qemu threads. These cores are deducted from the cores allocated for each VM (defaults to 0).

Sample configuration file
*************************

This is a sample template definition. Please note that indentation is significant in YAML::

    # Define a template named 'example'
    example:
          # Inherit parameters from a parent template (default: no inheritance)
          # inherits: 'parent-example'

          # Resources to allocate (required)
          resource-set: 'cluster'

          # Directory holding the image template for the CoW boot drive (default: no image)
          image: '/path/to/images/myexample'

	  # Model of Qemu virtual drive for the image (default: virtio)
	  disk-model: 'ide'

          # List of additional persistent (non CoW) drives. For templates lacking
          # an image, the first drive will be used as the default boot drive
          persistent-drives:
          # Simple syntax
          - '/path/to/first/drive'
          # Extended syntax with parameters
          - '/path/to/second/drive':
            # Multi-mount protection
            # Valid values:
            #  - yes (default): drive can only be attached once
            #  - cluster: drive can be attached to multiple VMs of a single cluster
            #  - no: disable this feature
            # These guarantees do not apply if multiple users try to attach the
            # same drive
            mmp: 'no'
            # Qemu caching mode (default: 'writeback')
            cache: 'unsafe'

          # Description of this template (default: none)
          description: 'Example of a template'

          # Mount points to expose via virtio-9p (default: none)
          mount-points:
           # 9p mount tag
           homedir:
             # Host path to export
             path: '/home'
             # Set to true for readonly export
             readonly: false

          # Custom arguments to pass to Qemu (default: none)
          custom-args:
            - '-cdrom'
            - '/path/to/my-iso'

          # Qemu executable to use (default: look for qemu-system-x86_64 in user PATH)
          qemu-bin: '/path/to/qemu/bin/qemu-system-x86_64'

          #  Model of Ethernet cards (default: virtio-net)
          nic-model: 'e1000'

          # Reserved cores for Qemu emulation (default: 0)
          emulator-cores: 2

See also
********

:ref:`pcocc-template(1)<template>`, :ref:`pcocc-batch(1)<batch>`, :ref:`pcocc-alloc(1)<alloc>`, :ref:`pcocc-save(1)<save>`, :ref:`pcocc-resources.yaml(5)<resources.yaml>`, :ref:`pcocc-networks.yaml(5)<networks.yaml>`, :ref:`pcocc-newvm-tutorial(7)<newvm>`
