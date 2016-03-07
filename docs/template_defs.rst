Template definitions
====================
Templates can be defined globally in ``/etc/pcocc/templates.yaml`` and for each user in ``~/.pcocc/templates.yaml``.
The following example describes the available parameters:

.. code-block:: yaml
  :caption: ~/.pcocc/templates.yaml

  # Define a template named 'example'
  example:
    # Inherit parameters from a parent template (default: no inheritance)
    # inherits: 'parent-example'

    # Resources to allocate (required)
    resource-set: 'cluster'

    # Directory holding the image template for the CoW boot drive (default: no image)
    image: '/path/to/images/myexample'

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
      mmp: no
      # Qemu caching mode (default: 'writeback')
      cache: 'unsafe'

    # Description of this template (default: none)
    description: 'Example of a template'

    # Mount points to expose via virtio-9p (default: none)
    mount-points:
     # 9P mount tag
     homedir:
       # Host path to export
       path: '/home'
       # Set to true for readonly export
       readonly: false

    # Custom arguments to pass to Qemu (default: none)
    custom-args:
      - '-cdrom'
      - '/path/to/my-iso'

    # Qemu executable to use (default: look for qemu-system-x86_64 in standard PATH)
    qemu-bin: '/path/to/qemu/bin/qemu-system-x86_64'

    #  Model of Ethernet cards (default: virtio-net)
    nic-model: 'e1000'

    # Reserved cores for Qemu emulation (default: 0)
    emulator-cores: 2

Image and mount paths can reference environment variables using the *%{env:ENV_VAR_NAME}* syntax
