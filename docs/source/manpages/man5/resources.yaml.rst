.. _resources.yaml:

|resources.yaml_title|
======================

Description
***********

:file:`/etc/pcocc/resources.yaml` is a YAML formatted file describing sets of resources that pcocc templates may reference. Currently resource sets are only composed of networks defined in :file:`/etc/pcocc/networks.yaml`.

Syntax
******

:file:`/etc/pcocc/resources.yaml` contains a key/value mapping. Each key represents a set of resources and the associated value contains a unique key, **networks** whose value is a list of networks to provide to VMs. Interfaces will be added to VMs in the same order as they appear in this list, which means that, for example, the first Ethernet network in the list should appear as eth0 in the guest operating system.


Sample configuration file
*************************

This is the default configuration file for reference. Please note that indentation is significant in YAML::

    # This configuration file holds system-wide definitions of set of resources
    # which can be used by VM templates

    default:
      networks:
        - nat-rssh

    ib-cluster:
      networks:
        - nat-rssh
        - ib

See also
********

:ref:`pcocc-template(1)<template>`, :ref:`pcocc-templates.yaml(5)<templates.yaml>`, :ref:`pcocc-networks.yaml(5)<networks.yaml>`, :ref:`pcocc-newvm-tutorial(7)<newvm>`
