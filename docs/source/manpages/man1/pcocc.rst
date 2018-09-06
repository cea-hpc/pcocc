.. _pcocc_usage:

|pcocc_title|
=============

.. include:: ../../description.rst

List of help topics
*******************

This documentation is organized into help topics which are listed in the following sections. These topics include tutorials to help you get started, individual pcocc sub-commands to manage and interact with virtual clusters and configuration files.

You may get further information on each of these topics listed below by doing:

    pcocc help [*TOPIC*]

For example to open the newvm tutorial:

    pcocc help newvm-tutorial

To example read help about the ssh sub-command:

    pcocc help ssh

For installing pcocc on a cluster, have a look at the :ref:`installation guide <installation_guide>`. [#f1]_

Sub-Commands
------------

pcocc supports the following sub-commands:

 * Define and Allocate VMs:

    :ref:`alloc<alloc>`
      |alloc_title|
    :ref:`batch<batch>`
      |batch_title|
    :ref:`template<template>`
      |template_title|
    :ref:`image<image>`
      |image_title|

 * Connect to VMs:

    :ref:`console<console>`
      |console_title|
    :ref:`nc<nc>`
      |nc_title|
    :ref:`scp<scp>`
      |scp_title|
    :ref:`ssh<ssh>`
      |ssh_title|
    :ref:`exec<exec>`
      |exec_title|
    :ref:`display<display>`
      |display_title|

 * Manage running VMs:

    :ref:`reset<reset>`
      |reset_title|
    :ref:`ckpt<ckpt>`
      |ckpt_title|
    :ref:`dump<dump>`
      |dump_title|
    :ref:`monitor-cmd<monitor-cmd>`
      |monitor-cmd_title|
    :ref:`save<save>`
      |save_title|
    :ref:`ps<ps>`
      |ps_title|

Tutorials
---------

:ref:`newvm-tutorial <newvm>`
 |newvm-tutorial_title|
:ref:`cloudconfig-tutorial <configvm>`
 |cloudconfig-tutorial_title|
:ref:`9pmount-tutorial <9pmount>`
 |9pmount-tutorial_title|


Configuration Files
-------------------

:ref:`batch.yaml<batch.yaml>`
 |batch.yaml_title|
:ref:`networks.yaml<networks.yaml>`
 |networks.yaml_title|
:ref:`resources.yaml<resources.yaml>`
 |resources.yaml_title|
:ref:`repos.yaml<repos.yaml>`
 |repos.yaml_title|
:ref:`templates.yaml<templates.yaml>`
 |templates.yaml_title|

See also
--------

:ref:`pcocc-alloc(1)<alloc>`, :ref:`pcocc-batch(1)<batch>`, :ref:`pcocc-ckpt(1)<ckpt>`, :ref:`pcocc-console(1)<console>`, :ref:`pcocc-display(1)<display>`, :ref:`pcocc-dump(1)<dump>`, :ref:`pcocc-exec(1)<exec>`, :ref:`pcocc-monitor-cmd(1)<monitor-cmd>`, :ref:`pcocc-image(1)<image>`,:ref:`pcocc-nc(1)<nc>`, :ref:`pcocc-reset(1)<reset>`, :ref:`pcocc-save(1)<save>`, :ref:`pcocc-scp(1)<scp>`, :ref:`pcocc-ssh(1)<ssh>`, :ref:`pcocc-template(1)<template>`, :ref:`pcocc-batch.yaml(5)<batch.yaml>`, :ref:`pcocc-networks.yaml(5)<networks.yaml>`, :ref:`pcocc-resources.yaml(5)<resources.yaml>`, :ref:`pcocc-repos.yaml(5)<repos.yaml>`, :ref:`pcocc-templates.yaml(5)<templates.yaml>`, :ref:`pcocc-9pmount-tutorial(7)<9pmount>`, :ref:`pcocc-cloudconfig-tutorial(7)<configvm>`, :ref:`pcocc-newvm-tutorial(7)<newvm>`

.. rubric:: Footnotes

.. [#f1] Local installation guide: /usr/share/doc/pcocc-|release|/install.html
