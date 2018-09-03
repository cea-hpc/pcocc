.. _template:

|template_title|
================

Synopsis
********

pcocc template [COMMAND] [ARG]

Description
***********

List and manage virtual machine templates.

Sub-Commands
************

   list
                Display a list of all templates (system-wide and user-defined)

   show [tpl]
                Show a detailed description of the template named *tpl*

Examples
********

To list available templates::

    pcocc template list

This produces an output similar to::

    NAME            DESCRIPTION                  RESOURCES    IMAGE
    ----            -----------                  ---------    -----
    mydebian        My custom Debian VM          cluster      /vms/debian9-cloud
    centos7-cloud   Cloud-init enabled CentOS 7  cluster      /vms/centos7-cloud
    debian9-cloud   Cloud-init enabled Debian 9  cluster      /vms/debian9-ci

To get detailed information relative to a template::

    pcocc template show mydebian

It produces an output such as::

    ATTRIBUTE         INHERITED    VALUE
    ---------         ---------    -----
    inherits          No           debian9-ci
    user-data         No           ~/conf
    image             Yes          /vms/debian9-ci
    resource-set      Yes          cluster
    image-revision    No           0 (Sun Jul  9 22:58:41 2017)

See also
********

:ref:`pcocc-image(1)<image>`, :ref:`pcocc-templates.yaml(5)<templates.yaml>`, :ref:`pcocc-resources.yaml(5)<resources.yaml>`
