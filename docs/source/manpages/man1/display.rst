.. _display:

|display_title|
===============

Synopsis
********

pcocc display [OPTIONS] [VM]

Description
***********

Display the graphical output of a VM. By default, the *remote-viewer* tool is invoked to display the graphical console of a VM. The *-p* switch can be used to display the content of a *remote-viewer* connection file instead. This allows to launch *remote-viewer* manually.

.. note::
    This requires the VM to have a **remote-display** method defined in it's template (see :ref:`pcocc-templates.yaml(7)<templates.yaml>`)

Options
*******

  -j, \-\-jobid [INTEGER]
            Jobid of the selected cluster

  -J, \-\-jobname [TEXT]
            Job name of the selected cluster

  \-\-user [TEXT]
            Select cluster among jobs of the specified user

  -p, \-\-print_opts
            Print remote-viewer options

  -h, \-\-help
            Show this message and exit.

Examples
********

To display to the graphical console of the first VM::

  pcocc display vm0

See also
********

:ref:`pcocc-ssh(1)<ssh>`, :ref:`pcocc-console(1)<console>`, :ref:`pcocc-template(1)<template>`, :ref:`pcocc-templates.yaml(7)<templates.yaml>`
