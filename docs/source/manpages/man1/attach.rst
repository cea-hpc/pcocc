.. _attach:

|attach_title|
==============

Synopsis
********

pcocc attach [OPTIONS]

Description
***********

Connect to the standard input/output of all running programs.

.. warning::
    This requires the VM to run the *pcoccagent* service

.. note::
    * Hitting *CTRL+D* will close target program standard input (STDIN)
    * Hitting *Escape + Enter* will detach you from programs

Options
*******

    -j, \-\-jobid [INTEGER]
                Jobid of the selected cluster

    -J, \-\-jobname [TEXT]
                Job name of the selected cluster

Examples
********

Attach to running programs::

    pcocc attach

Send EOF to running programs::

    pcocc attach
    /* CTRL+D */

Detach from running programs::

    pcocc attach
    /* Escape + Enter */

See also
********

ssh(1), :ref:`pcocc-scp(1)<scp>`, :ref:`pcocc-console(1)<console>`, :ref:`pcocc-nc(1)<nc>`, :ref:`pcocc-display(1)<display>`, :ref:`pcocc-exec(1)<exec>`, :ref:`pcocc-networks.yaml(5)<networks.yaml>`, :ref:`pcocc-9pmount-tutorial.yaml(7)<9pmount>`
