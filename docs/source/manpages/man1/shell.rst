.. _shell:

|shell_title|
=============

Synopsis
********

pcocc shell [OPTIONS] [login@][vmX]

Description
***********

Connect to a VM and open a shell using the pcoccagent execution capabilities

.. warning::
    This requires the VM to run the *pcoccagent* service

.. note::
    Once in the shell you may hit [CTRL+D] to close the connection

Options
*******

    -s, \-\-shell [SHELL]
                Shell to be used (sh, zsh, bash, ...) (optionnal, has to be installed in the VM)

    [login@]
                Login to be used to login the VM (passwordless)

    [vmX]
                Target VM where X stands for its ID

    -h, \-\-help
                Show this message and exit.

Examples
********

To log in as root to vm0::

    pcocc shell

To log in to vm4 of the default job as *user1*::

    pcocc shell user1@vm4

To login as root to vm3 with zsh::

    pcocc shell -s zsh vm3

It will produce the following output::

    [root@vm3]/# [HIT CTRL+D]
    --- Attach disconnected ---
    --- pcocc exec terminated ---

See also
********

ssh(1), :ref:`pcocc-scp(1)<scp>`, :ref:`pcocc-console(1)<console>`, :ref:`pcocc-nc(1)<nc>`, :ref:`pcocc-display(1)<display>`, :ref:`pcocc-exec(1)<exec>`, :ref:`pcocc-networks.yaml(5)<networks.yaml>`, :ref:`pcocc-9pmount-tutorial.yaml(7)<9pmount>`
