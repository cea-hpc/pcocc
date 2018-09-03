.. _ps:

|ps_title|
===============

Synopsis
********

pcocc ps [OPTIONS]

Description
***********

List currently running pcocc jobs. By default, only the jobs of the current user are listed. This behaviour can be changed with the *--all* and *--user* options.

Options
*******
  -u \-\-user [TEXT]
            List jobs of the specified user

  -a, \-\-all
            List all pcocc jobs

  -h, \-\-help
            Show this message and exit.

Examples
********

To list the pcocc jobs of the current user

  pcocc ps

