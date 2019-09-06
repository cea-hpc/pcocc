##################################
Installing the python-etcd library
##################################

pcocc uses the python-etcd library, a Python interface to the etcd database.

*************
Build the RPM
*************

The RPM building process is quite straightforward::

    git clone https://github.com/jplana/python-etcd.git
    cd python-etcd
    python setup.py bdist_rpm

Put the resulting packages in your local repositories and install ``python-etcd`` on your front-end and compute nodes or wait for pcocc to pull it as a dependency.
