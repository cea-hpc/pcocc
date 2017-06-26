##################################
Installing the python-etcd library
##################################

pcocc uses the python-etcd library, a Python interface to the etcd database.

*************
Build the RPM
*************

The RPM building process is quite straightforward::

    wget https://github.com/jplana/python-etcd/archive/0.4.4.tar.gz
    tar xvzf 0.4.4.tar.gz
    cd python-etcd-0.4.4
    python setup.py bdist_rpm

Put the resulting packages in your local repositories and install python-etcd on your front-end and compute nodes or wait for pcocc to pull it as a dependency.
