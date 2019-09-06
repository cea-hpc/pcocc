####################################
Installing the grpc python libraries
####################################

pcocc uses the python-grpcio library, a Python interface for the gRPC framework.

**************
Build the RPMs
**************

The required RPMs can be built using pyp2rpm.

You can install this tool on a build node using pip::

    pip install --upgrade pyp2rpm

You may have to also upgrade setuptools via pip if it complains.

Generate RPMs for python-protobuf::

    install pyp2rpm on a build node with pip
    pyp2rpm -t epel7 -b 2 -p 2 protobuf -v 3.6.0 -s

The generated specfile :file:`$HOME/rpmbuild/SPECS/python-protobuf.spec` may need to be edited. Under the `%files section` add if needed::

    %{python2_sitelib}/%{pypi_name}-%{version}-py%{python2_version}-nspkg.pth

Build the RPMs::

    rpmbuild -ba $HOME/rpmbuild/SPECS/python-protobuf.spec

Generate and build RPMs for grpcio and grpcio_tools::

     pyp2rpm -t epel7 -b 2 -p 2 grpcio -v 1.13.0 -s
     rpmbuild -ba $HOME/rpmbuild/SPECS/python-grpcio.spec
     pyp2rpm -t epel7 -b 2 -p 2 grpcio_tools -v 1.13.0 -s
     rpmbuild -ba $HOME/rpmbuild/SPECS/python-grpcio_tools.spec

Put the resulting packages in your local repositories and install them on your front-end and compute nodes or wait for pcocc to pull them as a dependency.
