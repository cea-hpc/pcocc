pcocc
=====

pcocc (pronounced like "peacock") stands for Private Cloud On a Compute Cluster. It allows users of an HPC cluster to host their own clusters of VMs on compute nodes, alongside regular jobs. Users are thus able to fully customize their software environments for development, testing, or facilitating application deployment. Compute nodes remain managed by the batch scheduler as usual since the clusters of VMs are seen as regular jobs. For each virtual cluster, pcocc allocates the necessary resources to host the VMs, including private Ethernet and/or Infiniband networks, creates temporary disk images from the selected templates and instantiates the requested VMs.

Requirements and dependencies
-----------------------------

pcocc makes use of several external components or services among which:

* A Slurm cluster with the Lua SPANK plugin
* Open vSwitch
* An etcd database and the etcd python bindings
* Qemu and KVM

Documentation
-------------

https://pcocc.readthedocs.io/en/latest/

Website
-------

Find the latest source at:

https://github.com/cea-hpc/pcocc
