pcocc
=========

Pcocc (pronounced like "peacock") stands for Private Cloud On a Compute
Cluster. It allows users of a HPC cluster to host their own clusters of VMs on
compute nodes alongside regular jobs. This allows users to fully customize their
software environments for development, testing or facilitating application
deployment. Compute nodes remain managed by the batch scheduler as usual, since
the clusters of VMs are seen as regular jobs. For each virtual cluster, pcocc
allocates the necessary ressources to host the virtual machines, including
private ethernet and/or infiniband networks, creates temporary disk images from
the selected templates (using CoW) and instantiates the requested VMs.

Requirements
-------------

Pcocc main requirements are:

* SLURM >= 2.4
* slurm-spank-plugins
* etcd >= 2.2
* openvswitch >= 1.11
* Qemu >= 1.6

For Infiniband:

* Mellanox adapters supporting SRIOV
* Linux kernel with VFIO support

Pcocc makes a few assumptions about the configuration of the host clusters such as:

* users have home directories shared between submit and compute nodes
* users may ssh to allocated compute nodes without a password (using GSSAPI or pubkey athentication for example)
* slurm manages task affinity and memory allocation

Installation
------------

See the installation documentation in the `docs` directory

    $ make -C docs html

Status
-------

Pcocc is under development, and may not be suitable for production use. Its
command line interface and configuration files syntax are not considered stable
and may change in future releases.

Website
-------

Find the latest source at:

https://github.com/cea-hpc/pcocc
