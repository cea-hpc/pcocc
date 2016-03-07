Introduction
============
Pcocc (pronounced like "peacock") stands for Private Cloud On a Compute Cluster. It allows users of a HPC cluster to host their own clusters of VMs on compute nodes, alongside regular jobs. This allows users to fully customize their software environments for development, testing, or facilitating application deployment. Compute nodes remain managed by the batch scheduler as usual, since the clusters of VMs are seen as regular jobs. For each virtual cluster, pcocc allocates the necessary resources to host the virtual machines, including private Ethernet and/or Infiniband networks, creates temporary disk images from the selected templates (using CoW) and instantiates the requested VMs.

Requirements
-------------

Pcocc main requirements are:

* SLURM >= 2.4
* slurm-spank-plugins
* etcd >= 2.2
* openvswitch >= 1.11
* Qemu >= 1.6

For virtual Infiniband networks:

* Mellanox adapters and drivers supporting SRIOV
* Linux kernel with VFIO support

Pcocc makes a few assumptions about the configuration of the host clusters such as:

* users have home directories shared between submit and compute nodes
* users may ssh to allocated compute nodes without a password (using GSSAPI or pubkey athentication for example)
* SLURM manages task affinity and memory allocation

Pcocc has mostly been tested on RHEL7 based distributions.

Working principles
------------------

Pcocc leverages SLURM to start, stop and supervise virtual clusters in the same way as regular parallel jobs. It allocates CPU and memory resources using sbatch/salloc and a SLURM plugin allows to setup virtual networks on the allocated nodes. Once the nodes are allocated and configured, VMs are launched by SLURM as any other task with the rights of the invoking user. VMs are configured to replicate, as much as possible, the resources and capabilites of the portion of the underlying host that is allocated for them (CPU model and core count, memory amount and NUMA topology, VCPU and virtual memory binding...) so as to maximise performance.

To launch a virtual cluster, the user selects a template from which to instanciate its VMs and the number of requested VMs (it is possible to combine several templates among a cluster). A template defines, among other things, the base image disk to use, the virtual networks to setup, and optional parameters such as host directories to export to the VMs via 9P. Administrators can define global templates from which users can inherit to define their own templates. When a VM is instanciated from a template, an ephemeral disk image is built from the reference image using Copy-On-Write. By default, any change made to the VMs disk is therefore lost once the virtual cluster stops but it is possible to save these changes to create new revisions of the templates.
