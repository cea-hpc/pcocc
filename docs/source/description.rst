Introduction
************

pcocc (pronounced like "peacock") stands for Private Cloud On a Compute Cluster. It allows users of an HPC cluster to host their own clusters of VMs on compute nodes, alongside regular jobs. Users are thus able to fully customize their software environments for development, testing, or facilitating application deployment. Compute nodes remain managed by the batch scheduler as usual since the clusters of VMs are seen as regular jobs. For each virtual cluster, pcocc allocates the necessary resources to host the VMs, including private Ethernet and/or Infiniband networks, creates temporary disk images from the selected templates and instantiates the requested VMs.

Working principle
*****************

pcocc leverages SLURM to start, stop and supervise virtual clusters in the same way as regular parallel jobs. It allocates CPU and memory resources using sbatch/salloc and a SLURM plugin allows to setup virtual networks on the allocated nodes. Once the nodes are allocated and configured, VMs are launched by SLURM as any other task with the rights of the invoking user. VMs are configured to replicate, as much as possible, the resources and capabilities of the portion of the underlying host that is allocated for them (CPU model and core count, memory amount and NUMA topology, CPU and memory binding...) so as to maximize performance.

To launch a virtual cluster, the user selects a template from which to instantiate its VMs and the number of requested VMs (it is possible to combine several templates among a cluster). A template defines, among other things, the base image disk to use, the virtual networks to setup, and optional parameters such as host directories to export to the VMs via 9p. Administrators can define system-wide templates from which users can inherit to define their own templates. When a VM is instantiated from a template, an ephemeral disk image is built from the reference image using copy-on-write. By default, any changes made to the VMs' disks are therefore lost once the virtual cluster stops but it is possible to save these changes to create new revisions of the templates.
