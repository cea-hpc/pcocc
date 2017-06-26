.. _batch.yaml:

|batch.yaml_title|
==================


Description
***********

:file:`/etc/pcocc/batch.yaml` is a YAML formatted file describing how pcocc should interact with the cluster batch environment. At this time pcocc expects a SLURM batch environment along with an etcd key-value store.

Syntax
******
This configuration files contains two keys. The **type** key defines the target batch mangager. Currently the only supported value is *slurm* for the aforementionned environment composed of SLURM and etcd. The **settings** key contains a key/value mapping defining parameters for the target batch manager. The following parameters can be defined:


SLURM settings
--------------
**etcd-servers**
 A list of hostnames of the etcd servers to use for pcocc.
**etcd-ca-cert**
 Path to the etcd CA certificate (required for the "https" etcd-protcol).
**etcd-client-port**
 Port to connect to etcd servers.
**etcd-protocol**
 Protocol used to connect to etcd servers among:

  * *http*:  plain http.
  * *https*: http over secure transport.

**etcd-auth-type**
 Authentication method to access the etcd servers among:

  * *password* use password authentication (recommended)
  * *none* do not use authentication


Sample configuration file
*************************

This is the default configuration file for reference. Please note that indentation is significant YAML::

    # Batch manager
    type: slurm
    settings:
         # List of etcd servers
         etcd-servers:
             - etcd1
             - etcd2
             - etcd3
         # CA certificate
         etcd-ca-cert: /etc/etcd/etcd-ca.crt
         # Client port
         etcd-client-port: 2379
         # Protocol
         etcd-protocol: http
         etcd-auth-type: password
