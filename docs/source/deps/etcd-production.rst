############################
Deploy a secure etcd cluster
############################
.. _etcd-production:

This guide explains how to setup a cluster of highly available etcd servers and to secure communications with TLS. This guide is adapted from the `official etcd documentation <https://coreos.com/os/docs/latest/>`_ in which you can find more detailed information.

**********************
Certificate Generation
**********************

To enable TLS you need to generate a self-signed certificate authority and server certificates. In this example, we will consider using the following nodes as a etcd servers.

+----------+----------------------------+----------------------+
| Hostname | FQDN                       | IP                   |
+==========+============================+======================+
|node1     | node1.mydomain.com         | 10.19.213.101        |
+----------+----------------------------+----------------------+
|node2     | node2.mydomain.com         | 10.19.213.102        |
+----------+----------------------------+----------------------+
|node3     | node3.mydomain.com         | 10.19.213.103        |
+----------+----------------------------+----------------------+

.. note::
    For high-availability it is best to use an odd number of servers. Adding more servers increases high-availability and can improve read performance but decrease write performance. It is recommendend to use 3, 5 or 7 servers.

To generate the CA and server certificates, we use Cloudflare's cfssl as suggested in the official documentation. It can be installed very easily as follows::

    mkdir ~/bin
    curl -s -L -o ~/bin/cfssl https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
    curl -s -L -o ~/bin/cfssljson https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
    chmod +x ~/bin/{cfssl,cfssljson}
    export PATH=$PATH:~/bin

Create a directory to hold your certificates and private keys. You may need them in the future if you need to generate more certificates so please make sure to keep them in a secure location with restrictive access permissions::

    mkdir ~/etcd-ca
    cd ~/etcd-ca

Generate the CA certificate::

    echo '{"CN":"CA","key":{"algo":"rsa","size":2048}}' | cfssl gencert -initca - | cfssljson -bare ca -
    echo '{"signing":{"default":{"expiry":"43800h","usages":["signing","key encipherment","server auth","client auth"]}}}' > ca-config.json

For each etcd server, generate a certificate as follows::

    export NAME=node1
    export ADDRESS=10.19.213.101,$NAME.mydomain.com,$NAME
    echo '{"CN":"'$NAME'","hosts":[""],"key":{"algo":"rsa","size":2048}}' | cfssl gencert -config=ca-config.json -ca=ca.pem -ca-key=ca-key.pem -hostname="$ADDRESS" - | cfssljson -bare $NAME

.. note::
   If your servers will be reached from other IPs or DNS aliases, make sure to reference them in the **ADDRESS** variable


You now have to deploy the generated keys and certificates in the :file:`/etc/etcd/` directory of each server node. For example for node1::

   scp ca.pem root@node1:/etc/etcd/etcd-ca.crt
   scp node1.pem root@node1:/etc/etcd/server.crt
   scp node1-key.pem root@node1:/etc/etcd/server.key
   ssh root@node1 chmod 600 /etc/etcd/server.key

.. note::
   The CA certificate ca.pem will later have to deployed on all nodes hosting pcocc (front-end and compute nodes). Make sure you keep a backup along with the whole etcd-ca directory.

******************
etcd Configuration
******************

etcd needs to be configured on each server node in the /etc/etcd/etcd.conf configuration file. Here is an example for node1::

    ETCD_NAME=node1
    ETCD_LISTEN_PEER_URLS="https://10.19.213.101:2380"
    ETCD_LISTEN_CLIENT_URLS="https://10.19.213.101:2379"
    ETCD_INITIAL_CLUSTER_TOKEN="pcocc-etcd-cluster"
    ETCD_INITIAL_CLUSTER="node1=https://node1.mydomain.com:2380,node2=https://node2.mydomain.com:2380,node3=https://node3.mydomain.com:2380"
    ETCD_INITIAL_ADVERTISE_PEER_URLS="https://node1.mydomain.com:2380"
    ETCD_ADVERTISE_CLIENT_URLS="https://node1.mydomain.com:2379"
    ETCD_TRUSTED_CA_FILE=/etc/etcd/etcd-ca.crt
    ETCD_CERT_FILE="/etc/etcd/server.crt"
    ETCD_KEY_FILE="/etc/etcd/server.key"
    ETCD_PEER_CLIENT_CERT_AUTH=true
    ETCD_PEER_TRUSTED_CA_FILE=/etc/etcd/etcd-ca.crt
    ETCD_PEER_KEY_FILE=/etc/etcd/server.key
    ETCD_PEER_CERT_FILE=/etc/etcd/server.crt

.. note::
    **ETCD_NAME**, **ETCD_ADVERTISE_CLIENT_URLS**, **ETCD_INITIAL_ADVERTISE_PEER_URLS**, **ETCD_LISTEN_PEER_URLS** and **ETCD_LISTEN_CLIENT_URLS** have to be adapted for each server node.

Finally, you may enable and start the service on all etcd nodes::

    systemctl enable etcd
    systemctl start etcd

*****************
Check etcd Status
*****************

To check if your etcd server is running correctly you may do::

    $ etcdctl --endpoints=https://node1.mydomain.com:2379 --ca-file=~/etcd-ca/ca.pem member list
    6c86f26914e6ace, started, Node2, https://node3.mydomain.com:2380, https://node3.mydomain.com:2379
    1ca80865c0583c45, started, Node1, https://node2.mydomain.com:2380, https://node2.mydomain.com:2379
    99c7caa3f8dfeb70, started, Node0, https://node1.mydomain.com:2380, https://node1.mydomain.com:2379

************************
Configure etcd for pcocc
************************

Before enabling authentication, configure a ``root`` user in etcd::

    etcdctl --endpoints="https://node1.mydomain.com:2379" --ca-file=~/etcd-ca/ca.pem  user add root

.. warning::
    Choose a secure password. You'll have to reference it in the pcocc configuration files.

Enable authentication::

    etcdctl --endpoints="https://node1.mydomain.com:2379" --ca-file=~/etcd-ca/ca.pem auth enable

Remove the guest role::

    $ etcdctl --endpoints="https://node1.mydomain.com:2379" --ca-file=~/etcd-ca/ca.pem -u root:<password> role remove guest
    Role guest removed

You should no longer be able to access the keystore without authentication::

    $ etcdctl --endpoints "https://node1.mydomain.com:2379" --ca-file=~/etcd-ca/ca.pem  get /
    Error:  110: The request requires user authentication (Insufficient credentials) [0]
