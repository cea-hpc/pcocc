import pytest
import os
import subprocess
import re

import pcocc
from pcocc.Networks import VNetworkConfig
from pcocc.Templates import TemplateConfig
from pcocc.Resources  import ResSetConfig


def sproc_init(*args, **kwargs):
    if args[0][0] == 'iptables' and '-C' in args[0]:
        raise subprocess.CalledProcessError(-1, args[0], '')
    else:
        return True

def sproc_cleanup(*args, **kwargs):
        return True

def test_init_ethnetwork(mocker, config, datadir):
    config.vnets = VNetworkConfig()
    config.rsets = ResSetConfig()
    config.tpls = TemplateConfig()

    config.vnets.load(str(datadir.join('networks_l3.yaml')))
    config.rsets.load(str(datadir.join('resources.yaml')))

    check_call = mocker.patch('subprocess.check_call')
    mocker.patch('subprocess.check_output', new=check_call)

    check_call.side_effect = sproc_init
    config.vnets['eth_l3'].init_node()

    check_call.side_effect = sproc_cleanup
    config.vnets['eth_l3'].cleanup_node()

    cmdline=""
    for name, args, kwargs in check_call.mock_calls:
        if isinstance(args[0], str):
            cmdline += args[0] + '\n'
        else:
            cmdline += ' '.join(args[0]) + '\n'

    print cmdline
    assert cmdline == """ovs-vsctl --may-exist add-br nat_xbr
ovs-ofctl del-flows -OOpenFlow13 nat_xbr --strict priority=0
ovs-vsctl set bridge nat_xbr other-config:hwaddr=52:54:00:ff:ff:ff
ip link set nat_xbr up
ip addr add 10.250.255.254/16 dev nat_xbr
ovs-ofctl add-flow -OOpenFlow13 nat_xbr priority=1000,dl_type=0x0806,actions=goto_table=50
ovs-ofctl add-flow -OOpenFlow13 nat_xbr priority=1000,dl_src=52:54:00:ff:ff:ff,actions=goto_table=20
ovs-ofctl add-flow -OOpenFlow13 nat_xbr priority=0,actions=goto_table=30
ovs-ofctl add-flow -OOpenFlow13 nat_xbr table=30,priority=1000,dl_dst=52:54:00:ff:ff:ff,actions=output:LOCAL
ovs-ofctl add-flow -OOpenFlow13 nat_xbr table=50,priority=1000,dl_type=0x0806, nw_dst=10.250.255.254,actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[], mod_dl_src:52:54:00:ff:ff:ff, load:0x2->NXM_OF_ARP_OP[], move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[], move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[], load:0x525400ffffff->NXM_NX_ARP_SHA[], load:0xafafffe->NXM_OF_ARP_SPA[], in_port
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -P FORWARD DROP
iptables -C FORWARD -d 10.250.0.0/16 -o nat_xbr -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -d 10.250.0.0/16 -o nat_xbr -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -C OUTPUT -d 10.250.0.0/16 -o nat_xbr -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -d 10.250.0.0/16 -o nat_xbr -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -C FORWARD -d 10.250.0.0/16 -o nat_xbr -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
iptables -A FORWARD -d 10.250.0.0/16 -o nat_xbr -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
iptables -C OUTPUT -d 10.250.0.0/16 -o nat_xbr -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
iptables -A OUTPUT -d 10.250.0.0/16 -o nat_xbr -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
iptables -C OUTPUT -d 10.250.0.0/16 -o nat_xbr -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -d 10.250.0.0/16 -o nat_xbr -p icmp --icmp-type echo-request -j ACCEPT
iptables -C OUTPUT -d 10.250.0.0/16 -o nat_xbr -j DROP
iptables -A OUTPUT -d 10.250.0.0/16 -o nat_xbr -j DROP
iptables -C FORWARD -s 10.250.0.0/16 -i nat_xbr -j ACCEPT
iptables -A FORWARD -s 10.250.0.0/16 -i nat_xbr -j ACCEPT
iptables -t nat -C POSTROUTING -s 10.250.0.0/16 ! -d 10.250.0.0/16 -p tcp -j MASQUERADE --to-ports 1024-65535
iptables -t nat -A POSTROUTING -s 10.250.0.0/16 ! -d 10.250.0.0/16 -p tcp -j MASQUERADE --to-ports 1024-65535
iptables -t nat -C POSTROUTING -s 10.250.0.0/16 ! -d 10.250.0.0/16 -p udp -j MASQUERADE --to-ports 1024-65535
iptables -t nat -A POSTROUTING -s 10.250.0.0/16 ! -d 10.250.0.0/16 -p udp -j MASQUERADE --to-ports 1024-65535
iptables -t nat -C POSTROUTING -s 10.250.0.0/16 ! -d 10.250.0.0/16 -p icmp --icmp-type echo-request -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.250.0.0/16 ! -d 10.250.0.0/16 -p icmp --icmp-type echo-request -j MASQUERADE
ovs-vsctl --if-exist del-br nat_xbr
echo 0 > /proc/sys/net/ipv4/ip_forward
iptables -P FORWARD ACCEPT
iptables -C FORWARD -d 10.250.0.0/16 -o nat_xbr -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -D FORWARD -d 10.250.0.0/16 -o nat_xbr -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -C OUTPUT -d 10.250.0.0/16 -o nat_xbr -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -D OUTPUT -d 10.250.0.0/16 -o nat_xbr -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -C FORWARD -d 10.250.0.0/16 -o nat_xbr -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
iptables -D FORWARD -d 10.250.0.0/16 -o nat_xbr -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
iptables -C OUTPUT -d 10.250.0.0/16 -o nat_xbr -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
iptables -D OUTPUT -d 10.250.0.0/16 -o nat_xbr -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
iptables -C OUTPUT -d 10.250.0.0/16 -o nat_xbr -p icmp --icmp-type echo-request -j ACCEPT
iptables -D OUTPUT -d 10.250.0.0/16 -o nat_xbr -p icmp --icmp-type echo-request -j ACCEPT
iptables -C OUTPUT -d 10.250.0.0/16 -o nat_xbr -j DROP
iptables -D OUTPUT -d 10.250.0.0/16 -o nat_xbr -j DROP
iptables -C FORWARD -s 10.250.0.0/16 -i nat_xbr -j ACCEPT
iptables -D FORWARD -s 10.250.0.0/16 -i nat_xbr -j ACCEPT
iptables -t nat -C POSTROUTING -s 10.250.0.0/16 ! -d 10.250.0.0/16 -p tcp -j MASQUERADE --to-ports 1024-65535
iptables -t nat -D POSTROUTING -s 10.250.0.0/16 ! -d 10.250.0.0/16 -p tcp -j MASQUERADE --to-ports 1024-65535
iptables -t nat -C POSTROUTING -s 10.250.0.0/16 ! -d 10.250.0.0/16 -p udp -j MASQUERADE --to-ports 1024-65535
iptables -t nat -D POSTROUTING -s 10.250.0.0/16 ! -d 10.250.0.0/16 -p udp -j MASQUERADE --to-ports 1024-65535
iptables -t nat -C POSTROUTING -s 10.250.0.0/16 ! -d 10.250.0.0/16 -p icmp --icmp-type echo-request -j MASQUERADE
iptables -t nat -D POSTROUTING -s 10.250.0.0/16 ! -d 10.250.0.0/16 -p icmp --icmp-type echo-request -j MASQUERADE
"""

def test_alloc_ethnetwork(mocker, config, datadir):
    config.batch.batchid = 100
    config.batch.list_all_jobs.return_value = [100]

    config.vnets = VNetworkConfig()
    config.rsets = ResSetConfig()
    config.tpls = TemplateConfig()

    config.vnets.load(str(datadir.join('networks_l3.yaml')))
    config.rsets.load(str(datadir.join('resources.yaml')))
    config.tpls.load(str(datadir.join('templates.yaml')))
    config.tracker = pcocc.NetUtils.Tracker(str(datadir.join('tracker.db')))

    cluster = pcocc.Cluster('test_l3:4', resource_only=True)

    check_call = mocker.patch('subprocess.check_call')
    mocker.patch('subprocess.check_output', new=check_call)
    check_call.side_effect = sproc_init

    mocker.patch('pcocc.NetUtils.OVSBridge.get_port_id').side_effect = xrange(0,10)
    mocker.patch('pcocc.NetUtils.NetDev._find_used_dev_ids').side_effect = [xrange(0,i) for i in xrange(0,10)]

    config.batch.get_host_rank.return_value = 0
    config.batch.node_rank = 0

    config.vnets['eth_l3'].alloc_node_resources(cluster)
    config.vnets['eth_l3'].free_node_resources(cluster)
    config.tracker.cleanup_ref(config.batch.batchid)

    cmdline=""
    for name, args, kwargs in check_call.mock_calls:
        if isinstance(args[0], str):
            cmdline += args[0] + '\n'
        else:
            cmdline += ' '.join(args[0]) + '\n'

    assert re.sub(r'/tmp/\w+', '/tmp/XXXXX', cmdline) == re.sub(r'/tmp/\w+', '/tmp/XXXXX',
"""ovs-vsctl --may-exist add-br nat_ibr0
ovs-ofctl del-flows -OOpenFlow13 nat_ibr0 --strict priority=0
ip link set nat_ibr0 mtu 1500
ip link set nat_ibr0 up
ip link add nat_veth1 type veth peer name nat_veth1b
ovs-vsctl --may-exist add-port nat_ibr0 nat_veth1
ovs-vsctl --may-exist add-port nat_xbr nat_veth1b
ip link set nat_veth1 up
ip link set nat_veth1b up
ip link set nat_veth1 mtu 1500
ip link set nat_veth1b mtu 1500
ip netns add nat_ns_eth_l3_100
ip link add nat_veth2 type veth peer name nat_veth2b
ip link set nat_veth2 up
ovs-vsctl --may-exist add-port nat_ibr0 nat_veth2
ip link set nat_veth2b address 52:54:00:ff:ff:fd
ip link set nat_veth2b netns nat_ns_eth_l3_100
ip netns exec nat_ns_eth_l3_100 ip link set nat_veth2b up
ip netns exec nat_ns_eth_l3_100 ip addr add 10.251.255.253/16 dev nat_veth2b
ip netns exec nat_ns_eth_l3_100 ip route add default via 10.251.255.254 dev nat_veth2b
ovs-ofctl add-group -OOpenFlow13 nat_ibr0 group_id=1,type=all
ip tuntap add nat_tap3 mode tap
ip link set nat_tap3 up
ip link set nat_tap3 mtu 1500
ovs-vsctl --may-exist add-port nat_ibr0 nat_tap3
ovs-ofctl add-group -OOpenFlow13 nat_ibr0 group_id=100,type=all
ip tuntap add nat_tap4 mode tap
ip link set nat_tap4 up
ip link set nat_tap4 mtu 1500
ovs-vsctl --may-exist add-port nat_ibr0 nat_tap4
ovs-ofctl add-group -OOpenFlow13 nat_ibr0 group_id=101,type=all
ip tuntap add nat_tap5 mode tap
ip link set nat_tap5 up
ip link set nat_tap5 mtu 1500
ovs-vsctl --may-exist add-port nat_ibr0 nat_tap5
ovs-ofctl add-group -OOpenFlow13 nat_ibr0 group_id=102,type=all
ip tuntap add nat_tap6 mode tap
ip link set nat_tap6 up
ip link set nat_tap6 mtu 1500
ovs-vsctl --may-exist add-port nat_ibr0 nat_tap6
ovs-ofctl add-group -OOpenFlow13 nat_ibr0 group_id=103,type=all
ovs-ofctl add-group -OOpenFlow13 nat_ibr0 group_id=2,type=all
ovs-ofctl mod-group -OOpenFlow13 nat_ibr0 group_id=1,type=all,bucket=output:3,bucket=output:4,bucket=output:5,bucket=output:6,bucket=output:2
ovs-ofctl mod-group -OOpenFlow13 nat_ibr0 group_id=100,type=all,bucket=output:4,bucket=output:5,bucket=output:6,bucket=output:2
ovs-ofctl mod-group -OOpenFlow13 nat_ibr0 group_id=101,type=all,bucket=output:3,bucket=output:5,bucket=output:6,bucket=output:2
ovs-ofctl mod-group -OOpenFlow13 nat_ibr0 group_id=102,type=all,bucket=output:3,bucket=output:4,bucket=output:6,bucket=output:2
ovs-ofctl mod-group -OOpenFlow13 nat_ibr0 group_id=103,type=all,bucket=output:3,bucket=output:4,bucket=output:5,bucket=output:2
ovs-ofctl mod-group -OOpenFlow13 nat_ibr0 group_id=2,type=all,bucket=output:3,bucket=output:4,bucket=output:5,bucket=output:6
ip netns exec nat_ns_eth_l3_100 /usr/sbin/dnsmasq --dhcp-authoritative --pid-file=/var/run/pcocc_dnsmasq_nat_ns_eth_l3_100.pid --conf-file= --leasefile-ro --dhcp-lease-max=65536 --dhcp-hostsfile /tmp/tmp_nwRni --domain=pcocc.pcocc.c-inti.ccc.ocre.cea.fr. --dhcp-option=15,pcocc.pcocc.c-inti.ccc.ocre.cea.fr. --dhcp-option=119,pcocc.pcocc.c-inti.ccc.ocre.cea.fr --dhcp-option=26,1450 --dhcp-option=option:dns-server,10.251.255.253 --dhcp-option=option:netmask,255.255.0.0 --dhcp-option=option:router,10.251.255.254 -F 10.251.0.0,static -h -E -H /tmp/tmpWIWn2A
iptables -t nat -C PREROUTING -d 10.200.0.1/32 -p tcp -m tcp --dport 60222 -j DNAT --to-destination 10.250.0.1:22
iptables -t nat -A PREROUTING -d 10.200.0.1/32 -p tcp -m tcp --dport 60222 -j DNAT --to-destination 10.250.0.1:22
iptables -t nat -C OUTPUT -d 10.200.0.1/32 -p tcp -m tcp --dport 60222 -j DNAT --to-destination 10.250.0.1:22
iptables -t nat -A OUTPUT -d 10.200.0.1/32 -p tcp -m tcp --dport 60222 -j DNAT --to-destination 10.250.0.1:22
iptables -t nat -C PREROUTING -d 10.200.0.1/32 -p tcp -m tcp --dport 60223 -j DNAT --to-destination 10.250.0.2:22
iptables -t nat -A PREROUTING -d 10.200.0.1/32 -p tcp -m tcp --dport 60223 -j DNAT --to-destination 10.250.0.2:22
iptables -t nat -C OUTPUT -d 10.200.0.1/32 -p tcp -m tcp --dport 60223 -j DNAT --to-destination 10.250.0.2:22
iptables -t nat -A OUTPUT -d 10.200.0.1/32 -p tcp -m tcp --dport 60223 -j DNAT --to-destination 10.250.0.2:22
iptables -t nat -C PREROUTING -d 10.200.0.1/32 -p tcp -m tcp --dport 60224 -j DNAT --to-destination 10.250.0.3:22
iptables -t nat -A PREROUTING -d 10.200.0.1/32 -p tcp -m tcp --dport 60224 -j DNAT --to-destination 10.250.0.3:22
iptables -t nat -C OUTPUT -d 10.200.0.1/32 -p tcp -m tcp --dport 60224 -j DNAT --to-destination 10.250.0.3:22
iptables -t nat -A OUTPUT -d 10.200.0.1/32 -p tcp -m tcp --dport 60224 -j DNAT --to-destination 10.250.0.3:22
iptables -t nat -C PREROUTING -d 10.200.0.1/32 -p tcp -m tcp --dport 60225 -j DNAT --to-destination 10.250.0.4:22
iptables -t nat -A PREROUTING -d 10.200.0.1/32 -p tcp -m tcp --dport 60225 -j DNAT --to-destination 10.250.0.4:22
iptables -t nat -C OUTPUT -d 10.200.0.1/32 -p tcp -m tcp --dport 60225 -j DNAT --to-destination 10.250.0.4:22
iptables -t nat -A OUTPUT -d 10.200.0.1/32 -p tcp -m tcp --dport 60225 -j DNAT --to-destination 10.250.0.4:22
ovs-ofctl add-flows -OOpenFlow13 nat_ibr0 /tmp/tmpJvpevg
ovs-ofctl add-flows -OOpenFlow13 nat_xbr /tmp/tmp2jB3cZ
iptables -t nat -C OUTPUT -d 10.200.0.1/32 -p tcp -m tcp --dport 60225 -j DNAT --to-destination 10.250.0.4:22
iptables -t nat -C PREROUTING -d 10.200.0.1/32 -p tcp -m tcp --dport 60225 -j DNAT --to-destination 10.250.0.4:22
iptables -t nat -C OUTPUT -d 10.200.0.1/32 -p tcp -m tcp --dport 60224 -j DNAT --to-destination 10.250.0.3:22
iptables -t nat -C PREROUTING -d 10.200.0.1/32 -p tcp -m tcp --dport 60224 -j DNAT --to-destination 10.250.0.3:22
iptables -t nat -C OUTPUT -d 10.200.0.1/32 -p tcp -m tcp --dport 60223 -j DNAT --to-destination 10.250.0.2:22
iptables -t nat -C PREROUTING -d 10.200.0.1/32 -p tcp -m tcp --dport 60223 -j DNAT --to-destination 10.250.0.2:22
iptables -t nat -C OUTPUT -d 10.200.0.1/32 -p tcp -m tcp --dport 60222 -j DNAT --to-destination 10.250.0.1:22
iptables -t nat -C PREROUTING -d 10.200.0.1/32 -p tcp -m tcp --dport 60222 -j DNAT --to-destination 10.250.0.1:22
ip link del nat_tap6
ip link del nat_tap5
ip link del nat_tap4
ip link del nat_tap3
ip link del nat_veth2
ip netns delete nat_ns_eth_l3_100
ip link del nat_veth1
ovs-ofctl del-flows -OOpenFlow13 nat_xbr cookie=100/-1
ovs-vsctl --if-exist del-br nat_ibr0
""")

