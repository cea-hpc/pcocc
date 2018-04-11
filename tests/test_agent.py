import pytest
import os
import subprocess
import time

from mock import patch

import pcocc.Agent as cmd

from ClusterShell.NodeSet import RangeSetParseError
from conftest import my_cluster, fail_cluster, Command
from pcocc.Error import NoAgentError


def test_command_init():
    # Error
    with pytest.raises(Exception):
        cmd.AgentCommand(None)
    # Basic
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    assert ccmd.c == c
    # Del
    del ccmd


def test_vm_count():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    assert ccmd.vm_count() == 8


def test_unfold_range():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)

    # Try int range
    r = ccmd.unfold_range(3)
    assert isinstance(r, list)
    assert r[0] == 3

    # Try str range
    r = ccmd.unfold_range("1")
    assert isinstance(r, list)
    assert r[0] == 1

    # Try linear ranges
    r = ccmd.unfold_range("0-7")
    assert isinstance(r, list)
    assert r == range(0, 8)

    # Try Range auto filter
    r = ccmd.unfold_range("0-128")
    assert isinstance(r, list)
    assert r == range(0, 8)

    # Try incorrect range
    with pytest.raises(RangeSetParseError):
        r = ccmd.unfold_range("vm[0-128]")

    # Try stride range
    r = ccmd.unfold_range("0-7/2")
    assert isinstance(r, list)
    assert len(r) == 4

    # Try full range
    r = ccmd.unfold_range("-")
    assert isinstance(r, list)
    assert r == range(0, 8)
    assert len(r) == ccmd.vm_count()


def run_func(pushret, index, thearg, sleep):
    if sleep != 0:
        time.sleep(sleep)
    pushret(index, index)
    assert thearg == 1234


def test_run_func():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)

    # Full range
    ret = ccmd.run_func(range(0, 8), run_func, (1234, 1))
    for i in range(0, 8):
        assert ret[str(i)] == i

    # Medium range
    ret = ccmd.run_func(range(0, 32), run_func, (1234, 1))
    for i in range(0, 8):
        assert ret[str(i)] == i

    # Huge Range
    ret = ccmd.run_func(range(0, 8192), run_func, (1234, 0))
    for i in range(0, 8192):
        assert ret[str(i)] == i

def test_chk():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)

    # Error
    ret = ccmd._chk(Command("error", "{}"))
    assert ret is None

    # Nothing as input
    ret = ccmd._chk(None)
    assert ret is None

    # Good JSON
    ret = ccmd._chk(Command("success", '{"test":"data"}'))
    assert isinstance(ret, dict)
    assert ret["test"] == "data"

    # Bad JSON
    ret = ccmd._chk(Command("success", '{"test}'))
    assert isinstance(ret, dict)
    assert ret == {}

class no_agent_cluster(my_cluster):
    """Mock of a pcocc cluster object failing all commands
    """
    def check_agent(self,vm):
        return 0


def test_noagent():
    with pytest.raises(NoAgentError):
        raise NoAgentError()
    
    c = no_agent_cluster()
    ccmd = cmd.AgentCommand(c)

    with pytest.raises(NoAgentError):
        ccmd.unfold_range("0-7")

def test_doexec():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.doexec("-", alloc_id=1,
                      command="ls",
                      args=["-l"],
                      uid=16,
                      gid=32)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_doexec_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.doexec("-", alloc_id=1,
                      command="ls",
                      args=["-l"],
                      uid=16,
                      gid=32)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_alloc():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.alloc("-", size=16,
                     desc="test",
                     global_alloc_id=123)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 8


def test_alloc_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.alloc("-", size=16,
                     desc="test",
                     global_alloc_id=123)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == -1


def test_allocfree():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.allocfree("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 8


def test_allocfree_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.allocfree("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == -1


def test_release():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.release("-", gid=99)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_release_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.release("-", gid=99)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_freeze():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.freeze("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_freeze_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.freeze("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_thaw():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.thaw("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_thaw_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.thaw("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_attach():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.attach("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_attach_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.attach("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_detach():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.detach("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_detach_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.detach("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_eof():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.eof("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_eof_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.eof("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_hello():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.hello("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 123


def test_hello_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.hello("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == -1


def test_hostname():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.hostname("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == "here"


def test_hostname_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.hostname("-")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_mkdir():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.mkdir("-", path="/here", mode=777)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_mkdir_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.mkdir("-", path="/here", mode=777)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_chmod():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.chmod("-", path="/here", mode=777)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_chmod_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.chmod("-", path="/here", mode=777)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_chown():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.chown("-", path="/here", uid=123, gid=456)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_chown_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.chown("-", path="/here",  uid=123, gid=456)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_ln():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.ln("-", src="/from", dest="/to")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_ln_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.ln("-", src="/from", dest="/to")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_mv():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.mv("-", src="/from", dest="/to")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_mv_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.mv("-", src="/from", dest="/to")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_stat():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.stat("-", path="/here")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert isinstance(ret[str(i)], dict)


def test_stat_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.stat("-", path="/here")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_rm():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.rm("-", path="/here")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_rm_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.rm("-", path="/here")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_truncate():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.truncate("-", path="/here", size="1234")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_truncate_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.truncate("-", path="/here", size="1234")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_unsetenv():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.unsetenv("-", key="thekey")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_unsetenv_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.unsetenv("-", key="thekey")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_getenv():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.getenv("-", key="thekey")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == "test"


def test_getenv_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.getenv("-", key="thekey")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_userinfo():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.userinfo("-", login="bob")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert isinstance(ret[str(i)], dict)
        assert "uid" in ret[str(i)]
        assert ret[str(i)]["uid"] == "1000"


def test_userinfo_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.userinfo("-", login="bob")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_lookup():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.lookup("-", hostname="vm0")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == "10.19.213.1"


def test_lookup_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.lookup("-", hostname="vm0")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_getip():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.getip("-", iface="eth0")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == "10.19.213.1"


def test_getip_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.getip("-", iface="eth0")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_setenv():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.setenv("-", key="thekey", value="test")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_setenv_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.setenv("-", key="thekey", value="test")
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_vmstat():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.vmstat("-", interupt=True)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert isinstance(ret[str(i)], dict)
        assert "cpu" in ret[str(i)]
        assert ret[str(i)]["cpu"] == "50"


def test_vmstat_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.vmstat("-", interupt=1)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_writefile():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.writefile("-", path="/here",
                         content="dGVzdA==",
                         base64=True,
                         append=True)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0

    ret = ccmd.writefile("-", path="/here",
                         content="test",
                         base64=False,
                         append=True)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 0


def test_writefile_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.writefile("-", path="/here",
                         content="test",
                         base64=True,
                         append=True)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_readfile():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.readfile("-", path="/here",
                        base64=True)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == "dGVzdA=="

    ret = ccmd.readfile("-", path="/here",
                        base64=False)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == "test"


def test_readfile_fail():
    c = fail_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.readfile("-", path="/here",
                        base64=True)
    for i in range(0, ccmd.vm_count()):
        assert str(i) in ret
        assert ret[str(i)] == 1


def test_printer():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)
    ret = ccmd.getenv("-", key="thekey")
    prt = cmd.AgentCommandPrinter("getenv", ret)
    assert isinstance(prt, object)
    assert isinstance(str(prt), str)


def test_execstream():
    c = my_cluster()
    ccmd = cmd.AgentCommand(c)

    def indata():
        for v in [1, 2, 3, 4]:
            yield v

    ret = ccmd.exec_stream(inputs=indata)

    data = []
    for v in ret:
        data.append(v)
    data.sort()
    assert data == [1, 2, 3, 4]
