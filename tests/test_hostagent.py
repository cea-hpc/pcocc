import pytest
import os
import subprocess
from mock import patch

import json
import pcocc.pcocc_pb2
from conftest import myInputOutput

from pcocc.Hypervisor import hostAgentContext, AgentError, pcoccHostAgent



def test_host_agent_ctx():

    def cb():
        pass
    
    # Callback Management
    ctx = hostAgentContext(vm_rank=0)

    assert ctx.vm_rank == 0
    ctx.set_ret_cb(123 , cb)

    rcb = ctx.get_ret_cb(123)
    assert cb == rcb

    rcb = ctx.get_ret_cb(123)
    assert rcb == None

    rcb = ctx.get_ret_cb(1234)
    assert rcb == None


    ectx = ctx.execctx_new(123)
    assert ectx

    gectx = ctx.execctx_get(123)
    assert gectx
    assert gectx == ectx

    with pytest.raises(AgentError):
        ctx.execctx_new(123)
    
    ngectx = ctx.execctx_get_or_create(456)
    assert gectx

    gectx = ctx.execctx_get_or_create(123)
    assert gectx
    assert gectx == ectx

    # Test Commands on 123

    ctx.execctx_command({"data": {"id":123, "kind":"stdout", "data":"test"}})
    assert len(gectx["outputs"]) == 1
    assert gectx["outputs"][0]["data"] == "test"
    assert gectx["outputs"][0]["stderr"] == 0

    ctx.execctx_command({"data": {"id":123, "kind":"stderr", "data":"test2"}})
    assert len(gectx["outputs"]) == 2
    assert gectx["outputs"][1]["data"] == "test2"
    assert gectx["outputs"][1]["stderr"] == 1

    ctx.execctx_command({"data": {"id":123, "kind":"end_exec"}})
    assert gectx["done"] == 1

    ctx.execctx_command({"data": {"id":123, "kind":"start_exec"}})
    assert gectx["done"] == 0 

    ctx.execctx_command({"data": {"id":123, "kind":"detach_exec"}})
    assert gectx["detach"] == 1

    ctx.execctx_command({"data": {"id":123, "kind":"attach_exec"}})
    assert gectx["detach"] == 0

    with pytest.raises(AgentError):
        ctx.execctx_command({"data": {}})



class myBatch(object):

    def get_vm_state_path(self, rank, path):
        return "this_is_the_path"
    
    def write_key(self, path, key, value):
        assert path == 'cluster/user'
        assert key == "hostagent/vms/1-agent"
        assert value == "started"


class myConfig(object):
    def __init__(self):
        self.batch = myBatch()


class mySocket(object):

    def __init__(self):
        self.data = []
        self.resp = []

    def connect(self, path):
        assert path == "this_is_the_path"


    def sendall(self,data):
        self.data.append(data)
        dat = json.loads( data )
        dat["cmd"] = "success"
        self.resp.append(json.dumps(dat))
    
    def recv(self, size):
        while len(self.resp) == 0:
            pass
        dat = self.resp.pop()
        dat = dat + "\n"
        return dat

    def popdata(self):
        return self.data.pop()
    
    def fileno(self):
        return -1
    
    def shutdown(self, type):
        pass
    
    def close(self):
        pass

class mySocketMod(object):
    AF_UNIX, SOCK_STREAM,SHUT_RDWR = range(3)
    def __init__(self):
        pass
    
    def socket( self, t, tt):
        return mySocket()


def my_read_a_command(self):
    pass


def my_queue_get(self, timeout):
    # Just say it went well
    return {"cmd":"success", "data":{}}



@patch("pcocc.Hypervisor.Config", myConfig)
@patch("pcocc.Hypervisor.socket", mySocketMod())
@patch("pcocc.Hypervisor.pcoccHostAgent.read_a_command", my_read_a_command)
@patch("pcocc.Hypervisor.Queue.Queue.get", my_queue_get)
def test_host_agent():
    agent = pcoccHostAgent(1)

    agent.send_eof()
    dat = agent.sock.popdata()
    assert dat
    cmd = json.loads(dat)
    assert cmd["cmd"] == "exec_stdin_eof"

    ret = agent.send_input(myInputOutput("testdata"))
    dat = agent.sock.popdata()
    assert dat
    cmd = json.loads(dat)
    assert cmd["cmd"] == "exec_stdin"
    assert cmd["data"]["data"] == "testdata"

    # Test output

    def act():
        return True

    agent.ctx.execctx_command({"data": {"id":123, "kind":"start_exec"}})
    agent.ctx.execctx_command({"data": {"id":123, "kind":"stdout", "data":"test"}})
    agent.ctx.execctx_command({"data": {"id":123, "kind":"end_exec"}})

    for e in agent.get_output(act):
        assert e
        assert e.stdin == "test"
        assert e.stderr == ""
    
    agent.ctx.execctx_command({"data": {"id":123, "kind":"start_exec"}})
    agent.ctx.execctx_command({"data": {"id":123, "kind":"stderr", "data":"test"}})
    agent.ctx.execctx_command({"data": {"id":123, "kind":"end_exec"}})

    for e in agent.get_output(act):
        assert e
        assert e.stdin == ""
        assert e.stderr == "test"
    
    # Test started
    agent.agent_started()


    # Test incoming commands (from agent)
    cmd = pcocc.pcocc_pb2.Command(source=0,
                                  destination=0,
                                  cmd="test",
                                  data='"TEST"')
    ret, _ = agent.process_incoming_command(cmd)

    assert ret == "error"

    # Test command switch

    # From agent
    agent.handle_incoming_command('{"cmd":"MIA", "data":{}}')
    dat = agent.sock.popdata()
    assert dat
    cmd = json.loads(dat)
    assert cmd["cmd"] == "error"

    # Actual commands
    cb_called = [0]

    def my_cb(action, data):
        cb_called[0] = 1

    agent.ctx.set_ret_cb(123, my_cb)
    agent.handle_incoming_command('{"cmd":"success", "tag":"123", "data":{}}')

    assert cb_called[0] == 1

    cb_called[0] = 0
    agent.ctx.set_ret_cb(123, my_cb)
    agent.handle_incoming_command('{"cmd":"error", "tag":"123", "data":{}}')

    assert cb_called[0] == 1

    # Async commands
    gectx = agent.ctx.execctx_get_or_create(123)
    
    gectx["dome"] = 0
    agent.handle_incoming_command('{"cmd":"async", "tag":"123", "data":{"type": "execstream" , "id":123, "kind":"end_exec"}}')
    assert gectx["done"] == 1

    agent.handle_incoming_command('{"cmd":"async", "tag":"123", "data":{"type": "agentstart"}}')

    # Call shutdown
    agent.quit()



