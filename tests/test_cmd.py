import pcocc.scripts.cmd as cmd
from conftest import my_cluster, fail_cluster
from mock import patch
from pcocc.scripts import click
from pcocc.scripts.click.testing import CliRunner
from ClusterShell.NodeSet import RangeSet

def dummy_load_config(batchid=None, batchname=None, batchuser=None,
                      default_batchname=None,
                      process_type=None):
    pass


def load_fake_cluster():
    return my_cluster()


def agent_run_and_expect(thecmd, expectedval, args=None, fail=False):
    if args is None:
        args = []
    with patch("pcocc.scripts.cmd.load_config",
               side_effect=dummy_load_config):
        with patch("pcocc.scripts.cmd.load_batch_cluster",
                   side_effect=load_fake_cluster):
            runner = CliRunner()
            # With Range
            for rng in ["-", "1-7/2", "1,5,7"]:
                res = runner.invoke(cmd.commands, [thecmd, "-w", rng] + args)
                if fail:
                    assert res.exit_code != 0
                else:
                    assert res.exit_code == 0
                    if rng == "-":
                        rset = range(0, 7)
                    else:
                        rset = RangeSet(rng)
                    for i in rset:
                        assert '"{0}": {1}'.format(i, expectedval) in res.output
            # With Index
            for idx in range(0, 7):
                res = runner.invoke(cmd.commands, [thecmd,"-w", idx] + args)
                if fail:
                    assert res.exit_code != 0
                else:
                    assert res.exit_code == 0
                    assert '"{0}": {1}'.format(idx, expectedval) in res.output


def test_agent():
    agent_run_and_expect(thecmd="hostname", expectedval='"here"')
    agent_run_and_expect(thecmd="hello", expectedval='123')
    agent_run_and_expect(thecmd="freeze", expectedval=0)
    agent_run_and_expect(thecmd="thaw", expectedval=0)
    agent_run_and_expect(thecmd="allocfree", expectedval=8)
    # MKDIR / CHMOD
    for thecmd in ["mkdir", "chmod"]:
        agent_run_and_expect(thecmd=thecmd,
                             expectedval=0,
                             args=["-p", "/here"])
        agent_run_and_expect(thecmd=thecmd,
                             expectedval=0,
                             args=["-p", "/here", "-m", "777"])
        agent_run_and_expect(thecmd=cmd,
                             expectedval=0,
                             args=[], fail=True)
    # IP
    agent_run_and_expect(thecmd="ip",
                         expectedval='"10.19.213.1"')
    agent_run_and_expect(thecmd="ip",
                         expectedval='"10.19.213.1"',
                         args=["-e", "eth0"])
    # Exec
    agent_run_and_expect(thecmd="exec",
                         expectedval="",
                         args=[], fail=True)
    agent_run_and_expect(thecmd="exec",
                         expectedval="",
                         args=["ls"], fail=True)
    agent_run_and_expect(thecmd="exec",
                         expectedval=0,
                         args=["-l", "1", "-u",
                               16, "-g", 32, "ls"])
    # Alloc
    agent_run_and_expect(thecmd="alloc",
                         expectedval="",
                         args=[], fail=True)
    agent_run_and_expect(thecmd="alloc",
                         expectedval="",
                         args=["-g", "123"], fail=True)
    agent_run_and_expect(thecmd="alloc",
                         expectedval="8",
                         args=["-g", 123,
                               "-c", 16,
                               "-d", "test"])
    # Release
    agent_run_and_expect(thecmd="release",
                         expectedval=0,
                         args=["-g", 99])

    # Vm Stat
    agent_run_and_expect(thecmd="vmstat",
                         expectedval='{\n        "cpu": "50"\n    }',
                         args=["-r"])
