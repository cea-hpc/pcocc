#  Copyright (C) 2014-2015 CEA/DAM/DIF
#
#  This file is part of PCOCC, a tool to easily create and deploy
#  virtual machines using the resource manager of a compute cluster.
#
#  PCOCC is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  PCOCC is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with PCOCC. If not, see <http://www.gnu.org/licenses/>

from __future__ import division
import sys
import subprocess
import atexit
import select
import signal
import os
import termios
import shlex
import datetime
import struct
import errno
import tempfile
import re
import time
import threading
import logging
import pcocc
import pcocc.Image
import pcocc.Plot

from shutil import copyfile
from pcocc.scripts import click
from pcocc import PcoccError, Config, Cluster, Hypervisor
from pcocc.Backports import subprocess_check_output
from pcocc.Batch import ProcessType
from pcocc.Misc import fake_signalfd, wait_or_term_child, stop_threads
from pcocc.scripts.Shine.TextTable import TextTable
from pcocc.pcocc_pb2 import stdio
from pcocc.Agent import AgentCommand, AgentCommandPrinter


helperdir = '/etc/pcocc/helpers'


def handle_error(err):
    """ Print exception with stack trace if in debug mode """

    click.secho(str(err), fg='red', err=True)
    if Config().debug:
        raise err
    sys.exit(-1)


def cleanup(spr, terminal_settings):
    """ Called at exit to restore terminal settings """
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW,
                      terminal_settings)
    try:
        spr.kill()
    except OSError as err:
        # Subprocess already killed
        if err.errno == errno.ESRCH:
            pass
        else:
            raise


def ascii(text):
    return text.encode('ascii', 'ignore')


def docstring(docstr, sep="\n"):
    """ Decorator: Append to a function's docstring.
    """
    def _decorator(func):
        if func.__doc__ == None:
            func.__doc__ = docstr
        else:
            func.__doc__ = sep.join([func.__doc__, docstr])
        return func
    return _decorator


def load_config(batchid=None, batchname=None, batchuser=None,
                default_batchname=None,
                process_type=ProcessType.USER):

    if batchuser and (batchid is None) and (batchname is None):
        raise click.UsageError('the target job must be explicitely set '
                               'when specifying a user')
    config = Config()
    config.load(jobid=batchid, jobname=batchname,
                batchuser=batchuser, default_jobname=default_batchname,
                process_type=process_type)
    config.load_user()
    return config


def load_batch_cluster(user=None,batchid=None):
    definition = Config().batch.read_cluster_definition(user, batchid)
    return Cluster(definition)

@click.group(context_settings=dict(help_option_names=['-h', '--help']))
@click.option('-v', '--verbose', count=True)
def cli(verbose):
    Config().verbose = verbose

def display_manpage(page):
    try:
        if page == 'pcocc':
            p = subprocess.Popen(['man', page])
        else:
            p = subprocess.Popen(['man', 'pcocc-' + page])
    except:
        raise click.UsageError("No such help topic '" + page + "'\n"
                               "       use 'pcocc help' to list topics")

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    p.communicate()
    signal.signal(signal.SIGINT, signal.SIG_DFL)

@cli.command(name='help', short_help='Display man pages for a given subcommand')
@click.argument('command', default='pcocc')
def pcocc_help(command):
    display_manpage(command)

@cli.group(hidden=True)
def internal():
    """ For internal use """
    pass

@cli.group()
def template():
    """ List and manage templates """
    pass

DEFAULT_SSH_OPTS = [ '-o', 'UserKnownHostsFile=/dev/null', '-o',
                     'LogLevel=ERROR', '-o', 'StrictHostKeyChecking=no' ]

def find_vm_rnat_port(cluster, index, port=22):
    cluster.wait_host_config()
    host_port = pcocc.EthNetwork.VEthNetwork.get_rnat_host_port(index, port)
    if host_port:
        return host_port
    else:
        sys.stderr.write('Error: port {0} is not reverse NATed\n'.format(
            port))
        sys.exit(-1)

def find_vm_ssh_opt(opts, regex, s_opts, v_opts, first_arg_only=True):
    """Parse ssh/scp arguments to find the remote vm hostname"""
    skip = False
    i = 0
    for i, opt in enumerate(opts):
        if skip:
            skip = False
            continue
        if re.match(r'-[{0}]+$'.format(s_opts), opt):
            continue
        if opt in [ "-"+o for o in v_opts]:
            skip=True
            continue
        match = re.search(regex, opt)
        if match:
            break
        if first_arg_only:
            raise click.UsageError("Unable to parse vm name")
    else:
        raise click.UsageError("Unable to parse vm name")

    return i, match


@cli.command(name='display',
             short_help='Display the graphical output of a VM')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-p', '--print_opts', is_flag=True, help='Print remote-viewer options')
@click.argument('vm', nargs=1, default='vm0')
def pcocc_display(jobid, jobname, print_opts, vm):
    """Display the graphical output of a VM

    This requires the VM to have a remote display method defined in it's template.

    \b
    Example usage:
           pcocc display vm0
    """
    try:
        config = load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()
        index = vm_name_to_index(vm)
        vm = cluster.vms[index]

        if vm.remote_display == 'spice':
            opts_file = os.path.join(config.batch.cluster_state_dir,
                                     'spice_vm{0}/console.vv'.format(index))
            if print_opts:
                with open(opts_file, 'r') as f:
                    print f.read()
            else:
                s_ctl = subprocess.Popen(['remote-viewer', opts_file])
                ret = s_ctl.wait()
                sys.exit(ret)
        else:
            raise click.UsageError('VM has no valid remote display')

    except PcoccError as err:
        handle_error(err)

def ps_display_jobs(joblist):
    tbl = TextTable("%id %user %partition %nodes %name %template %elapsed %timelimit")

    try:

        for j in joblist:
            tbl.append({'id': str(j["batchid"]),
                        'user': j["user"],
                        'partition': j["partition"],
                        'nodes': str(j["node_count"]),
                        'name': j["jobname"],
                        'template': j["definition"],
                        'elapsed': j["exectime"],
                        'timelimit': j["timelimit"]
                        })
    except PcoccError as err:
        handle_error(err)
    print tbl


def ps_display_vm_state(cluster):
    tbl = TextTable("%vm %hostname %description %value")

    try:
        for i in range(0, cluster.vm_count()):
            state = cluster.state(i)
            tbl.append({'vm': "vm" + str(i),
                        'hostname': state.get("hostname"),
                        'description': state["desc"],
                        'value': state["value"]
                        })
    except PcoccError as err:
        handle_error(err)
    print tbl


@cli.command(name='ps',
             short_help='List Clusters and Jobs')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-a', '--allj', is_flag=True, default=False,
              help='Use to display all pcocc jobs')
def pcocc_shell(jobid, jobname, allj):
    """Display currently allocated pcocc clusters
       or display the state of a specific cluster
    """
    config = load_config(jobid, jobname, default_batchname='pcocc')
    jobs = config.batch.list_alive_jobs()

    filtered_list = []
    if jobid or jobname:
        # In this mode we are targetting a single cluster
        # we then proceed to display its state

        cluster = load_batch_cluster()

        current_id = config.batch.batchid
        print(current_id)
        batch_desc = [v for v in jobs if v["batchid"] == current_id ]

        if len(batch_desc) == 0:
            raise Exception("Error this job was not found")

        # Start by displaying Batch level infos
        click.secho("\nAllocation Information:\n",
                        fg='blue')
        ps_display_jobs(batch_desc)

        #Now Generate VM state
        click.secho("\nVirtual Machines' State:\n",
                    fg='blue')
        ps_display_vm_state(cluster)
    else:
        # In this mode we are not targetting a particular job 
        # we therefore display jobs
        for j in jobs:
            if allj or (j["user"] == config.batch.batchuser):
                filtered_list.append(j)
        ps_display_jobs(filtered_list)


@cli.command(name='shell',
             context_settings=dict(ignore_unknown_options=True,
                                   allow_interspersed_args=False),
             short_help='Open a Shell Using the Pcocc Agent')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-s', '--shell', type=str, default="bash",
              help='Shell to be used (default=bash)')
@click.argument('shell_opts', nargs=-1, type=click.UNPROCESSED)
def pcocc_shell(jobid, jobname, shell, shell_opts):
    """Open a shell to a VM using the Pcocc Agent

    \b
    Example usage:
           pcocc shell user@vm1

    """
    config = load_config(jobid, jobname, default_batchname='pcocc')
    cluster = load_batch_cluster()

    ccmd = AgentCommand( cluster, 0 )

    #No argument case
    if shell_opts == ():
        shell_opts = ("root@vm0", )

    shell_opts = " ".join(shell_opts)

    s_vm_user = "root"
    s_vm_idx = 0

    login_vm = re.search(r"(?P<login>\w+)@vm(?P<vmid>\d+)", shell_opts) 
    
    if not login_vm:
        vm = re.search(r"vm(?P<vmid>\d+)", shell_opts )
        
        if not vm:
            sys.stderr.write("Cannot parse login expression " + shell_opts + "\n")
            sys.exit(1)
        else:
            #VM only
            s_vm_idx = int(vm.group("vmid"))
    else:
        #login + vm
        s_vm_idx = int(login_vm.group("vmid"))
        s_vm_user = login_vm.group("login")

    #Now resolve the target user
    user_gid = 0
    user_uid = 0

    if s_vm_user != "root":
        #It seems that we need to resolve target UID
        user_info = ccmd.userinfo( s_vm_idx, s_vm_user )
        if user_info == None:
            sys.stderr.write("Failed to resolve infos for user " + s_vm_user + "\n")
            sys.exit(1)
        else:
            if user_info[ str(s_vm_idx)] == None:
                sys.stderr.write("Failed to resolve infos for user " + s_vm_user + "\n" )
                sys.exit(1)

            user_uid = int(user_info[ str(s_vm_idx) ]["uid"])
            user_gid = int(user_info[ str(s_vm_idx) ]["gid"])

    local_pcocc_exec(config,
                     ccmd,
                     jobid,
                     jobname,
                     "",
                     s_vm_idx,
                     1,
                     [shell, '-i'],
                     user_uid,
                     user_gid)


@cli.command(name='ssh',
             context_settings=dict(ignore_unknown_options=True,
                                   allow_interspersed_args=False),
             short_help='Connect to a VM via ssh')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('--user',
              help='Select cluster among jobs of the specified user')
@click.argument('ssh-opts', nargs=-1, type=click.UNPROCESSED)
def pcocc_ssh(jobid, jobname, user, ssh_opts):
    """Connect to a VM via ssh

    This requires the VM to have its ssh port reverse NAT'ed to the
    host in its NAT network configuration.

    \b
    Example usage:
           pcocc ssh user@vm1

    """
    try:
        load_config(jobid, jobname, default_batchname='pcocc',
                    batchuser=user)

        cluster = load_batch_cluster()

        ssh_opts = list(ssh_opts)
        arg_index, match = find_vm_ssh_opt(ssh_opts, r'(^|@)vm(\d+)',
                                          '1246AaCfgKkMNnqsTtVvXxYy',
                                          'bcDeFiLlmOopRSw')

        vm_index = int(match.group(2))
        remote_host = cluster.vms[vm_index].get_host()
        ssh_port = find_vm_rnat_port(cluster, vm_index)
        ssh_opts[arg_index] = ssh_opts[arg_index].replace("vm%d"%vm_index,
                                                          remote_host)
        s_ctl = subprocess.Popen(['ssh', '-p', '%s'%(ssh_port)] +
                                 DEFAULT_SSH_OPTS + ssh_opts)
        ret = s_ctl.wait()
        sys.exit(ret)

    except PcoccError as err:
        handle_error(err)


@cli.command(name='scp',
             context_settings=dict(ignore_unknown_options=True,
                                   allow_interspersed_args=False),
             short_help='Transfer files to a VM via scp')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('--user',
              help='Select cluster among jobs of the specified user')
@click.argument('scp-opts', nargs=-1, type=click.UNPROCESSED)
def pcocc_scp(jobid, jobname, user, scp_opts):
    """Transfer files to a VM via scp

       This requires the VM to have its ssh port reverse NAT'ed to the host in 
       its NAT network configuration.

       \b
       Example usage:
           pcocc scp -r dir bar@vm1:

    """
    try:
        load_config(jobid, jobname, default_batchname='pcocc',
                    batchuser=user)

        cluster = load_batch_cluster()

        scp_opts = list(scp_opts)
        arg_index, match = find_vm_ssh_opt(scp_opts, r'(^|@)vm(\d+):',
                                          '12346BCpqrv', 'cfiloPS', False)

        vm_index = int(match.group(2))
        remote_host = cluster.vms[vm_index].get_host()
        scp_opts[arg_index] = scp_opts[arg_index].replace("vm%d:"%vm_index,
                                                          remote_host+':')
        ssh_port = find_vm_rnat_port(cluster, vm_index)
        s_ctl = subprocess.Popen(
            ['scp', '-P', ssh_port] +  DEFAULT_SSH_OPTS + scp_opts)
        ret = s_ctl.wait()
        sys.exit(ret)

    except PcoccError as err:
        handle_error(err)

@cli.command(name='nc',
             context_settings=dict(ignore_unknown_options=True),
             short_help='Connect to a VM via nc')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('--user',
              help='Select cluster among jobs of the specified user')
@click.argument('nc-opts', nargs=-1, type=click.UNPROCESSED)
def pcocc_nc(jobid, jobname, user, nc_opts):
    """Connect to a VM via nc

    This requires the VM to have the selected port reverse NAT'ed to the
    host in its NAT network configuration.

    \b
    Example usage:
           pcocc nc vm1 80

    """
    try:
        load_config(jobid, jobname, default_batchname='pcocc',
                    batchuser=user)
        cluster = load_batch_cluster()

        nc_opts = list(nc_opts)
        rgxp = r'^vm(\d+)$'
        if len(nc_opts) > 0 and re.match(rgxp, nc_opts[-1]):
            host_opts = [nc_opts[-1]]
            vm_index = int(re.match(rgxp, host_opts[-1]).group(1))
            vm_port = 31337
            last_opt = max(0, len(nc_opts) -1)
        elif len(nc_opts) > 1 and re.match(rgxp, nc_opts[-2]):
            vm_index = int(re.match(rgxp, nc_opts[-2]).group(1))
            try:
                vm_port = int(nc_opts[-1])
            except ValueError:
                raise click.UsageError(
                    'Invalid port number {0}.'.format(nc_opts[-1]))
            last_opt = max(0, len(nc_opts) -2)
        else:
            raise click.UsageError("Unable to parse vm name")

        remote_host = cluster.vms[vm_index].get_host()

        nc_port = find_vm_rnat_port(cluster, vm_index, vm_port)
        s_ctl = subprocess.Popen(['nc'] +
                                 nc_opts[0:last_opt] +
                                 [ remote_host, nc_port ])
        ret = s_ctl.wait()
        sys.exit(ret)

    except PcoccError as err:
        handle_error(err)

def validate_save_dir(dest_dir, force):
    try:
        dest_dir = os.path.abspath(dest_dir)
        if dest_dir[-1] == '/':
            dest_dir = dest_dir[:-1]
        if os.path.isfile(dest_dir):
            raise click.UsageError('destination cannot be an existing file')
        if os.path.exists(dest_dir):
            if force:
                return dest_dir
            else:
                raise click.UsageError('destination directory already exists')
        if not os.path.exists(os.path.dirname(dest_dir)):
            raise click.UsageError('base directory %s does not exist' %
                                   (os.path.dirname(dest_dir)))
        if not os.path.isdir(os.path.dirname(dest_dir)):
            raise click.UsageError('base directory %s is not a direcotry' %
                                   (os.path.dirname(dest_dir)))
        else:
            os.mkdir(dest_dir)
    except OSError as err:
        raise click.UsageError('invalid destination directory: ' + err.strerror)

    return dest_dir

def vm_name_to_index(name):
    match = re.match(r'vm(\d+)$', name)
    if not match:
        raise click.UsageError("invalid vm name " + name)

    return int(match.group(1))

@cli.command(name='save',
             short_help='Save the disk of a VM')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-d', '--dest',
              help='Make a full copy in a new directory',
              metavar='DIR')
@click.option('-s', '--safe',
              help='Wait indefinitely for the Qemu agent to freeze filesystems',
              is_flag=True)
@click.argument('vm', nargs=1, default='vm0')
def pcocc_save(jobid, jobname, dest,  vm, safe):
    """Save the disk of a VM to a new disk image

    By default the output file only contains the differences between
    the current state of the disk and the template from which the VM
    was instantiated. Therefore, all incremental saves leading to an
    image have to be preserved.

    To save the disk to a new independant image file specify a new
    path with --dest.

    \b
    Example usage:
           pcocc save vm1

    """
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()
        index = vm_name_to_index(vm)
        vm = cluster.vms[index]

        if vm.image_dir is None:
            click.secho('Template is not based on a CoW image',
                        fg='red', err=True)
            sys.exit(-1)

        if dest:
            dest_dir = validate_save_dir(dest, False)

        click.secho('Saving image...')
        if dest:
            save_path = os.path.join(dest_dir, 'image')
            full = True
        else:
            save_path = os.path.join(vm.image_dir,
                                     'image-rev%d'%(vm.revision + 1))
            full = False

        if safe:
            freeze_opt = Hypervisor.VM_FREEZE_OPT.YES
        else:
            freeze_opt = Hypervisor.VM_FREEZE_OPT.TRY

        vm.save(save_path, full, freeze_opt)

        click.secho('vm%d disk '
                    'succesfully saved to %s' % (index,
                                                 save_path), fg='green')

    except PcoccError as err:
        handle_error(err)

@cli.command(name='reset',
             short_help='Reset a VM')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.argument('vm', nargs=1, default='vm0')
def pcocc_reset(jobid, jobname,  vm):
    """Reset a VM

    The effect is similar to the reset button on a physical machine.

    \b
    Example usage:
           pcocc reset vm1

    """
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()
        index = vm_name_to_index(vm)
        vm = cluster.vms[index]

        vm.reset()

        click.secho('vm%d has been reset'% (index), fg='green')

    except PcoccError as err:
        handle_error(err)



@cli.command(name='monitor-cmd',
             short_help='Send a command to the monitor')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.argument('vm', nargs=1, default='vm0')
@click.argument('cmd', nargs=-1)
def pcocc_monitor_cmd(jobid, jobname,  vm, cmd):
    """Send a command to the monitor

    \b
    Example usage:
           pcocc monitor-cmd vm0 info registers

    """
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()
        index = vm_name_to_index(vm)
        vm = cluster.vms[index]
        vm.wait_start()
        res = vm.human_monitor_cmd(' '.join(cmd))
        print res

    except PcoccError as err:
        handle_error(err)


@cli.command(name='dump',
             short_help='Dump VM memory to a file')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.argument('vm', nargs=1)
@click.argument('dumpfile', nargs=1)
def pcocc_dump(jobid, jobname,  vm, dumpfile):
    """Dump VM memory to a file

    The file is saved as ELF and includes the guest's memory
    mapping. It can be processed with crash or gdb.

    \b
    Example usage:
           pcocc dump vm1 output.bin

    """
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()
        index = vm_name_to_index(vm)
        vm = cluster.vms[index]

        dumpfile = os.path.abspath(dumpfile)

        click.secho('Dumping vm memory...')
        vm.dump(dumpfile)
        click.secho('vm%d has been dumped to %s'% (index,
                                                   dumpfile), fg='green')

    except PcoccError as err:
        handle_error(err)

@cli.command(name='ckpt',
             short_help='Checkpoint a virtual cluster')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-F', '--force', is_flag=True,
              help='Overwrite directory if exists')
@click.argument('ckpt-dir', nargs=1)
def pcocc_ckpt(jobid, jobname, force, ckpt_dir):
    """Checkpoint the current state of a cluster

    Both the disk image and memory of all VMs of the cluster are
    saved and the cluster is terminated. It is then possible to
    restart from this state using the --restart-ckpt option of
    the alloc and batch commands.

    CKPT_DIR should not already exist unless -F is specified. In that
    case, make sure you're not overwriting the checkpoint from which
    the cluster was restarted.

    \b
    Example usage:
           pcocc ckpt /path/to/checkpoints/mycheckpoint

    """
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        #Freeze the pcocc agent
        ccmd = AgentCommand( cluster, 0, log=False )
        ccmd.freeze("-")

        dest_dir = validate_save_dir(ckpt_dir, force)

        cluster.checkpoint(dest_dir)
        click.secho('Cluster state succesfully checkpointed '
                    'to %s'%(dest_dir), fg='green')

    except PcoccError as err:
        handle_error(err)


@cli.command(name='console',
             short_help='Connect to a VM console')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-l', '--log', is_flag=True, help='Show console log')
@click.argument('vm', nargs=1, default='vm0')
def pcocc_console(jobid, jobname, log, vm):
    """Connect to a VM console

    Hit Ctrl-C 3 times to exit.

    \b
    Example usage:
        pcocc console vm1
"""
    try:
        signal.signal(signal.SIGINT, clean_exit)
        signal.signal(signal.SIGTERM, clean_exit)

        config = load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        index = vm_name_to_index(vm)
        vm = cluster.vms[index]
        vm.wait_start()
        remote_host = vm.get_host()

        if log:
            try:
                # FIXME: reading the whole log at once will not
                # work for large logs
                log = subprocess_check_output(
                    shlex.split(
                        'ssh {0} cat {1}'.format(
                            remote_host,
                            config.batch.get_vm_state_path(
                                vm.rank,
                                'qemu_console_log'))))
                click.echo_via_pager(log)
            except Exception:
                click.secho("Unable to read console log",
                            fg='red', err=True)

            sys.exit(0)


        socket_path = config.batch.get_vm_state_path(vm.rank,
                                                     'pcocc_console_socket')
        self_stdin = sys.stdin.fileno()

        # Raw terminal
        old = termios.tcgetattr(self_stdin)
        new = list(old)
        new[3] = new[3] & ~termios.ECHO & ~termios.ISIG & ~termios.ICANON
        termios.tcsetattr(self_stdin, termios.TCSANOW,
                          new)

        s_ctl = subprocess.Popen(
            shlex.split('ssh %s nc -U %s ' % (remote_host, socket_path)),
            stdin=subprocess.PIPE)

        # Restore terminal and cleanup children at exit
        atexit.register(cleanup, s_ctl, old)

        last_int = datetime.datetime.now()
        int_count = 0
        while 1:
            rdy = select.select([sys.stdin, s_ctl.stdin], [], [s_ctl.stdin])

            if s_ctl.stdin in rdy[2] or s_ctl.stdin in rdy[0]:
                sys.stderr.write('Connection closed\n')
                break

            # Exit if Ctrl-C is pressed repeatedly
            if sys.stdin in rdy[0]:
                buf = os.read(self_stdin, 1024)
                if struct.unpack('b', buf[0:1])[0] == 3:
                    if (datetime.datetime.now() - last_int).total_seconds() > 2:
                        last_int = datetime.datetime.now()
                        int_count = 1
                    else:
                        int_count += 1

                    if int_count == 3:
                        print '\nDetaching ...'
                        break

                s_ctl.stdin.write(buf)

        # Restore terminal now to let user interrupt the wait if needed
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW,
                          old)
        s_ctl.terminate()
        s_ctl.wait()

    except PcoccError as err:
        handle_error(err)


batch_alloc_doc=""" Instantiate or restore a virtual cluster.
A cluster definition is expressed as a list of templates and
counts e.g.: tpl1:6,tpl2:2 will instantiate a cluster with 6
VMs from template tpl1 and 2 VMs from template tpl2

Batch options will be passed on to the underlying
batch manager.
"""

alloc_doc="""
In interactive mode (pcocc alloc), a shell is launched which allows to
easily interact with the created cluster as all pcocc commands
launched from the shell will implicitely target this cluster. The
virtual cluster will also be automatically terminated when the shell
exits.

\b
Example usage:
       pcocc alloc -c 4 --qos=test tpl1:6,tpl2:2
"""

batch_doc="""
\b
Example usage:
       pcocc batch -c 4 --qos=test tpl1:6,tpl2:2
"""

def gen_alloc_script_opt(alloc_script):
    if alloc_script:
        return ['-E', alloc_script]
    else:
        return []

def gen_ckpt_opt(restart_ckpt):
    if restart_ckpt:
        return ['-r', restart_ckpt]
    else:
        return []

def get_license_opts(cluster):
    license_list = cluster.get_license_list()
    if license_list:
        return ['-L', ','.join(license_list)]
    else:
        return []

@cli.command(name='batch',
             context_settings=dict(ignore_unknown_options=True),
             short_help="Run a virtual cluster (batch)")
@click.option('-r', '--restart-ckpt',
              help='Restart cluster from the specified checkpoint',
              metavar='DIR')
@click.option('-b', '--batch-script', type=click.File('r'),
              help='Launch a batch script in the first vm')
@click.option('-E', '--host-script', type=click.File('r'),
              help='Launch a batch script on the first host')
@click.argument('batch-options', nargs=-1, type=click.UNPROCESSED)
@click.argument('cluster-definition', nargs=1)
@docstring(batch_alloc_doc+batch_doc)
def pcocc_batch(restart_ckpt, batch_script, host_script, batch_options,
                cluster_definition):

    try:
        config = load_config(process_type=ProcessType.OTHER)

        cluster_definition = ascii(cluster_definition)
        cluster = Cluster(cluster_definition)
        batch_options=list(batch_options)
        ckpt_opt = gen_ckpt_opt(restart_ckpt)

        (wrpfile, wrpname) = tempfile.mkstemp()
        wrpfile = os.fdopen(wrpfile, 'w')

        if batch_script or host_script:
            launcher_opt = []
        else:
            launcher_opt = ['-w']

        wrpfile.write(
"""#!/bin/bash
#SBATCH -o pcocc_%j.out
#SBATCH -e pcocc_%j.err
""")
        if batch_script:
            launcher_opt += ['-s', '"$TEMP_BATCH_SCRIPT"']
            wrpfile.write(
"""
TEMP_BATCH_SCRIPT="/tmp/pcocc.batch.$$"
cat <<"PCOCC_BATCH_SCRIPT_EOF" >> "${TEMP_BATCH_SCRIPT}"
""")
            wrpfile.write(batch_script.read())
            wrpfile.write(
"""
PCOCC_BATCH_SCRIPT_EOF
chmod u+x "$TEMP_BATCH_SCRIPT"
""")

        if host_script:
            launcher_opt += ['-E', '"$TEMP_HOST_SCRIPT"']
            wrpfile.write(
"""
TEMP_HOST_SCRIPT="/tmp/pcocc.host.$$"
cat <<"PCOCC_HOST_SCRIPT_EOF" >> "${TEMP_HOST_SCRIPT}"
""")
            wrpfile.write(host_script.read())
            wrpfile.write(
"""
PCOCC_HOST_SCRIPT_EOF
chmod u+x "$TEMP_HOST_SCRIPT"
""")

        wrpfile.write(
"""
PYTHONUNBUFFERED=true pcocc %s internal launcher %s %s %s &
wait
rm "$TEMP_BATCH_SCRIPT" 2>/dev/null
rm "$TEMP_HOST_SCRIPT" 2>/dev/null
""" % (' '.join(build_verbose_opt()), ' '.join(launcher_opt),
       ' '.join(ckpt_opt), cluster_definition))

        wrpfile.close()
        ret = config.batch.batch(cluster,
                                 batch_options +
                                 get_license_opts(cluster) +
                                 ['-n', '%d' % (len(cluster.vms))],
                                  wrpname)
        sys.exit(ret)

    except PcoccError as err:
        handle_error(err)

def build_verbose_opt():
    if Config().verbose > 0:
        return [ '-' + 'v' * Config().verbose ]
    else:
        return []



@cli.command(name='exec',
             short_help="Execute commands through the guest agent",
             context_settings=dict(ignore_unknown_options=True,
                                   allow_interspersed_args=False))
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-w', '--rng', default="", type=str,
              help='Range of VMids on which the command should be executed')
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
@click.option('-c', '--cores', default=1, type=int,
              help='Number of cores to execute in each VM')
@click.option('-u', '--uid', default=0, type=int,
              help='UID used to run the command')
@click.option('-g', '--gid', default=0, type=int,
              help='GID used to run the command')
@click.argument('cmd', nargs=-1, required=False, type=click.UNPROCESSED)
def pcocc_exec(jobid, jobname, rng, index, cores, cmd, uid, gid):
    """Execute commands through the guest agent

       For this to work, a pcocc agent must be started in the
       guest.
    """
    config = load_config(jobid, jobname, default_batchname='pcocc')
    cluster = load_batch_cluster()

    ccmd = AgentCommand(cluster, 0)

    local_pcocc_exec(config, ccmd,
                     jobid, jobname,
                     rng, index,
                     cores, cmd,
                     uid, gid)



def pcocc_get_exec_id( config, g_alloc_id):
    current_alloc_id = 0
    if g_alloc_id < 0:
        #Get a global ID
        current_alloc_id = config.batch.read_key('cluster/user',
                                                 "hostagent/exec_alloc_id")
        if not current_alloc_id:
            config.batch.write_key('cluster/user',
                                   "hostagent/exec_alloc_id",
                                   "0")
            current_alloc_id = 0
        else:
            #Convert to int
            current_alloc_id = int(current_alloc_id)
            config.batch.write_key('cluster/user',
                                   "hostagent/exec_alloc_id",
                                   str(current_alloc_id + 1))
    else:
        current_alloc_id = g_alloc_id

    return current_alloc_id


@cli.command(name='mpirun',
             short_help="Launch MPI programs inside VMs",
             context_settings=dict(ignore_unknown_options=True,
                                   allow_interspersed_args=False))
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-w', '--rng', default="", type=str,
              help='Range of VMids on which the command should be executed')
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
@click.option('-n', '--np', default=1, type=int,
              help='Number of processes to run on')
@click.option('-c', '--cores', default=1, type=int,
              help='Number of cores to provide to each process')
@click.option('-l', '--login', default="root", type=str,
              help='login used to run the command')
@click.option('-m', '--mpi', default="openmpi", type=str,
              help='MPI type to be used')
@click.option('-v', '--mpiv', default="1.0", type=str,
              help='MPI version to be used')
@click.option('-e', '--eth', default="eth1", type=str,
              help='Ethernet Card Used to do MPI communications')
@click.argument('cmd', nargs=-1, required=False, type=click.UNPROCESSED)
def pcocc_exec(jobid, jobname, rng, index, np, cores, login, mpi, mpiv,  eth, cmd):
    config = load_config(jobid, jobname, default_batchname='pcocc')
    cluster = load_batch_cluster()

    ccmd = AgentCommand( cluster, 0, log=False )

    if rng != "":
        index = rng
    need_to_generate_hostfile = 0
    #Check host-based connectivity
    ips = ccmd.lookup( "-", "vm0" )
    #Now check that everybody knows VM0
    for _, v in ips.items():
        if v == 1:
            need_to_generate_hostfile = 1
    
    #Generate the corresponding host-file
    if need_to_generate_hostfile:
        ips = ccmd.getip( "-", eth )
        hosts = ccmd.hostname( "-" )
        hostfile=""
        for k, _ in hosts.items():
            host = hosts[k]
            ip = " ".join( ips[k].split("#") )
            hostfile += "{0} {1}\n".format(ip, host)
        ccmd.writefile( "-", "/etc/hosts", hostfile, append=True )

    cores_to_run = np * cores

    #Now see how many nodes we need
    free_cores = ccmd.allocfree("-")
    total_cores = 0
    for k,v in free_cores.items():
        iv = int(v)
        free_cores[ k ] = iv
        total_cores += iv

    if total_cores < cores_to_run:
        raise Exception("Cannot run {0} cores on {1} remaining".format(cores_to_run, total_cores))

    #Get alloc id
    current_alloc_id = pcocc_get_exec_id( config, -1 )

    #Now allocate cores
    left_to_alloc = cores_to_run

    vmlist = []

    for k,v in free_cores.items():
        if v == 0:
            continue
        alloc = ccmd.alloc(k, v, "", current_alloc_id )
        for _, vv in alloc.items():
            if vv < 0:
                raise Exception("Failed to allocate on vm ")
        vmlist.append(k)
        left_to_alloc -= v
        if left_to_alloc <= 0:
            break

    #Retrieve user infos
    uid="0"
    gid="0"

    if login != "root":
        userinfo=ccmd.userinfo( vmlist[0], login )
        infosforvm = userinfo[ vmlist[0] ]
        if infosforvm == None:
            raise Exception("Failed to resolve user {0} on {1}".format(login, vmlist[0]))
        uid = infosforvm["uid"]
        gid = infosforvm["gid"]

    mpicmd = []
            #Now time to run the command
    try:
        #We now specialize our command
        if mpi == "openmpi":
            #Generate host list
            host_slot_list=[]
            for i in range(0, len(vmlist)):
                k=vmlist[i]
                if 3 <= int(mpiv[0]):
                    host_slot_list.append( "vm" +  k + ":" + str(free_cores[k]) )
                else:
                    for i in range(0, int(free_cores[k])):
                        host_slot_list.append( "vm" +  k )
            hostlist = ",".join(host_slot_list)
            #Write command
            acmd = ["mpirun",
                      "-np",
                      str(np),
                      #"-cpus-per-proc",
                      #str(cores),
                      "-H",
                      hostlist ] + list(cmd)
        elif (mpi == "pmix"):
             #Generate host list (new OMPI style)
            host_slot_list=[]
            for i in range(0, len(vmlist)):
                k=vmlist[i]
                host_slot_list.append( "vm" +  k + ":" + str(free_cores[k]) )
            hostlist = ",".join(host_slot_list)
            acmd = ["psrvr",
                      "--daemonize",
                      "-H",
                      hostlist,
                      "&&",
                      "prun",
                      "-np",
                      str(np)] + list(cmd)
        elif (mpi == "mpich") or ( mpi == "mpc" ) or ( mpi == "mpcp" ):
            #Generate host list
            host_slot_list=[]
            for i in range(0, len(vmlist)):
                k=vmlist[i]
                host_slot_list.append( "vm" +  k )
            hostlist = ",".join(host_slot_list)
            if mpi == "mpc":
                acmd = ["mpcrun",
                      "-p={0}".format(len(vmlist)),
                      "-n={0}".format(np),
                      "-hosts",
                      hostlist] + list(cmd)
            elif mpi == "mpcp":
                acmd = ["mpcrun",
                      "-p={0}".format(np),
                      "-n={0}".format(np),
                      "-hosts",
                      hostlist] + list(cmd)
            else:
                acmd = ["mpirun",
                      "-hosts",
                      hostlist,
                      "-np",
                      str(np)] + list(cmd)

        else:
            raise Exception("No such MPI implementation {0}".format(mpi))
            
        scmd = " ".join(acmd) 
        mpicmd = ["bash",
                  "-lc",
                  scmd ]
        ret = ccmd.doexec(vmlist[0], current_alloc_id,  mpicmd[0], mpicmd[1:] , uid, gid)

        #Check for errors
        for k in ret:
            if ret[k] == 1:
                raise Exception("Failled to exec on {0}, now releasing alloc".format(k))
        
        #Eventually attach to the output
        detached = local_pcocc_cmd_attach( ccmd,  jobid, jobname )
    except Exception as e:
        ccmd.release("-", current_alloc_id)
        handle_error(e)
    if detached == 0:
        ccmd.release("-", current_alloc_id)

#We add this indirection to be able to call exec from other commands
def local_pcocc_exec(config, ccmd, jobid,
                     jobname, rng, index,
                     cores, cmd, uid, gid,
                     attach=True, g_alloc_id=-1):
    
    if rng != "":
        index = rng

    current_alloc_id = pcocc_get_exec_id( config, g_alloc_id )
    
    try:
        allocs = ccmd.alloc(index, cores, "", current_alloc_id )
        for _, vv in allocs.items():
            if vv < 0:
                raise Exception("Failed to allocate on vm ")
        #Now time to run the command
        ret = ccmd.doexec(index, current_alloc_id,  cmd[0], cmd[1:] , uid, gid)

        #Check for errors
        for k in ret:
            if ret[k] == 1:
                raise Exception("Failled to exec on {0}, now releasing alloc".format(k))
    except Exception as e:
        ccmd.release(index, current_alloc_id)
        handle_error(e)


    detached = 0
    #Now attach to target
    if attach:
        detached = local_pcocc_cmd_attach( ccmd,  jobid, jobname )

    if detached == 0 :
        #If we are here we got EOF
        ccmd.release(index, current_alloc_id)

    return current_alloc_id


@cli.command(name='alloc',
             context_settings=dict(ignore_unknown_options=True),
             short_help="Run a virtual cluster (interactive)")
@click.option('-r', '--restart-ckpt',
              help='Restart cluster from the specified checkpoint',
              metavar='DIR')
@click.option('-E', '--alloc-script', metavar='SCRIPT',
              help='Execute a script on the allocation node')
@click.argument('batch-options', nargs=-1, type=click.UNPROCESSED)
@click.argument('cluster-definition', nargs=1)
@docstring(batch_alloc_doc+alloc_doc)
def pcocc_alloc(restart_ckpt, alloc_script, batch_options, cluster_definition):
    try:
        config = load_config(process_type = ProcessType.OTHER)

        cluster_definition=ascii(cluster_definition)
        cluster = Cluster(cluster_definition)
        batch_options=list(batch_options)
        ckpt_opt = gen_ckpt_opt(restart_ckpt)
        alloc_opt = gen_alloc_script_opt(alloc_script)

        ret = config.batch.alloc(cluster,
                                 batch_options + get_license_opts(cluster) +
                                 ['-n', '%d' % (len(cluster.vms))],
                                  ['pcocc'] + build_verbose_opt() +
                                 [ 'internal', 'launcher',
                                  cluster_definition] + alloc_opt +
                                  ckpt_opt)

        sys.exit(ret)

    except PcoccError as err:
        handle_error(err)

@internal.command(name='launcher',
             context_settings=dict(ignore_unknown_options=True),
             short_help="For internal use")
@click.option('-r', '--restart-ckpt',
              help='Restart cluster from the specified checkpoint')
@click.option('-w', '--wait', is_flag=True,
              help='Do not exit after interactive shell or script exit')
@click.option('-s', '--script',
              help='Run a script in the first VM and exit')
@click.option('-E', '--alloc-script',
              help='Run a script on the allocation node and exit')
@click.argument('cluster-definition', nargs=1)
def pcocc_launcher(restart_ckpt, wait, script, alloc_script, cluster_definition):
    config = load_config(process_type=ProcessType.LAUNCHER)
    batch = config.batch

    cluster_definition = ascii(cluster_definition)
    cluster = Cluster(cluster_definition)

    batch.populate_env()

    if restart_ckpt:
        ckpt_opt=['-r', restart_ckpt]
    else:
        ckpt_opt=[]

    # TODO: provide a way for the user to plugin his own pre-run scripts here
    os.mkdir(os.path.join(batch.cluster_state_dir, 'slurm'))
    for path in os.listdir(helperdir):
        path = os.path.abspath(os.path.join(helperdir, path))
        if os.path.isfile(path) and os.access(path, os.X_OK):
            subprocess.call(path, cwd=batch.cluster_state_dir)

    # TODO: This cmdline should be tunable
    s_pjob = batch.run(cluster,
                       ['-Q', '-X', '--resv-port'],
                       ['pcocc'] +
                       build_verbose_opt() +
                       [ 'internal', 'run'] +
                       ckpt_opt)
    try:
        cluster.wait_host_config()
    except PcoccError as err:
        s_pjob.kill()
        handle_error(err)
    except KeyboardInterrupt:
        s_pjob.kill()
        handle_error(PcoccError('Cluster launch was interrupted'))

    batch.write_key("cluster/user", "definition", cluster_definition)

    term_sigfd = fake_signalfd([signal.SIGTERM, signal.SIGINT])

    monitor_list = [ s_pjob.pid ]

    if script:
        if restart_ckpt:
            s_exec = subprocess.Popen(["pcocc", "exec"])
        else:
            s_exec = subprocess.Popen(["pcocc", "exec", "-s", script])
        if alloc_script:
            s_exec2 = subprocess.Popen(shlex.split(alloc_script))
            monitor_list.append(s_exec2.pid)
    elif alloc_script:
        s_exec = subprocess.Popen(shlex.split(alloc_script))
    else:
        shell_env = os.environ
        shell_env['PROMPT_COMMAND']='echo -n "(pcocc/%d) "' % (batch.batchid)
        shell = os.getenv('SHELL', default='bash')
        s_exec = subprocess.Popen(shell, env=shell_env)

    monitor_list.append(s_exec.pid)

    while True:
        status, pid, _ = wait_or_term_child(monitor_list,
                                            signal.SIGTERM, term_sigfd, 40)
        if pid == s_pjob.pid:
            if status != 0:
                sys.stderr.write("The cluster terminated unexpectedly\n")
            else:
                sys.stderr.write("The cluster has shut down\n")

            # This is racy but helps
            if s_exec.poll() is None:
                s_exec.terminate()

            time.sleep(1)
            if s_exec.poll() is None:
                s_exec.kill()

            sys.exit(status >> 8)
        elif pid == s_exec.pid and not wait:
            sys.stderr.write("Terminating the cluster...\n")
            t = threading.Timer(4000, wait_timeout, [s_pjob])
            t.start()
            s_pjob.send_signal(signal.SIGINT)
            s_pjob.wait()
            t.cancel()
            sys.exit(status >> 8)


def wait_timeout(s_proc):
    try:
        logging.error("Forcibly killing hypervisor processes...\n")
        s_proc.kill()
    except Exception:
        pass

@internal.command(name='pkeyd',
             short_help="For internal use")
def pcocc_pkeyd():
    try:
        config = load_config(process_type=ProcessType.OTHER)
        # Always raise verbosity for pkey daemon
        config.verbose = max(config.verbose, 1)

        config.vnets['ib'].pkey_daemon()
    except PcoccError as err:
        handle_error(err)


# We want to catch some signals and exit ourselves
# so that all 'atexit' cleanup callbacks are executed
def clean_exit(sig, frame):
    if Config().hyp.host_agent:
        Config().hyp.host_agent.signal()
    stop_threads.set()
    logging.info("Exit")
    sys.exit(0)

@internal.command(name='run',
             short_help="For internal use")
@click.option('-r', '--restart-ckpt',
              help='Restart cluster from the specified checkpoint')
def pcocc_run(restart_ckpt):
    signal.signal(signal.SIGINT, clean_exit)
    signal.signal(signal.SIGTERM, clean_exit)

    try:
        load_config(process_type=ProcessType.HYPERVISOR)
        cluster = load_batch_cluster()

        cluster.load_node_resources()

        if restart_ckpt:
            cluster.run(restart_ckpt)
        else:
            cluster.run()

    except PcoccError as err:
        handle_error(err)


@internal.command(name='setup',
             short_help="For internal use")
@click.argument('action', type=click.Choice(['init', 'cleanup', 'create', 'delete']))
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster (only valid for deletion)')
@click.option('--nolock', is_flag=True,
              help='Disable locking')
@click.option('-F', '--force', is_flag=True,
              help='Force job deletion')
def pcocc_setup(action, jobid, nolock, force):
    # Dont load user config, we run as a privileged user
    config = Config()

    if not nolock:
        config.lock_node()

    # Always raise verbosity for setup processes
    config.verbose = max(config.verbose, 1)

    if(action != 'delete' and (jobid or force)):
        raise click.UsageError('this option can only be used with delete')

    if action == 'init':
        config.load(process_type=ProcessType.OTHER)
        config.batch.init_node()
        config.config_node()
    elif action == 'cleanup':
        config.load(process_type=ProcessType.OTHER)
        config.cleanup_node()
    elif action == 'create':
        config.load(process_type=ProcessType.SETUP)
        config.tracker.reclaim(config.batch.list_all_jobs())
        config.batch.create_resources()
        cluster = Cluster(config.batch.cluster_definition,
                          resource_only=True)
        cluster.alloc_node_resources()
    elif action == 'delete':
        config.load(jobid=jobid, process_type=ProcessType.SETUP)
        config.tracker.cleanup_ref(config.batch.batchid)
        config.batch.delete_resources(force)
        cluster = Cluster(config.batch.cluster_definition,
                          resource_only=True)
        cluster.free_node_resources()


    if not nolock:
        config.release_node()

@template.command(name='list',
             short_help="List all templates")
def pcocc_tpl_list():
    tbl = TextTable("%name %desc %res %image")

    tbl.header_labels = {'res': 'resources',
                         'desc': 'description'}

    tbl.col_width = {'image': 100,
                     'desc': 40}

    try:
        config = load_config()

        for name, tpl in config.tpls.iteritems():
            if not tpl.placeholder:
                tbl.append({'name': name,
                            'image': tpl.image,
                            'res': tpl.rset.name,
                            'desc': tpl.description})
    except PcoccError as err:
        handle_error(err)
    print tbl

@template.command(name='show',
             short_help="Display a template")
@click.argument('template', nargs=1)
def pcocc_tpl_show(template):
    try:
        config = load_config()

        try:
            tpl = config.tpls[template]
        except KeyError as err:
            click.secho('Template not found: ' + template, fg='red', err=True)
            sys.exit(-1)

        tpl.display()
    except PcoccError as err:
        handle_error(err)

@template.command(name='export',
             short_help="Export the image associated with a template")
@click.option('-o', '--output', default="./image.qcow2", type=str,
              help='Output file and format (default output.qcow2)')
@click.argument('template', nargs=1)
def pcocc_tpl_export(output, template):
    config = load_config()
    pcocc_tpl_export_local(config, output, template)

#This is an indirection to allow the export
#to be used locally in this file
def pcocc_tpl_export_local(config, output, template):
    output = os.path.abspath(output)

    if os.path.isfile(output):
        click.secho('Output file already exists ' + output, fg='red', err=True)
        sys.exit(-1)

    try:

        try:
            tpl = config.tpls[template]
        except KeyError as err:
            click.secho('Template not found: ' + template, fg='red', err=True)
            sys.exit(-1)

        #Resolve current image
        image, rev = tpl.resolve_image()
        pcocc.Image.convert(image, output, quiet=False)
        click.secho( "'{0} (revision {1})' has been exported to '{2}'".format(
                        template,
                        rev,
                        output),
                    fg='green', err=True)
    except PcoccError as err:
        handle_error(err)


@template.command(name='import',
             short_help="Import a VM image to a new template")
@click.option('-n', '--name', type=str, required=True, default="",
              help='Name of the new template to be created')
@click.option('-i', '--inherit', default="", type=str, required=False,
              help='Name of the existing template to inherit from')
@click.option('-p', '--prefix', default="", type=str, required=False,
              help='Prefix where to store the VM images (directory)')
@click.argument('image', nargs=1, required=False)
def pcocc_tpl_import(name, inherit, prefix,  image):


    if image != None:
        if not os.path.isfile(image):
            click.secho("Input image file does not exist '" + image + "'", fg='red', err=True)
            sys.exit(-1)
        else:
            image = os.path.abspath(image)

    if name == "":
        click.secho("You must provide a name to the new template", fg='red', err=True)
        sys.exit(-1)

    try:
        config = load_config()

        try:
            tpl = config.tpls[name]
            if tpl:
                click.secho("There seems to be an existing template with name '" + name + "'",
                            fg='red',
                            err=True)
                return
        except:
            pass

        if inherit != "":
            try:
                tpl = config.tpls[inherit]
            except KeyError as err:
                click.secho('Parent template not found: ' + inherit, fg='red', err=True)
                sys.exit(-1)
        else:
            #No inherit and no image is incorrect
            if image == "":
                click.secho('If you provide no image you must inherit from a template',
                            fg='red',
                            err=True)
                sys.exit(-1)


        to_store = ""
        if prefix == "":
            to_store = config.user_conf_dir + "/" + name 
        else:
            to_store = prefix + "/" + name

        sys.stderr.write("Creating template directory '{0}'... ".format(to_store))
        try:
            os.mkdir(to_store)
            sys.stderr.write("OK\n")
        except:
            sys.stderr.write("ERROR\n")
            click.secho('Failed to create VM storage directory: ' + to_store, fg='red', err=True)
            sys.exit(-1)

        output_image = to_store + "/image"

        if( (inherit != "") and (image == None) ):
            pcocc_tpl_export_local(config, output_image, inherit)
        else:
            pcocc.Image.convert( image, to_store + "/image", quiet=False)

        tpl_config = "\n\n"
        tpl_config += "#Autogenerated by 'pcocc import' on {0}\n".format(
                            str(datetime.datetime.now()))
        tpl_config += "{0}:\n".format(name)
        tpl_config += "    image: {0}\n".format(to_store)
        if inherit != "":
            tpl_config += "    inherits: {0}\n".format(inherit)
        tpl_config += "#   resource-set: cluster\n"
        tpl_config += "#   user-data: ~/my-cloud-file\n"
        tpl_config += "#   mount-points:\n"
        tpl_config += "#       homes:\n"
        tpl_config += "#           path: pathtomy/home\n"
        tpl_config += "#           readonly: false\n"
        tpl_config += "\n\n"

        template_file = os.path.join(config.user_conf_dir,
                                    'templates.yaml')

        if os.path.isfile(template_file):
            copyfile(template_file, template_file + ".bak")
            click.secho("Saved a backup of 'templates.yaml' in '" + template_file +".bak'",
                        fg='blue',
                        err=True)


        sys.stderr.write("Registering new template '{0}'... ".format(name))
        try:
            with open(template_file, "a") as tplf:
                tplf.write(tpl_config)
            tplf.close()
            sys.stderr.write("OK\n")
        except:
            sys.stderr.write("ERROR\n")
            sys.exit(-1)

        click.secho("Sucessfully imported '{0}' with this configuration:\n{1}"
                    .format(name, tpl_config),
                    fg='green',
                    err=True)

    except PcoccError as err:
        handle_error(err)


@cli.command(name='attach',
             short_help="Attach to standard input and outputs for running programs")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')

def pcocc_cmd_attach( jobid, jobname ):
    load_config(jobid, jobname, default_batchname='pcocc')
    cluster = load_batch_cluster()

    ccmd = AgentCommand( cluster, 0 )
    
    return local_pcocc_cmd_attach( ccmd, jobid, jobname )

#We need this extra indirection to alloc a direct call from exec
def local_pcocc_cmd_attach( ccmd, jobid, jobname ):

    #Broadcast attach
    ccmd.attach("-")

    detached = [0]

    def iterin(deta):
        yield stdio(vmid = -1, stdin="", stderr="",eof=False)
        while 1 :
            l = sys.stdin.readline()
            if not l :
                #Bcast EOF
                yield stdio(vmid = -1, stdin="", stderr="",eof=True)
                ccmd.eof("-")
                return
            if l[0] == chr(27):
                click.secho("You are now detached from program output" ,  fg='blue', err=True)
                click.secho("Use 'pcocc attach' to reattach" ,  fg='blue', err=True)
                #Broadcast detach
                #yield stdio(vmid = -1, id=-1, stdin="", stderr="",eof=True)
                deta[0]=1
                return
            yield stdio(vmid = -1, stdin=l, stderr="",eof=False)

    try:
        outputs = ccmd.exec_stream( iterin(detached) )

        for dat in outputs:
            if dat.stdin != "":
                sys.stdout.write( dat.stdin  )
            if dat.stderr != "":
                sys.stderr.write( dat.stderr)
    except:
        pass

    if detached[0] == 1:
        ccmd.detach("-")

    return detached[0]

@cli.group()
def agent():
    """ Gathers commands related to the pcocc agent """
    pass

def top_display_keys(stats):
    tbl = TextTable("%key %description")

    try:
        for k in stats:
            if k[0:5] != "stat_":
                continue
            tbl.append({'key': k,
                        'description': ""})
    except PcoccError as err:
        handle_error(err)
    print tbl


def top_display_keys_desc( key ):
    #Special cases
    entries = key.split("_")
    if key.startswith("stat_diff_cpu"):
        return click.style("{0} time spent in {1} since last query".format(entries[2], entries[3]),
                           fg="red")
    elif key.startswith("stat_cpu"):
        if "percent" in key:
            return click.style("{0} current load in percent (%)".format(entries[1]),
                           fg="cyan", bold=True)
        else:
            return click.style("{0} time spent in {1} since launch".format(entries[1], entries[2]),
                           fg="red")
        
    elif key.startswith("stat_softirq"):
        irq_names = {"1":"TOTAL",
                     "2":"HI",
                     "3":"TIMER",
                     "4":"NET_TX",
                     "5":"NET_RX",
                     "6":"BLOCK",
                     "7":"BLOCK_IOPOLL",
                     "8":"TASKLET",
                     "9":"SCHED",
                     "10":"HRTIMER",
                     "11":"RCU"}
        return click.style("{0} software interrupts (softirq)".format(irq_names[entries[2]]),
                     fg="magenta")
    elif key.startswith("stat_mem"):
        mem_desc = {
            "stat_mem_nfs_unstable_kb":
            "NFS memory sent to the server and not committed to storage",
            "stat_mem_mapped_kb":
            "Memory used by files being mmapped",
            "stat_mem_vmallocused_kb":
            "Amount of VMALLOC aread used",
            "stat_mem_committed_as_kb":
            "Amount of memory allocated on the system",
            "stat_mem_writebacktmp_kb":
            "Memory used by FUSE for write-back",
            "stat_mem_pagetables_kb":
            "Memory dedicated to the lowest level of the page-table",
            "stat_mem_active_file__kb":
            "Pagecage memory used and not reclaimed",
            "stat_mem_swapfree_kb":
            "Remaining SWAP space available",
            "stat_mem_anonhugepages_kb":
            "Non-file memory mapped in huge-pages",
            "stat_mem_buffers_kb":
            "Memory currently used in buffers",
            "stat_mem_memtotal_kb":
            "Memory available on the system",
            "stat_mem_shmem_kb":
            "Memory used for shared-memory",
            "stat_mem_swaptotal_kb":
            "Memory available in the SWAP",
            "stat_mem_slab_kb":
            "Memory for in-kernel data-structures",
            "stat_mem_hugepagesize_kb":
            "The size of a HugePage",
            "stat_mem_dirty_kb":
            "Memory to be written to Disk",
            "stat_mem_unevictable_kb":
            "Memory that cannot be SWAPPED out",
            "stat_mem_memfree_kb":
            "Physical Memory free on the system",
            "stat_mem_vmallocchunk_kb":
            "Largest continuous free block of VMALLOC",
            "stat_mem_directmap2m_kb":
            "Memory mapped to HugePages",
            "stat_mem_swapcached_kb":
            "Memory both in mem and SWAP",
            "stat_mem_bounce_kb":
            "Memory for block-device bounce buffs",
            "stat_mem_memavailable_kb":
            "Estimate of how much memory is available",
            "stat_mem_writeback_kb":
            "Memory being written back to Disk",
            "stat_mem_hardwarecorrupted_kb":
            "Memory identified as not working",
            "stat_mem_sunreclaim_kb":
            "Part of SLAB which cannot be reclaimed",
            "stat_mem_commitlimit_kb":
            "Based on overcommit maximum memory available on system",
            "stat_mem_sreclaimable_kb":
            "Part of the SLAB which can be reclaimed",
            "stat_mem_vmalloctotal_kb":
            "Total size of the VMALLOC memory area",
            "stat_mem_directmap4k_kb":
            "Amount of memory mapped in standard 4k pages",
            "stat_mem_inactive_kb":
            "Memory reclaimable without performance impact",
            "stat_mem_inactive_file__kb":
            "Pagecache memory available for reclaim",
            "stat_mem_directmap1g_kb":
            "Memory mapped in 1GB pages",
            "stat_mem_active_kb":
            "Memory in-use",
            "stat_mem_anonpages_kb":
            "Non-File pages in page-table",
            "stat_mem_inactive_anon__kb":
            "Anonymous memory which is Swappable",
            "stat_mem_active_anon__kb":
            "Anonymous memory in-use",
            "stat_mem_kernelstack_kb":
            "Memory used by the kernel stack",
            "stat_mem_mlocked_kb":
            "Pages locked using mlock",
            "stat_mem_cached_kb":
            "Memory in the pagecache"
        }

        try:
            return click.style("{0}".format(mem_desc[key]),
                                fg="green", bold=True)
        except:
            return  click.style("???",
                                fg="green", bold=True)
    return ""


def top_display_keys(stats):
    tbl = TextTable("%key %description")

    try:
        for k in stats:
            if k[0:5] != "stat_":
                continue
            tbl.append({'key': k,
                        'description': top_display_keys_desc(k)})
    except PcoccError as err:
        handle_error(err)
    print tbl


def top_graph_value(ccmd, index,  key, interupt=False):
    """This generates a graph for a given probe key

    Arguments:
        ccmd {ClusterCommand} -- The object used to send commands
        index {Str/Int} -- Index of the VMs to measure
        key {Str} -- The key to be measured over time

    Keyword Arguments:
        interupt {bool} -- If the interrups have to be followed (default: {False})

    Raises:
        Exception -- Failed to retrieve graph data
        Exception -- The key was not found
    """
    if len(key.split(",")) != 1:
        raise Exception("You may only provide a single key to -g")

    stats = ccmd.vmstat(0, interupt)
    if len(stats) == 0:
        raise Exception("Failed to retrieve graph data")
    tdata = stats['0']
    try:
        tdata[key]
    except:
        raise Exception("No such key use 'pcocc top -l'")

    # Now enter the reading loop
    start = int(time.time())

    titles = [None] * ccmd.vm_count()
    acc = [None] * ccmd.vm_count()

    g = pcocc.Plot.GnuPlot()

    while True:
        stats = {}
        stats = ccmd.vmstat(index, interupt)
        now = int(time.time()) - start
        for k in stats:
            titles[int(k)] = "vm" + k

            if acc[int(k)] is None:
                acc[int(k)] = []

            if isinstance( stats[k], dict) == False:
                raise PcoccError("Could not retrieve vmstat data")

            serie = acc[int(k)]
            serie.append([now, stats[k][key]])
        g.plot(acc, titles, xlabel="time", style="lp")
        time.sleep(1)

def top_display_values(ccmd, index, key, interupt=False):

    stats = ccmd.vmstat(index, interupt)

    keys=key.strip().split(",")

    for k in keys:
        k = k.strip()

    col = "%vm"

    for i in range(0, len(keys)):
        col = col + " %v"+chr(97 + i)

    tbl = TextTable(col)
    tbl.color = True

    tbl.header_labels = {}
    for i in range(0, len(keys)):
        tbl.header_labels["v"+chr(97+i)] = keys[i]


    try:
        for k in stats:
            entry = {"vm":str(k)}
            for i in range(0, len(keys)):
                e = "v"+chr( 97 + i)
                entry[e] = stats[str(k)][keys[i]]
            tbl.append(entry)
    except PcoccError as err:
        handle_error(err)
    print tbl


def top_display_report(ccmd):
    """This implements the basic information
    display for the "pcocc top" command

    Arguments:
        ccmd {ClusterCommand} -- Handler to send commands
    """
    # Gather Data
    stats = ccmd.vmstat("-")

    # Gather Data
    acc_cpu = [[]]
    acc_memory = [[]]

    for i in range(0, ccmd.vm_count()):
        try:
            cpup = stats[ str(i) ]["stat_cpu_percent"]
            memf = stats[ str(i) ]["stat_mem_memfree_kb"]
            memt = stats[ str(i) ]["stat_mem_memtotal_kb"]
            # Convert
            cpup = round(float(cpup)*100.0, 2)
            memf = round(float(memf), 2)
            memt = round(float(memt), 2)
            memp = ((memt-memf) * 100.0) / memt
            # Add to graph
            acc_cpu[0].append([i, cpup])
            acc_memory[0].append([i, memp])
        except:
            pass

    # Plot Load with impulses
    click.secho('\nCurrent CPU Load in %',
                fg='red', bold=True)
    g = pcocc.Plot.GnuPlot(ratio=5)
    g.plot(acc_cpu, ["CPU Load (%)"], xlabel="VM ID", style="steps")
    # Plot Memory with impulses
    click.secho('Current Memory Usage in %',
                fg='red', bold=True)
    g = pcocc.Plot.GnuPlot(ratio=5)
    g.plot(acc_memory, ["Memory Usage (%)"], xlabel="VM ID", style="steps")

    # Now Generate a summary table

    col = "%vm %usedmem %totalmem %mempct %cpuload"

    tbl = TextTable(col)
    tbl.color = True

    tbl.header_labels["vm"] = "VM ID"
    tbl.header_labels["usedmem"] = "Used Memory (GB)"
    tbl.header_labels["totalmem"] = "Total Memory (GB)"
    tbl.header_labels["mempct"] = "Memory Used (%)"
    tbl.header_labels["cpuload"] = "CPU Used (%)"

    for i in range(0, ccmd.vm_count()):
        cpup = float(stats[ str(i) ]["stat_cpu_percent"])
        memf = float(stats[str(i)]["stat_mem_memfree_kb"]) / (1024*1024)
        memt = float(stats[str(i)]["stat_mem_memtotal_kb"]) / (1024*1024)
        memused = memt - memf
        memp = ((memt-memf) * 100.0) / memt
        entry = {
            "vm": str(i),
            "usedmem": str(round(memused, 2)),
            "totalmem": str(round(memt, 2)),
            "mempct": str(round(memp, 2)),
            "cpuload": str(round(cpup*100.0, 2))
        }

        tbl.append(entry)
    
    print tbl



@agent.command(name='top',
             short_help='Monitor vm state')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-w', '--rng', default="", type=str,
              help='Range of VMids on which the command should be executed')
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
@click.option('-r', '--interupt',  is_flag=True, default=False,
              help='If the stats have to include the interupts')
@click.option('-l', '--lst', is_flag=True, default=False,
              help='Use to display available probes')
@click.option('-g', '--graph', default="", type=str,
              help='Graph a given key over time')
@click.option('-k', '--key', default="", type=str,
              help='Display a given probe over VMs')
def pcocc_top(jobid, jobname, rng, index,  interupt, lst, graph, key):
    """Display statistics from VMs
    """
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        ccmd = AgentCommand(cluster, 0)

        if rng != "":
            index = rng

        if lst:
            stats = ccmd.vmstat(0, interupt)
            if len(stats) != 1:
                raise Exception("Failed to retrieve keys")
            top_display_keys(stats['0'])
        elif graph != "":
            top_graph_value(ccmd, index, graph, interupt)
        elif key != "":
            top_display_values(ccmd, index, key, interupt)
        else:
            top_display_report(ccmd)
    except PcoccError as err:
        handle_error(err)


@agent.group()
def commands():
    """ Issue commands to the pcocc agent """
    pass


@commands.command(name='hostname',
             short_help="Get Hostname from VMs")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-w', '--rng', default="", type=str,
              help='Range of VMids on which the command should be executed')
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
def pcocc_cmd_hostname( jobid, jobname, rng, index ):
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        ccmd = AgentCommand(cluster)

        if rng != "":
            index = rng
        ret = ccmd.hostname(index)

        print(AgentCommandPrinter("hostname", ret))
    except PcoccError as err:
        handle_error(err)

@commands.command(name='hello',
             short_help="Ping event to check if the agent is alive (returns UNIX TS)")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-w', '--rng', default="", type=str,
              help='Range of VMids on which the command should be executed')
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
def pcocc_cmd_hello( jobid, jobname, rng, index ):
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        ccmd = AgentCommand(cluster)

        if rng != "":
            index = rng

        ret = ccmd.hello(index)

        print(AgentCommandPrinter("hello", ret ))
    except PcoccError as err:
        handle_error(err)   



@commands.command(name='freeze',
             short_help="Suspend events from the pcocc agent")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-w', '--rng', default="", type=str,
              help='Range of VMids on which the command should be executed')
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
def pcocc_cmd_freeze( jobid, jobname, rng, index ):
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        ccmd = AgentCommand(cluster)

        if rng != "":
            index = rng

        ret = ccmd.freeze(index)

        print(AgentCommandPrinter("freeze", ret ))
    except PcoccError as err:
        handle_error(err)

@commands.command(name='thaw',
             short_help="Resume events from the pcocc agent")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-w', '--rng', default="", type=str,
              help='Range of VMids on which the command should be executed')
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
def pcocc_cmd_thaw( jobid, jobname, rng, index ):
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        ccmd = AgentCommand(cluster)

        if rng != "":
            index = rng

        ret = ccmd.thaw(index)

        print(AgentCommandPrinter("thaw", ret ))
    except PcoccError as err:
        handle_error(err)

@commands.command(name='mkdir',
             short_help="Create a directory on the target vms with a mode")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-w', '--rng', default="", type=str,
              help='Range of VMids on which the command should be executed')
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
@click.option('-p', '--path', type=str, required=True,
              help='Hierarchy of paths to be created')
@click.option('-m', '--mode', default=777, type=int,
              help='Mode of the directory to be created')
def pcocc_cmd_mkdir( jobid, jobname, rng, index, path, mode ):
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        ccmd = AgentCommand(cluster)

        if rng != "":
            index = rng

        ret = ccmd.mkdir(index, path, mode)

        print(AgentCommandPrinter("mkdir", ret ))
    except PcoccError as err:
        handle_error(err)

@commands.command(name='ip',
             short_help="Get ip for target iface on target vms")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-w', '--rng', default="", type=str,
              help='Range of VMids on which the command should be executed')
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
@click.option('-e', '--eth', type=str, default="eth0",
              help='Device to be queried (default eth0)')
def pcocc_cmd_getip( jobid, jobname, rng, index, eth ):
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        ccmd = AgentCommand(cluster)

        if rng != "":
            index = rng

        ret = ccmd.getip(index, eth)

        print(AgentCommandPrinter("getip", ret ))
    except PcoccError as err:
        handle_error(err)



@commands.command(name='chmod',
             short_help="Change rights for a file on target vms")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-w', '--rng', default="", type=str,
              help='Range of VMids on which the command should be executed')
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
@click.option('-p', '--path', type=str, required=True,
              help='Hierarchy of paths to be created')
@click.option('-m', '--mode', default=777, type=int,
              help='Mode of the directory to be created')
def pcocc_cmd_chmod( jobid, jobname, rng, index, path, mode ):
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        ccmd = AgentCommand(cluster)

        if rng != "":
            index = rng

        ret = ccmd.chmod(index, path, mode)

        print(AgentCommandPrinter("chmod", ret ))
    except PcoccError as err:
        handle_error(err)

@commands.command(name='exec',
             short_help="Run a command on VMs")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-w', '--rng', default="", type=str,
              help='Range of VMids on which the command should be executed')
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
@click.option('-l', '--alloc', type=int, required=True,
              help='Target global alloc ID')
@click.option('-u', '--uid', type=int, default=0,
              help='UID to run the progam with')
@click.option('-g', '--gid', type=int, default=0,
              help='GID to run the progam with')
@click.argument('cmd', nargs=-1, required=True, type=click.UNPROCESSED)
def pcocc_cmd_exec( jobid, jobname, rng, index, alloc, cmd, uid, gid ):
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        ccmd = AgentCommand(cluster)

        if rng != "":
            index = rng

        ret = ccmd.doexec(index, alloc,  cmd[0], cmd[1:], uid=uid, gid=gid)
        print(AgentCommandPrinter("exec", ret ))
    except PcoccError as err:
        handle_error(err)


@commands.command(name='alloc',
             short_help="Allocate resources on given vms")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-w', '--rng', default="", type=str,
              help='Range of VMids on which the command should be executed')
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
@click.option('-c', '--count', type=int, required=True,
              help='Number of cores to allocate')
@click.option('-d', '--desc', default="None", type=str,
              help='Description of the allocation')
@click.option('-g', '--gad', type=int, required=True,
              help='ID of the global allocation')
def pcocc_cmd_alloc( jobid, jobname, rng, index, count, desc, gad ):
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        ccmd = AgentCommand(cluster)

        if rng != "":
            index = rng

        ret = ccmd.alloc(index, count, desc, gad)

        print(AgentCommandPrinter("alloc", ret ))
    except PcoccError as err:
        handle_error(err)

@commands.command(name='release',
             short_help="Release resources on given vms")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-w', '--rng', default="", type=str,
              help='Range of VMids on which the command should be executed')
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
@click.option('-g', '--gad', default=-1, type=int,
              help='Global alloc ID to be targetted')
def pcocc_cmd_release( jobid, jobname, rng, index,  gad ):
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        ccmd = AgentCommand( cluster, 0 )

        if rng != "":
            index = rng
        
        ret = ccmd.release(index, gad)

        print(AgentCommandPrinter("release", ret ))
    except PcoccError as err:
        handle_error(err)


@commands.command(name='allocfree',
             short_help="List number of CPU free on VMs")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-w', '--rng', default="", type=str,
              help='Range of VMids on which the command should be executed')
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
def pcocc_cmd_allocfree( jobid, jobname, rng, index ):
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        ccmd = AgentCommand(cluster)

        if rng != "":
            index = rng

        ret = ccmd.allocfree(index)

        print(AgentCommandPrinter("allocfree", ret ))
    except PcoccError as err:
        handle_error(err)

@commands.command(name='vmstat',
             short_help="Get Statistics from VMs")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-w', '--rng', default="", type=str,
              help='Range of VMids on which the command should be executed')
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
@click.option('-r', '--interupt',  is_flag=True, default=False,
              help='If the stats have to include the interupts')
def pcocc_cmd_allocfree( jobid, jobname, rng, index, interupt ):
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        ccmd = AgentCommand(cluster)

        if rng != "":
            index = rng

        ret = ccmd.vmstat(index, interupt)

        print(AgentCommandPrinter("vmstat", ret ))
    except PcoccError as err:
        handle_error(err)
