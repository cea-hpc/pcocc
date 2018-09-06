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
import pwd
import logging
import pcocc
import random
import stat

from pcocc.Tbon import UserCA
from pcocc.scripts import click
from pcocc import PcoccError, Config, Cluster, Hypervisor
from pcocc.Backports import subprocess_check_output
from pcocc.Batch import ProcessType
from pcocc.Misc import fake_signalfd, wait_or_term_child, stop_threads
from pcocc.scripts.Shine.TextTable import TextTable
from pcocc.Agent import AgentCommand
from pcocc.Templates import TEMPLATE_IMAGE_TYPE
from pcocc import agent_pb2

from ClusterShell.NodeSet import RangeSet, RangeSetParseError

helperdir = '/etc/pcocc/helpers'

def handle_error(err):
    """ Print exception with stack trace if in debug mode """
    # pylint: disable=E0704
    click.secho(str(err), fg='red', err=True)
    if Config().debug:
        raise
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

def load_batch_cluster():
    definition = Config().batch.read_key('cluster/user', 'definition',
                                               blocking=True)
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
              help='Create a new image instead of a new revision')
@click.option('-s', '--safe',
              help='Wait indefinitely for the Qemu agent to freeze filesystems',
              is_flag=True)
@click.option('--full',
              help='Save a full image in a standalone layer',
              default=False,
              is_flag=True)
@click.argument('vm', nargs=1, default='vm0')
def pcocc_save(jobid, jobname, dest, vm, safe, full):
    """Save the disk of a VM

    By default the output file only contains the differences between
    the current state of the disk and the template from which the VM
    was instantiated.

    \b
    Example usage:
           pcocc save vm1

    """
    try:
        config  = load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()
        index   = vm_name_to_index(vm)
        vm = cluster.vms[index]

        if  vm.image_type == TEMPLATE_IMAGE_TYPE.NONE:
            click.secho('Template is not based on a CoW image',
                        fg='red', err=True)
            sys.exit(-1)

        if vm.image_type == TEMPLATE_IMAGE_TYPE.REPO:
            if dest:
                # For incremental save into a new image, start by making sure
                # all the incremental data blobs are in the destination repo
                if not full:
                    config.images.copy_image(vm.image, dest)
                else:
                    # We dont allow silent overwrite so check if the
                    # destination exists now instead of erroring out later
                    # (in the non-full case, the copy catches it early)
                    config.images.check_overwrite(dest)

            else:
                dest = vm.image

            save_path = config.images.prepare_vm_import(dest)
        else:
            if dest:
                validate_save_dir(dest, False)
                save_path = os.path.join(dest, 'image')
                full = True
            else:
                save_path = os.path.join(vm.image_dir,
                                         'image-rev%d'%(vm.revision + 1))

        if safe:
            freeze_opt = Hypervisor.VM_FREEZE_OPT.YES
        else:
            freeze_opt = Hypervisor.VM_FREEZE_OPT.TRY

        click.echo("Saving image...")
        vm.save(save_path, full, freeze_opt)

        if vm.image_type == TEMPLATE_IMAGE_TYPE.REPO:
            if not full:
                new_image = config.images.add_revision_layer(dest, save_path)
            else:
                new_image = config.images.add_revision_full("vm", dest, save_path)
            click.secho('vm{0} disk succesfully saved to {1} revision {2}'.format(
                            index,
                            dest,
                            new_image['revision']
                        ),
                        fg='green')
        else:
            click.secho('vm{0} disk succesfully saved to {1}'.format(
                index,
                save_path),
                        fg='green')

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

        dest_dir = validate_save_dir(ckpt_dir, force)

        # Try to freeze
        click.secho('Preparing checkpoint')
        ret = AgentCommand.freeze(cluster, CLIRangeSet("all", cluster), timeout=5)
        for _, _ in ret.iterate():
            pass

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


def gen_user_data_opt(user_data):
    if user_data:
        return ['--user-data', user_data]
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
@click.option('--user-data', type=click.Path(exists=True),
              help='Override the user-data property of the templates')
@click.argument('batch-options', nargs=-1, type=click.UNPROCESSED)
@click.argument('cluster-definition', nargs=1)
@docstring(batch_alloc_doc+batch_doc)
def pcocc_batch(restart_ckpt, batch_script, host_script, user_data, batch_options,
                cluster_definition):

    try:
        config = load_config(process_type=ProcessType.OTHER)

        cluster_definition = ascii(cluster_definition)
        cluster = Cluster(cluster_definition)
        batch_options=list(batch_options)
        ckpt_opt = gen_ckpt_opt(restart_ckpt)
        user_data_opt = gen_user_data_opt(user_data)

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
PYTHONUNBUFFERED=true pcocc %s internal launcher %s %s %s %s &
wait
rm "$TEMP_BATCH_SCRIPT" 2>/dev/null
rm "$TEMP_HOST_SCRIPT" 2>/dev/null
""" % (' '.join(build_verbose_opt()), ' '.join(launcher_opt),
       ' '.join(ckpt_opt), ' '.join(user_data_opt), cluster_definition))

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


@cli.command(name='alloc',
             context_settings=dict(ignore_unknown_options=True),
             short_help="Run a virtual cluster (interactive)")
@click.option('-r', '--restart-ckpt',
              help='Restart cluster from the specified checkpoint',
              metavar='DIR')
@click.option('-E', '--alloc-script', metavar='SCRIPT',
              help='Execute a script on the allocation node')
@click.option('--user-data', type=click.Path(exists=True),
              help='Override the user-data property of the templates')
@click.argument('batch-options', nargs=-1, type=click.UNPROCESSED)
@click.argument('cluster-definition', nargs=1)
@docstring(batch_alloc_doc+alloc_doc)
def pcocc_alloc(restart_ckpt, alloc_script, user_data, batch_options, cluster_definition):
    try:
        config = load_config(process_type = ProcessType.OTHER)

        cluster_definition=ascii(cluster_definition)
        cluster = Cluster(cluster_definition)
        batch_options=list(batch_options)
        ckpt_opt = gen_ckpt_opt(restart_ckpt)
        alloc_opt = gen_alloc_script_opt(alloc_script)
        user_data_opt = gen_user_data_opt(user_data)
        ret = config.batch.alloc(cluster,
                                 batch_options + get_license_opts(cluster) +
                                 ['-n', '%d' % (len(cluster.vms))],
                                  ['pcocc'] + build_verbose_opt() +
                                 [ 'internal', 'launcher'] + alloc_opt + user_data_opt +
                                 ckpt_opt + [cluster_definition])

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
@click.option('--user-data', type=click.Path(exists=True),
              help='Override the user-data property of the templates')
@click.argument('cluster-definition', nargs=1)
def pcocc_launcher(restart_ckpt, wait, script, alloc_script, user_data, cluster_definition):
    config = load_config(process_type=ProcessType.LAUNCHER)
    batch = config.batch

    logging.debug("Starting pcocc launcher")

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

    logging.debug("Launching hypervisors")
    # TODO: This cmdline should be tunable
    s_pjob = batch.run(cluster,
                       ['-Q', '-X', '--resv-port'],
                       ['pcocc'] +
                       build_verbose_opt() +
                       [ 'internal', 'run'] + gen_user_data_opt(user_data) +
                       ckpt_opt)
    try:
        cluster.wait_host_config()
    except PcoccError as err:
        s_pjob.kill()
        handle_error(err)
    except KeyboardInterrupt:
        s_pjob.kill()
        handle_error(PcoccError('Cluster launch was interrupted'))

    logging.debug("Hypervisors are running")


    batch.write_key("cluster/user", "definition", cluster_definition)

    batch.write_key("cluster/user", "ca_cert", UserCA.new().dump_yaml())

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
            t = threading.Timer(40, wait_timeout, [s_pjob])
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
    stop_threads.set()
    sys.exit(0)

@internal.command(name='run',
             short_help="For internal use")
@click.option('-r', '--restart-ckpt',
              help='Restart cluster from the specified checkpoint')
@click.option('--user-data', type=click.Path(exists=True),
              help='Override the user-data property of the templates')
def pcocc_internal_run(restart_ckpt, user_data):
    signal.signal(signal.SIGINT, clean_exit)
    signal.signal(signal.SIGTERM, clean_exit)

    try:
        load_config(process_type=ProcessType.HYPERVISOR)
        cluster = load_batch_cluster()

        cluster.load_node_resources()

        if restart_ckpt:
            cluster.run(ckpt_dir=restart_ckpt)
        else:
            cluster.run(user_data=user_data)

    except PcoccError as err:
        handle_error(err)

@cli.command(name='exec',
             short_help="Execute commands through the guest agent",
             context_settings=dict(ignore_unknown_options=True,
                                   allow_interspersed_args=False))
@click.option('-i', '--index', default=0, type=int,
              help='Index of the vm on which the command should be executed')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-u', '--user',
              help='User id to use to execute the command')
@click.option('-s', '--script', is_flag=True,
              help='Cmd is a shell script to be copied to /tmp and executed in place')
@click.argument('cmd', nargs=-1, required=False, type=click.UNPROCESSED)
def pcocc_exec(index, jobid, jobname, user, script, cmd):
    """Execute commands through the guest agent

       For this to work, a pcocc agent must be started in the
       guest. This is mostly available for internal use where we do
       not want to rely on a network connexion / ssh server.
    """
    try:
        load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

        if not user:
            user = pwd.getpwuid(os.getuid()).pw_name

        cmd = list(cmd)

        if script:
            basename = os.path.basename(cmd[0])
            cluster.vms[index].put_file(cmd[0],
                                    '/tmp/%s' % basename)
            cmd = ['bash', '/tmp/%s' % basename]

        ret = cluster.exec_cmd([index], cmd, user)
        sys.exit(max(ret))

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
        for t in 'user', 'system':
            click.secho("{} templates:".format(t.capitalize()),
                        fg='blue', bold=True)

            for name, tpl in sorted(config.tpls.iteritems()):
                if tpl.source_type == t:
                    tbl.append({'name': name,
                                'image': tpl.image,
                                'res': tpl.rset.name,
                    'desc': tpl.description})
            print tbl
            print
            tbl.purge()

    except PcoccError as err:
        handle_error(err)


@template.command(name='show',
             short_help="Show details for a template")
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

class CLIRangeSet(RangeSet):
    def __init__(self, indices=None, cluster=None):
        try:
            if indices == "all":
                super(CLIRangeSet, self).__init__("0-{}".format(cluster.vm_count() - 1))
            elif indices is not None:
                super(CLIRangeSet, self).__init__(ascii(indices))
            else:
                super(CLIRangeSet, self).__init__()
        except RangeSetParseError as e:
            raise PcoccError(str(e))

def per_cluster_cli(allows_user):
    """Decorator for CLI commands which act on a running cluster The
       function arguments must contain jobid, jobname and cluster, and
       optionally user if allows_user is True
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            if allows_user:
                load_config(kwargs["jobid"], kwargs["jobname"], default_batchname='pcocc',
                            batchuser=kwargs["user"])
            else:
                load_config(kwargs["jobid"], kwargs["jobname"], default_batchname='pcocc')

            kwargs["cluster"] = load_batch_cluster()
            try:
                return func(*args, **kwargs)
            except PcoccError as err:
                handle_error(err)
        return wrapper
    return decorator


def writefile(cluster, indices, source, destination):
    try:
        with open(source) as f:
            source_data = f.read()
        perms = os.stat(source)[stat.ST_MODE]
    except IOError as err:
        raise PcoccError("unable to read source file for copy: {}".format(err))

    start_time = time.time()
    ret = AgentCommand.writefile(cluster, indices,
                                 path=destination, data=source_data,
                                 perms=perms, append=False)
    for k, e in ret.iterate():
        click.secho("vm{}: {}".format(k, e), fg='red', err=True)

    click.secho("{} VMs answered in {:.2f}s".format(
        len(indices), time.time() - start_time),
                fg='green', err=True)

    ret.raise_errors()

def display_vmagent_error(index, err):
    click.secho("vm{}: {}".format(index, err), fg='red', err=True)

def parallel_execve(cluster, indices, cmd, env, user, display_errors=True):
    # Launch tasks on rangeset
    exec_id = random.randint(0, 2**63-1)
    ret = AgentCommand.execve(cluster, indices, filename=cmd[0],
                              exec_id=exec_id, args=cmd[1:],
                              env=env, username=user)

    # Check if some VMs had errors during launch
    for index, err in ret.iterate():
        if isinstance(err, PcoccError):
            if display_errors:
                display_vmagent_error(index, err)
        else:
            raise err

    return ret, exec_id

def filter_vms(indices, result):
    return indices.difference(RangeSet(result.errors.keys()))

def collect_output_bg(result_iterator, display_results,
                      display_errors):
    def collector_th():
        exit_status = 0
        try:
            for key, msg in result_iterator.iterate(yield_results=display_results,
                                                    keep_results=(not display_results)):
                if isinstance(msg, agent_pb2.IOMessage):
                    if msg.kind == agent_pb2.IOMessage.stdout:
                        sys.stdout.write(msg.data)
                    else:
                        sys.stderr.write(msg.data)
                elif isinstance(msg, agent_pb2.ExitStatus):
                    logging.info("Received Exit status")
                    if msg.status != 0 and display_errors:
                        display_vmagent_error(key, "exited with exit code {}".format(msg.status))
                    if msg.status > exit_status:
                        exit_status = msg.status
                elif isinstance(msg, agent_pb2.DetachResult):
                    logging.info("Agent asked us to detach")
                else:
                    # We ignore other message types for now
                    logging.debug("Ignoring message of type %s from %d", type(msg), key)

            logging.debug("Last message received from output stream: "
                          "signalling main thread")
        except Exception as err:
            if display_errors:
                click.secho(str(err), fg='red', err=True)
            if not exit_status:
                exit_status = -1

        #Make sure the RPC is terminated in case we exited early due
        #to some error
        result_iterator.cancel()
        result_iterator.exit_status = exit_status

    output_th = threading.Thread(None, collector_th, None)
    output_th.start()
    return output_th

def multiprocess_call(cluster, indices, cmd, env, user):
    # Launch tasks on rangeset
    exec_ret, exec_id = parallel_execve(cluster, indices, cmd, env, user)

    # Continue only on VMs on which the exec succeeded
    good_indices = filter_vms(indices, exec_ret)
    if not good_indices:
        return -1

    return multiprocess_attach(cluster, good_indices, exec_id, exec_ret.errors)

def multiprocess_attach(cluster, indices, exec_id, exec_errors = None):
    # Launch streaming "attach" RPC
    attach_ret = AgentCommand.attach_stdin(cluster, indices, exec_id)
    # Collect in background thread
    output_th = collect_output_bg(attach_ret, display_results=True,
                                display_errors=True)
    # Wait for collection output (use a pseudo infinite timeout to not block signals)
    output_th.join(2**32-1)
    logging.info("Output thread joined\n")
    exit_code = attach_ret.exit_status

    if  exec_errors and not exit_code:
        return -1
    else:
        return exit_code

@cli.group(hidden=True)
def agent():
    """ Manage VMs through the pcocc agent """
    pass

@agent.command(name='run',
             short_help="Execute commands in VMs",
             context_settings=dict(ignore_unknown_options=True,
                                   allow_interspersed_args=False))
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-u', '--user',
              help='User name to use to execute the command')
@click.option('-i', '--indices', default="all", type=str,
              help='Rangeset of VM indices on which the command should be executed')
@click.option('-s', '--script', is_flag=True,
              help='Cmd is a shell script to be copied to /tmp and executed in place')
@click.option('-m', '--mirror-env', is_flag=True,
              help='Propagate local environment variables')
@click.argument('cmd', nargs=-1, required=True, type=click.UNPROCESSED)
@per_cluster_cli(False)
def pcocc_run(jobid, jobname, user, indices, script, mirror_env, cmd, cluster):
    #FIXME: handle pty option once we have agent support
    vms = CLIRangeSet(indices, cluster)

    if not user:
        user = pwd.getpwuid(os.getuid()).pw_name

    cmd = list(cmd)
    if script:
        basename = os.path.basename(cmd[0])
        dest = os.path.join('/tmp', basename)
        writefile(cluster, vms, cmd[0], dest)
        cmd = ['bash', dest]

    env = []
    if mirror_env:
        for e, v in os.environ.iteritems():
            env.append("{}={}".format(e,v))

    exit_code = multiprocess_call(cluster, vms, cmd, env, user)

    sys.exit(exit_code)

@agent.command(name='attach',
             short_help="Attach to a running command",
             context_settings=dict(ignore_unknown_options=True,
                                   allow_interspersed_args=False))
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-i', '--indices', default="all", type=str,
              help='Rangeset of VM indices on which the command should be executed')
@click.argument('exec_id', nargs=1, type=int, required=True)
@per_cluster_cli(False)
def pcocc_attach(jobid, jobname, indices, exec_id, cluster):
    vms = CLIRangeSet(indices, cluster)
    exit_code = multiprocess_attach(cluster, vms, exec_id)
    sys.exit(exit_code)


@agent.command(name='writefile', short_help="Copy a file in VMs")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-i', '--indices', default="all", type=str,
              help='Rangeset of VM indices on which the command should be executed')
@click.argument('source', nargs=1, type=str)
@click.argument('dest', nargs=1, type=str)
@per_cluster_cli(False)
def pcocc_writefile(jobid, jobname, indices, source, dest, cluster):
    rangeset = CLIRangeSet(indices, cluster)
    writefile(cluster, rangeset, source, dest)

@agent.command(name='freeze',
             short_help="Freeze the VM agents")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-i', '--indices', default="all", type=str,
              help='Rangeset of VM indices on which the command should be executed')
@per_cluster_cli(False)
def pcocc_freeze(jobid, jobname, indices, cluster):
    rangeset = CLIRangeSet(indices, cluster)
    start_time = time.time()

    ret = AgentCommand.freeze(cluster, rangeset)
    for k, e in ret.iterate():
        display_vmagent_error(k, e)

    if not ret.errors:
        click.secho("{} VMs answered in {:.2f}s".format(
            len(rangeset), time.time() - start_time),
                    fg='green', err=True)

    sys.exit(-int(bool(ret.errors)))


@agent.command(name='listexec',
             short_help="List running commands")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-i', '--indices', default="all", type=str,
              help='Rangeset of VM indices on which the command should be executed')
@per_cluster_cli(False)
def pcocc_listexec(jobid, jobname, indices, cluster):
    rangeset = CLIRangeSet(indices, cluster)

    ret = AgentCommand.listexec(cluster, rangeset)
    ret.iterate_all()
    click.echo(ret)

@agent.command(name='thaw',
             short_help="Thaw the VM agents")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-i', '--indices', default="all", type=str,
              help='Rangeset of VM indices on which the command should be executed')
@per_cluster_cli(False)
def pcocc_thaw(jobid, jobname, indices, cluster):
    rangeset = CLIRangeSet(indices, cluster)
    start_time = time.time()

    ret = AgentCommand.thaw(cluster, rangeset)
    for k, e in ret.iterate():
        display_vmagent_error(k, e)

    if not ret.errors:
        click.secho("{} VMs answered in {:.2f}s".format(
            len(rangeset), time.time() - start_time),
                    fg='green', err=True)

    sys.exit(-int(bool(ret.errors)))

@agent.command(name='ping',
             short_help="Ping the VM agents")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-i', '--indices', default="all", type=str,
              help='Rangeset of VM indices on which the command should be executed')
@per_cluster_cli(False)
def pcocc_ping(jobid, jobname, indices, cluster):
    rangeset = CLIRangeSet(indices, cluster)
    start_time = time.time()

    ret = AgentCommand.hello(cluster, rangeset)
    for k, e in ret.iterate():
        display_vmagent_error(k, e)

    if not ret.errors:
        click.secho("{} VMs answered in {:.2f}s".format(
            len(rangeset), time.time() - start_time),
                    fg='green', err=True)

    # Return -1 if there is any error
    sys.exit(-int(bool(ret.errors)))

@cli.group()
def image():
    """ List and manage images """
    pass

@image.group(name="repo")
def img_repo():
    """ List and manage image repositories """
    pass

def print_repolist(rlist):
    tbl = TextTable("%name %path %writable")

    for r in rlist:
        if os.path.exists(r.path):
            writable = str(bool(os.access(r.path, os.W_OK)))
        else:
            writable = 'N/A'
        tbl.append({'name': r.name,
                    'path': r.path,
                    'writable': writable})

    print tbl

@img_repo.command(name='list',
             short_help="List pcocc image repositories")
def pcocc_image_repo_list():
    try:
        config = load_config(None, None, "")

        l = config.images.list_repos()
        print_repolist(l)
    except PcoccError as err:
        handle_error(err)

@image.command(name='import',
             short_help="Import an image to a repository")
@click.option('-t', '--fmt', type=str,
              help='Force source image format')
@click.argument('kind', nargs=1, type=str)
@click.argument('source', nargs=1, type=str)
@click.argument('dest', nargs=1, type=str)
def pcocc_image_import(kind, fmt, source, dest):
    """Import the source image file to an image in the destination repository.

    The only supported image KIND is "vm"

    Images in repositories are specified with URIs of the form
    [REPO:]IMAGE[@REVISION].

    The destination image name must not already be used in the destination
    repository and the revision is ignored since the import operation creates
    the first revision of a new image.
    """

    if kind not in ["vm"]:
        raise PcoccError("Unsupported image kind {0}")

    try:
        load_config(None, None, "")
        Config().images.import_image(kind, source, dest, fmt)
    except PcoccError as err:
        handle_error(err)

@image.command(name='delete',
             short_help="Delete an image from a repository")
@click.argument('image', nargs=1, type=str)
def pcocc_image_delete(image):
    """Delete an image from a repository

    Images in repositories are specified with URIs of the form
    [REPO:]IMAGE[@REVISION]

    If a revision is specified, only the specified revision is deleted,
    otherwise all revisions of the image are deleted.
    """
    try:
        load_config(None, None, "")
        Config().images.delete_image(image)
    except PcoccError as err:
        handle_error(err)

@image.command(name='export',
             short_help="Export an image from a repository")
@click.option('-t', '--fmt', type=str,
              help='Force destination image format')
@click.argument('source', nargs=1, type=str)
@click.argument('dest', nargs=1, type=str)
def pcocc_image_export(fmt, source, dest):
    """Export the source image from a repository to the destination file.

    Images in repositories are specified with URIs of the form
    [REPO:]IMAGE[@REVISION]
    """

    try:
        load_config(None, None, "")
        Config().images.export_image(source, dest, fmt)
    except PcoccError as err:
        handle_error(err)

@image.command(name='copy',
               short_help="Copy an image from one repository to another")
@click.argument('source', nargs=1, type=str)
@click.argument('dest', nargs=1, type=str)
def pcocc_image_copy(source, dest):
    """Copy an image from a repository to another image in a
    repository.

    Images in repositories are specified with URIs of the form
    [REPO:]IMAGE[@REVISION]

    The destination image name must not already be used in the destination
    repository and the destination revision is ignored since a copy operation
    creates the first revision of a new image.
    """
    try:
        load_config(None, None, "")
        click.secho("Copying image ...")
        Config().images.copy_image(source, dest)
        click.secho("Image successufly copied", fg="green")
    except PcoccError as err:
        handle_error(err)

@image.command(name='show',
             short_help="Show details for an image")
@click.argument('image', nargs=1, type=str)
def pcocc_image_show(image):
    """Show details for an image

    Images in repositories are specified with URIs of the form
    [REPO:]IMAGE[@REVISION]
    """
    try:
        load_config(None, None, "")
        meta, _ = Config().images.get_image(image)
        ts = time.localtime(meta["timestamp"])
        str_time = time.strftime('%Y-%m-%d %H:%M:%S', ts)

        print("------------------------------")
        print("%5s %24s" % ("Repo:", meta["repo"]))
        print("%5s %24s" % ("Name:", meta["name"]))
        print("%s %24s" % ("Type:", "Virtual Machine (qcow2)"))
        print("------------------------------")
        print("%5s %24s" % ("URI: ", meta["repo"] + ":" +
                            meta["name"] + "@" + str(meta["revision"])))
        print("%s %22s" % ("Layers:", str(len(meta["data_blobs"]))))
        print("------------------------------")
        print("%7s %22s" % ("Owner: ", meta["owner"]))
        print("%7s %21s" % ("Date:   ", str_time))
        print("------------------------------")

        revisions = Config().images.image_revisions(image)
        print("")
        tbl = TextTable("%rev %size %date")
        tbl.header_labels = {'rev': 'Revision',
                             'size' : 'Size',
                             'date': 'Creation Date'}

        for rev in revisions:
            meta, data = Config().images.get_image(image, rev)
            ts = time.localtime(meta["timestamp"])
            str_time = time.strftime('%Y-%m-%d %H:%M:%S', ts)

            tbl.append({'rev': str(rev),
                        'size': formatted_file_size(data),
                        'date': str_time})

        print tbl
    except PcoccError as err:
        handle_error(err)

def print_image_list(images):
    tbl = TextTable("%name %type %revision %repo %owner %date")
    for img in sorted(images.itervalues(), key=lambda i:i[i.keys()[0]]["name"]):
        rev = max(img.keys())
        ts = time.localtime(img[rev]["timestamp"])
        str_time = time.strftime('%Y-%m-%d %H:%M:%S', ts)
        repo = img[rev]["repo"]

        tbl.append({'name'     : img[rev]["name"],
                    'type'     : img[rev]["kind"],
                    'revision' : str(rev),
                    'repo'     : repo,
                    'owner'    : img[rev]["owner"],
                    "date"     : str_time})

    print tbl

@image.command(name='list',
             short_help="List images in repositories")
@click.option('-R', '--repo', type=str,
              help='Restrict image list to a repository')
@click.argument('regex', nargs=1, type=str, default="")
def pcocc_image_list(regex, repo):
    """List images in configured repositories.

    If REGEX is provided, only images whose name match the provided regular
    expression are shown.
    """

    try:
        config = load_config(None, None, "")
        if repo:
            repo_list = [repo]
        else:
            repo_list = [r.name for r in config.images.list_repos()]

        for repo in repo_list:
            img_list = config.images.find(regex, repo)
            if img_list:
                click.secho("{} images:".format(repo.capitalize()),
                            fg='blue', bold=True)
                print_image_list(img_list)
                print

    except PcoccError as err:

        handle_error(err)


def formatted_file_size(path):
    size = os.path.getsize(path)
    if size < 1024:
        return "{0} Bytes".format(size)
    elif size < 1024*1024:
        return "{0} KB".format(float(size)//1024.0)
    elif size < 1024*1024*1024:
        return "{0} MB".format(float(size)//(1024.0*1024.0))
    elif size < 1024*1024*1024*1024:
        return "{0} GB".format(float(size)//(1024.0*1024.0*1024.0))


@cli.command(name='ps',
             short_help='List current pcocc jobs')
@click.option('-a', '--all', 'allusers',
              is_flag=True, default=False,
              help='List jobs for all users')
@click.option('-u', '--user', default = "",
              help='List jobs of the specified user')
def pcocc_ps(user, allusers):
    """List current pcocc jobs
    """
    try:
        config = load_config()

        if not user:
            user = pwd.getpwuid(os.getuid()).pw_name

        if allusers:
            # all superses --user
            user = None

        joblist = config.batch.get_job_details(user)

        tbl = TextTable("%id %name %user %partition %nodes %duration %timelimit")
        for j in joblist:
            tbl.append({'id': str(j["batchid"]),
                        'user': j["user"],
                        'partition': j["partition"],
                        'nodes': str(j["node_count"]),
                        'name': j["jobname"],
                        'duration': j["exectime"],
                        'timelimit': j["timelimit"]
                    })

        print tbl

    except PcoccError as err:
        handle_error(err)
