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
import fcntl
import time
import threading
import click
import pwd
import logging
import pcocc
from pcocc import PcoccError, Config, Cluster, Hypervisor
from pcocc.Backports import total_seconds, subprocess_check_output
from pcocc.Batch import ProcessType
from pcocc.Misc import fake_signalfd, wait_or_term_child, stop_threads
from Shine.TextTable import TextTable

helperdir = '/etc/pcocc/helpers'

def handle_error(err):
    """ Print exception with stack trace if in debug mode """

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

def ascii (text):
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

    p.communicate()

@cli.command(name='help', short_help='Display man pages for a given subcommand')
@click.argument('command', default='pcocc')
def help(command):
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
    host_port = pcocc.Networks.VNATNetwork.get_rnat_host_port(index, port)
    if host_port:
        return host_port
    else:
        sys.stderr.write('Error: port {0} is not reverse NATed\n'.format(
            port))
        sys.exit(-1)

def find_vm_ssh_opt(opts, regex, s_opts, v_opts, first_arg_only=True):
    """Parse ssh/scp arguments to find the remote vm hostname"""
    skip = False
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
        config = load_config(jobid, jobname, default_batchname='pcocc',
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

       This requires the VM to have its ssh port reverse NAT'ed to the host in its NAT network configuration.

       \b
       Example usage:
           pcocc scp -r dir bar@vm1:

    """
    try:
        config = load_config(jobid, jobname, default_batchname='pcocc',
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
        config = load_config(jobid, jobname, default_batchname='pcocc',
                             batchuser=user)
        cluster = load_batch_cluster()

        nc_opts = list(nc_opts)
        rgxp = r'^vm(\d+)$'
        if len(nc_opts) > 0 and re.match(rgxp, nc_opts[-1]):
            host_opts = [nc_opts[-1]]
            vm_index = int(re.match(rgxp, nc_opts[-1]).group(1))
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
    match = re.match('vm(\d+)$', name)
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
        config = load_config(jobid, jobname, default_batchname='pcocc')
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
        config = load_config(jobid, jobname, default_batchname='pcocc')
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
        config = load_config(jobid, jobname, default_batchname='pcocc')
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
        config = load_config(jobid, jobname, default_batchname='pcocc')
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
        config = load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()

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
                break;

            # Exit if Ctrl-C is pressed repeatedly
            if sys.stdin in rdy[0]:
                buffer = os.read(self_stdin, 1024)
                if struct.unpack('b', buffer[0:1])[0] == 3:
                    if total_seconds(datetime.datetime.now() - last_int) > 2:
                        last_int = datetime.datetime.now()
                        int_count = 1
                    else:
                        int_count += 1

                    if int_count == 3:
                        print '\nDetaching ...'
                        break

                s_ctl.stdin.write(buffer)

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
cat <<\PCOCC_BATCH_SCRIPT_EOF >> "${TEMP_BATCH_SCRIPT}"
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
cat <<\PCOCC_HOST_SCRIPT_EOF >> "${TEMP_HOST_SCRIPT}"
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
    resource_definition = cluster.resource_definition
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
    except Exception as e:
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
def pcocc_run(restart_ckpt):
    signal.signal(signal.SIGINT, clean_exit)
    signal.signal(signal.SIGTERM, clean_exit)

    try:
        config = load_config(process_type=ProcessType.HYPERVISOR)
        cluster = load_batch_cluster()

        cluster.load_node_resources()

        if restart_ckpt:
            cluster.run(restart_ckpt)
        else:
            cluster.run()

    except PcoccError as err:
        handle_error(err)

@cli.command(name='exec',
             short_help="Execute commands through the guest agent")
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
@click.argument('cmd', nargs=-1, required=False)
def pcocc_exec(index, jobid, jobname, user, script, cmd):
    """Execute commands through the guest agent

       For this to work, a pcocc agent must be started in the
       guest. This is mostly available for internal use where we do
       not want to rely on a network connexion / ssh server.
    """
    try:
        config = load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()
        batch = config.batch

        if not user:
            user = pwd.getpwuid(os.getuid()).pw_name

        cmd = list(cmd)

        if script:
            basename = os.path.basename(cmd[0])
            cluster.vms[0].put_file(cmd[0],
                                    '/tmp/%s' % basename)
            cmd = ['bash', '/tmp/%s' % basename]

        ret = cluster.exec_cmd([index], cmd, user)
        sys.exit(max(ret))

    except PcoccError as err:
        handle_error(err)


class Lock:
    """Simple flock based Lock"""
    def __init__(self, filename):
        self.filename = filename
        self.handle = open(filename, 'w')

    def acquire(self):
        fcntl.flock(self.handle, fcntl.LOCK_EX)

    def release(self):
        fcntl.flock(self.handle, fcntl.LOCK_UN)

    def __del__(self):
        self.handle.close()

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

    lock = Lock("/tmp/.pcocc_setup.lock")
    if not nolock:
        lock.acquire()

    # Always raise verbosity for setup processes
    config.verbose = max(config.verbose, 1)

    if(action != 'delete' and (jobid or force)):
        raise click.UsageError('this option can only be used with delete')

    if action == 'init':
        config.load(process_type=ProcessType.OTHER)
        Config().batch.init_node()
        config.config_node()
    elif action == 'cleanup':
        config.load(process_type=ProcessType.OTHER)
        config.cleanup_node()
    elif action == 'create':
        config.load(process_type=ProcessType.SETUP)
        Config().batch.create_resources()
        cluster = Cluster(config.batch.cluster_definition,
                          resource_only=True)
        cluster.alloc_node_resources()
    elif action == 'delete':
        config.load(jobid=jobid, process_type=ProcessType.SETUP)
        Config().batch.delete_resources(force)
        cluster = Cluster(config.batch.cluster_definition,
                          resource_only=True)
        cluster.free_node_resources()

    if not nolock:
        lock.release()


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
