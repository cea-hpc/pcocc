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
import json
import click

from pcocc.Tbon import UserCA
from pcocc import PcoccError, Config, Cluster, Hypervisor, Docker
from pcocc.Batch import ProcessType
from pcocc.Misc import fake_signalfd, wait_or_term_child, stop_threads,CHILD_EXIT
from pcocc.scripts.Shine.TextTable import TextTable
from pcocc.Agent import AgentCommand, DEFAULT_AGENT_TIMEOUT
from pcocc.Templates import DRIVE_IMAGE_TYPE
from pcocc.Image import ImageType
import pcocc.Container
import pcocc.Run as Run

from ClusterShell.NodeSet import NodeSet, RangeSet
from ClusterShell.NodeSet import RangeSetParseError, NodeSetParseError


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
    restore_terminal(terminal_settings)
    try:
        spr.kill()
    except OSError as err:
        # Subprocess already killed
        if err.errno == errno.ESRCH:
            pass
        else:
            raise

def docstring(docstr, sep="\n"):
    """ Decorator: Append to a function's docstring.
    """
    def _decorator(func):
        if func.__doc__ is None:
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


def load_batch_cluster(resource_only=False):
    val, index = Config().batch.read_key_index('cluster', 'destroyed')
    if val:
        logging.info("Load batch: stale cluster dir, waiting for cleanup")
        Config().batch.wait_key_index('cluster', 'destroyed', index)


    definition = Config().batch.read_key('cluster/user', 'definition',
                                         blocking=True)
    if resource_only:
        resource_definition = Config().batch.read_key('cluster/user', 'resource_definition')
        if resource_definition:
            definition = resource_definition
        else:
            resource_only=False

    return Cluster(definition, resource_only=resource_only)


def per_cluster_cli(allows_user):
    """Decorator for CLI commands which act on a running cluster The
       function arguments must contain jobid, jobname and cluster, and
       optionally user if allows_user is True
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            if allows_user:
                load_config(kwargs["jobid"],
                            kwargs["jobname"],
                            default_batchname='pcocc',
                            batchuser=kwargs["user"])
            else:
                load_config(kwargs["jobid"],
                            kwargs["jobname"],
                            default_batchname='pcocc')

            kwargs["cluster"] = load_batch_cluster()
            try:
                return func(*args, **kwargs)
            except PcoccError as err:
                handle_error(err)
        return wrapper
    return decorator


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
    except (subprocess.CalledProcessError, OSError):
        raise click.UsageError("No such help topic '" + page + "'\n"
                               "       use 'pcocc help' to list topics")

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    p.communicate()
    signal.signal(signal.SIGINT, signal.SIG_DFL)


@cli.command(name='help', short_help='Display man pages'
                                     ' for a given subcommand')
@click.argument('command', default='pcocc')
def pcocc_help(command):
    display_manpage(command)


@cli.group(hidden=True)
def internal():
    """ For internal use """


@cli.group()
def template():
    """ List and manage templates """


DEFAULT_SSH_OPTS = ['-o', 'UserKnownHostsFile=/dev/null', '-o',
                    'LogLevel=ERROR', '-o', 'StrictHostKeyChecking=no']


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
        if opt in ["-" + o for o in v_opts]:
            skip = True
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
@click.option('-p', '--print_opts', is_flag=True,
              help='Print remote-viewer options')
@click.argument('vm', nargs=1, default='vm0')
def pcocc_display(jobid, jobname, print_opts, vm):
    """Display the graphical output of a VM

    This requires the VM to have a remote display method
    defined in it's template.

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
                    print(f.read())
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
@click.option('-p', '--port', type=int, default=22,
              help='Port to connect to on the remote host')
@click.argument('ssh-opts', nargs=-1, type=click.UNPROCESSED)
def pcocc_ssh(jobid, jobname, user, ssh_opts, port):
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

        cluster = load_batch_cluster(resource_only=True)

        ssh_opts = list(ssh_opts)
        arg_index, match = find_vm_ssh_opt(ssh_opts, r'(^|@)vm(\d+)',
                                           '1246AaCfgKkMNnqsTtVvXxYy',
                                           'bcDeFiLlmOopRSw')

        vm_index = int(match.group(2))
        remote_host = cluster.vms[vm_index].get_host()
        ssh_port = find_vm_rnat_port(cluster, vm_index, port=port)
        ssh_opts[arg_index] = ssh_opts[arg_index].replace("vm%d"%vm_index,
                                                          remote_host)
        s_ctl = subprocess.Popen(['ssh', '-p', '%s' % (ssh_port)] +
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

        cluster = load_batch_cluster(resource_only=True)

        scp_opts = list(scp_opts)
        arg_index, match = find_vm_ssh_opt(scp_opts, r'(^|@)vm(\d+):',
                                           '12346BCpqrv', 'cfiloPS', False)

        vm_index = int(match.group(2))
        remote_host = cluster.vms[vm_index].get_host()
        scp_opts[arg_index] = scp_opts[arg_index].replace("vm%d:" % vm_index,
                                                          remote_host + ':')
        ssh_port = find_vm_rnat_port(cluster, vm_index)
        s_ctl = subprocess.Popen(
            ['scp', '-P', ssh_port] + DEFAULT_SSH_OPTS + scp_opts)
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
        cluster = load_batch_cluster(resource_only=True)

        nc_opts = list(nc_opts)
        rgxp = r'^vm(\d+)$'
        if len(nc_opts) > 0 and re.match(rgxp, nc_opts[-1]):
            host_opts = [nc_opts[-1]]
            vm_index = int(re.match(rgxp, host_opts[-1]).group(1))
            vm_port = 31337
            last_opt = max(0, len(nc_opts) - 1)
        elif len(nc_opts) > 1 and re.match(rgxp, nc_opts[-2]):
            vm_index = int(re.match(rgxp, nc_opts[-2]).group(1))
            try:
                vm_port = int(nc_opts[-1])
            except ValueError:
                raise click.UsageError(
                    'Invalid port number {0}.'.format(nc_opts[-1]))
            last_opt = max(0, len(nc_opts) - 2)
        else:
            raise click.UsageError("Unable to parse vm name")

        remote_host = cluster.vms[vm_index].get_host()

        nc_port = find_vm_rnat_port(cluster, vm_index, vm_port)
        s_ctl = subprocess.Popen(['nc'] +
                                 nc_opts[0:last_opt] +
                                 [remote_host, nc_port])
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
        raise click.UsageError('invalid destination'
                               ' directory: ' + err.strerror)

    return dest_dir


def vm_set_to_index(vmset):
    try:
        nodeset = NodeSet(vmset)
    except NodeSetParseError as e:
        raise PcoccError(str(e))

    res = []
    for name in nodeset:
        res.append(vm_name_to_index(name))

    return RangeSet(res)


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
              help='Wait indefinitely for the Qemu'
                   ' agent to freeze filesystems',
              is_flag=True)
@click.option('--full',
              help='Save a full image in a standalone layer',
              default=False,
              is_flag=True)
@click.argument('vm', nargs=1, default='vm0')
def pcocc_save(jobid, jobname, dest, vm, safe, full):
    """Save the main drive of a VM

    By default the output file only contains the differences between
    the current state of the disk and the template from which the VM
    was instantiated.

    \b
    Example usage:
           pcocc save vm1

    """
    try:
        config = load_config(jobid, jobname, default_batchname='pcocc')
        cluster = load_batch_cluster()
        index = vm_name_to_index(vm)
        vm = cluster.vms[index]

        drives = vm.block_drives
        if not drives:
            raise PcoccError('VM has no drive to save')

        drive = drives[0]

        # For now we only support full backups for persistent drives
        if drive['persistent']:
            full = True

        new_dest = False
        # Explicit destination specified: store in a new image
        if dest:
            new_dest = True
            if drive['type'] == DRIVE_IMAGE_TYPE.REPO:
                # If there was no previous repository image
                # force full new image
                if drive['image'] is None:
                    full = True

                # We dont allow silent overwrite so check if the
                # destination exists now instead of erroring out later
                config.images.check_overwrite(dest)
            elif drive['type'] == DRIVE_IMAGE_TYPE.DIR:
                validate_save_dir(dest, False)
                # In directory mode, new images are always full iamges
                full = True
        else:
            # Store in the current image
            dest = drive['image']

        if not dest:
            raise PcoccError('No default target image to save VM main drive. '
                             'Please use specify one with --dest')

        if drive['type'] == DRIVE_IMAGE_TYPE.REPO:
            save_path = config.images.prepare_vm_import(dest)
        elif drive['type'] == DRIVE_IMAGE_TYPE.DIR:
            if full:
                save_path = os.path.join(dest, 'image')
            else:
                save_path = os.path.join(vm.image_dir,
                                         'image-rev%d' % (vm.revision + 1))

        if safe:
            freeze_opt = Hypervisor.VM_FREEZE_OPT.YES
        else:
            freeze_opt = Hypervisor.VM_FREEZE_OPT.TRY

        if full:
            mode = Hypervisor.DRIVE_SAVE_MODE.FULL
        else:
            mode = Hypervisor.DRIVE_SAVE_MODE.TOP

        ret = save_drive(cluster,
                         [vm.rank],
                         ['drive0'],
                         [save_path],
                         mode,
                         freeze_opt,
                         False,
                         False,
                         'Updating repository...')

        ret.raise_errors()

        if drive['type'] == DRIVE_IMAGE_TYPE.REPO:
            if not full:
                if new_dest:
                    # For incremental save into a new image,
                    # start by copying the previous
                    # image to the new one so that we can add
                    # the new layer on top later
                    config.images.copy_image(drive['image'], dest)

                new_image = config.images.add_revision_layer(dest, save_path)
            else:
                new_image = config.images.add_revision_full(ImageType.vm,
                                                            dest,
                                                            save_path)
            click.secho('vm{0} disk succesfully'
                        ' saved to {1} revision {2}'.format(
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
@click.argument('vms', nargs=1, default='vm0')
@per_cluster_cli(False)
def pcocc_reset(jobid, jobname,  vms, cluster):
    """Reset a VM

    The effect is similar to the reset button on a physical machine.

    \b
    Example usage:
           pcocc reset vm1

    """
    try:
        index = vm_set_to_index(vms)
        start_time = time.time()

        ret = AgentCommand.reset(cluster, index)
        for k, e in ret.iterate():
            display_vmagent_error(k, e)

        if not ret.errors:
            click.secho("{} VMs reset in {:.2f}s".format(
                len(index), time.time() - start_time),
                fg='green', err=True)

        # Return -1 if there is any error
        sys.exit(-int(bool(ret.errors)))

    except PcoccError as err:
        handle_error(err)


@cli.command(name='monitor-cmd',
             short_help='Send a command to the monitor')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.argument('vms', nargs=1, default='vm0')
@click.argument('cmd', nargs=-1)
@per_cluster_cli(False)
def pcocc_monitor_cmd(jobid, jobname,  vms, cmd, cluster):
    """Send a command to the monitor

    \b
    Example usage:
           pcocc monitor-cmd vm0 info registers

    """
    try:
        index = vm_set_to_index(vms)

        ret = AgentCommand.monitor_cmd(cluster, index, cmd=cmd)
        for k, e in ret.iterate():
            display_vmagent_error(k, e)

        print(ret)

        # Return -1 if there is any error
        sys.exit(-int(bool(ret.errors)))

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
@per_cluster_cli(False)
def pcocc_dump(jobid, jobname,  vm, dumpfile, cluster):
    """Dump VM memory to a file

    The file is saved as ELF and includes the guest's memory
    mapping. It can be processed with crash or gdb.

    \b
    Example usage:
           pcocc dump vm1 output.bin

    """
    try:
        index = vm_set_to_index(vm)
        start_time = time.time()

        dumpfile = os.path.abspath(dumpfile)

        ret = AgentCommand.dump(cluster, index, path=dumpfile)

        last = 0
        with click.progressbar(length=100, label='Dumping memory') as bar:
            for k, r in ret.iterate(yield_results=True, yield_errors=True):
                if isinstance(r, Exception):
                    click.echo('\nvm{0}: {1}'.format(k, r), err=True)
                    continue

                upd = int(100 * r.pct) - last
                last = last + upd
                if upd:
                    bar.update(upd)

        ret.raise_errors()

        click.secho("{} VMs dumped in {:.2f}s".format(
            len(index), time.time() - start_time),
            fg='green', err=True)

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
        click.secho('Preparing checkpoint...')
        ret = AgentCommand.freeze(cluster,
                                  CLIRangeSet("all", cluster),
                                  timeout=5)
        ret.iterate_all()

        save_drive_list = []
        for vm in cluster.vms:
            if vm.image_type != DRIVE_IMAGE_TYPE.NONE:
                save_drive_list.append(vm.rank)

        if save_drive_list:
            ret = save_drive(cluster,
                             RangeSet(save_drive_list),
                             ['drive0'],
                             [os.path.join(dest_dir, 'disk')],
                             Hypervisor.DRIVE_SAVE_MODE.TOP,
                             Hypervisor.VM_FREEZE_OPT.NO,
                             True,
                             True,
                             'Drive checkpoint complete')

            ret.raise_errors()

        ret = ckpt_memory(cluster, CLIRangeSet("all", cluster),
                          os.path.join(dest_dir, 'memory'), True,
                          'Memory checkpoint complete')
        ret.raise_errors()

        click.secho('Cluster state succesfully checkpointed '
                    'to %s' % (dest_dir), fg='green')

    except PcoccError as err:
        handle_error(err)


def make_raw_terminal(self_stdin):
    # Raw terminal
    old = termios.tcgetattr(self_stdin)
    new = list(old)
    new[3] = new[3] & ~termios.ECHO & ~termios.ISIG & ~termios.ICANON
    termios.tcsetattr(self_stdin, termios.TCSANOW,
                      new)
    return old


def restore_terminal(old):
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW,
                      old)


def ckpt_memory(cluster, vm_indices, path, use_suffix, final_message):
    ret = AgentCommand.checkpoint(cluster,
                                  RangeSet(vm_indices),
                                  path=path,
                                  vm_suffix_path=use_suffix)

    running_count = len(vm_indices)

    vm_tx = [0] * len(cluster.vms)
    vm_tot = [0] * len(cluster.vms)

    show_eta = False
    show_percent = False
    item_show_func = (lambda x: ('({:.2f}MB / {:.2f}MB)'.format(
        float(x[0]) / 1024 / 1024,
        float(x[1]) / 1024 / 1024)) if x
        else '')

    with click.progressbar(length=1000000,
                           label='Stopping VMs',
                           show_eta=show_eta,
                           show_percent=show_percent,
                           bar_template='%(label)s %(info)s',
                           item_show_func=item_show_func) as bar:

        for k, r in ret.iterate(yield_results=True, yield_errors=True):
            if isinstance(r, Exception):
                click.echo('\nvm{0}: {1}'.format(k, r), err=True)
                continue

            if r.status == 'active':
                if running_count > 1:
                    vm_str = ' ({} VMs)'.format(running_count)
                else:
                    vm_str = ''

                bar.label = 'Copying memory{}...'.format(vm_str)
                vm_tx[k] = (r.total - r.remaining)
                vm_tot[k] = r.total

            if r.status == 'complete':
                running_count = running_count - 1

                vm_tx[k] = vm_tot[k]
                if running_count == 0:
                    bar.label = final_message

            bar.current_item = (sum(vm_tx), sum(vm_tot), running_count)
            bar.update(1)

    return ret


def save_drive(cluster, vm_indices, drives, paths, save_mode, freeze_mode,
               use_suffix, stop_vm, final_message):

    ret = AgentCommand.save(cluster,
                            RangeSet(vm_indices),
                            drives=drives,
                            paths=paths,
                            mode=save_mode,
                            freeze=freeze_mode,
                            vm_suffix_path=use_suffix)

    if save_mode == Hypervisor.DRIVE_SAVE_MODE.FULL and len(vm_indices) == 1:
        show_eta = True
        show_percent = True
        item_show_func = (lambda x: ('({:.2f}MB / {:.2f}MB)'.format(
            float(x[0]) / 1024 / 1024,
            float(x[1]) / 1024 / 1024)) if x
            else '')
    else:
        show_eta = False
        show_percent = False
        item_show_func = (lambda x: ('({:.2f}MB)'.format(
            float(x[0]) / 1024 / 1024)) if x
            else '')

    running_count = len(vm_indices)
    vm_tx = [0] * len(cluster.vms)

    if freeze_mode == Hypervisor.VM_FREEZE_OPT.NO:
        initial_message = 'Initiating copy...'
        freeze_count = 0
    else:
        initial_message = 'Freezing drives...'
        freeze_count = len(vm_indices)

    if stop_vm:
        stop_count = len(vm_indices)
    else:
        stop_count = 0

    with click.progressbar(length=1000000,
                           label=initial_message,
                           show_eta=show_eta,
                           show_percent=show_percent,
                           bar_template='%(label)s %(info)s',
                           item_show_func=item_show_func) as bar:

        for k, r in ret.iterate(yield_results=True, yield_errors=True):
            if isinstance(r, Exception):
                click.echo('\nvm{0}: {1}'.format(k, r), err=True)
                continue

            if r.status == 'freeze-failed':
                click.secho('\nvm{0}: failed to freeze filesystems, '
                            'data could be corrupted if filesystems'
                            ' are in use'.format(k),
                            fg='red',
                            err=True)
                freeze_count = freeze_count - 1
                bar.update(1)
                continue

            if r.status == 'frozen':
                freeze_count = freeze_count - 1
                bar.update(1)
                continue

            if r.status == 'vm-stopped':
                stop_count = stop_count - 1
                if freeze_count == 0:
                    bar.label = 'Stopping VMs...'
                bar.update(1)
                continue

            if r.status == 'running':
                if show_percent:
                    upd = int(1000000. * float(r.offset - vm_tx[k]) /
                              float(r.len))
                else:
                    upd = 1

                vm_tx[k] = r.offset

                if running_count > 1:
                    drv_str = ' ({} drives)'.format(running_count)
                else:
                    drv_str = ''
                if stop_count == 0:
                    bar.label = 'Copying drive data{}...'.format(drv_str)
                    bar.current_item = (sum(vm_tx), r.len, running_count)

                bar.update(upd)

            elif r.status == 'complete':
                running_count = running_count - 1
                bar.current_item = (sum(vm_tx), sum(vm_tx),
                                    running_count)
                if running_count == 0:
                    bar.label = final_message
                    bar.update(1000000)

    return ret


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
        cluster = load_batch_cluster(resource_only=True)

        index = vm_name_to_index(vm)
        vm = cluster.vms[index]
        vm.wait_start()
        remote_host = vm.get_host()

        if log:
            try:
                # FIXME: reading the whole log at once will not
                # work for large logs
                subprocess.check_call(shlex.split(
                    'ssh -t {0} less {1}'.format(
                        remote_host,
                        config.batch.get_vm_state_path(
                            vm.rank,
                            'qemu_console_log'))))
            except Exception:
                click.secho("Unable to read console log",
                            fg='red', err=True)
                raise
            sys.exit(0)

        socket_path = config.batch.get_vm_state_path(vm.rank,
                                                     'pcocc_console_socket')
        self_stdin = sys.stdin.fileno()

        # Raw terminal
        old = Run.make_raw_terminal(self_stdin)

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
                    if (datetime.datetime.now() -
                            last_int).total_seconds() > 2:
                        last_int = datetime.datetime.now()
                        int_count = 1
                    else:
                        int_count += 1

                    if int_count == 3:
                        print('\nDetaching ...')
                        break

                s_ctl.stdin.write(buf)
                s_ctl.stdin.flush()

        # Restore terminal now to let user interrupt the wait if needed
        Run.restore_terminal(old)
        s_ctl.terminate()
        s_ctl.wait()

    except PcoccError as err:
        handle_error(err)


batch_alloc_doc = """ Instantiate or restore a virtual cluster.
A cluster definition is expressed as a list of templates and
counts e.g.: tpl1:6,tpl2:2 will instantiate a cluster with 6
VMs from template tpl1 and 2 VMs from template tpl2

Batch options will be passed on to the underlying
batch manager.
"""

alloc_doc = """
In interactive mode (pcocc alloc), a shell is launched which allows to
easily interact with the created cluster as all pcocc commands
launched from the shell will implicitely target this cluster. The
virtual cluster will also be automatically terminated when the shell
exits.

\b
Example usage:
       pcocc alloc -c 4 --qos=test tpl1:6,tpl2:2
"""

batch_doc = """
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
@docstring(batch_alloc_doc + batch_doc)
def pcocc_batch(restart_ckpt,
                batch_script,
                host_script,
                user_data,
                batch_options,
                cluster_definition):
    # Hook to enable calling from other functions
    return _pcocc_batch(restart_ckpt,
                        batch_script,
                        host_script,
                        user_data,
                        batch_options,
                        cluster_definition)


def _pcocc_batch(restart_ckpt,
                 batch_script,
                 host_script,
                 user_data,
                 batch_options,
                 cluster_definition,
                 docker=False,
                 mirror_user=False,
                 config=None):
    try:
        # pcocc docker alloc may load the config beforehand
        if config is None:
            config = load_config(process_type=ProcessType.OTHER)

        cluster = Cluster(cluster_definition)
        batch_options = list(batch_options)
        ckpt_opt = gen_ckpt_opt(restart_ckpt)
        docker_opt = ["--docker"] if docker else []
        mirror_opt = ["-m"] if mirror_user else []
        user_data_opt = gen_user_data_opt(user_data)

        (wrpfile, wrpname) = tempfile.mkstemp()
        wrpfile = os.fdopen(wrpfile, 'w')

        if batch_script or host_script:
            launcher_opt = []
        else:
            launcher_opt = ['-w']

        wrpfile.write("""#!/bin/bash
#SBATCH -o pcocc_%j.out
#SBATCH -e pcocc_%j.err
""")
        if batch_script:
            launcher_opt += ['-s', '"$TEMP_BATCH_SCRIPT"']
            wrpfile.write("""
TEMP_BATCH_SCRIPT="/tmp/pcocc.batch.$$"
cat <<"PCOCC_BATCH_SCRIPT_EOF" >> "${TEMP_BATCH_SCRIPT}"
""")
            wrpfile.write(batch_script.read())
            wrpfile.write("""
PCOCC_BATCH_SCRIPT_EOF
chmod u+x "$TEMP_BATCH_SCRIPT"
""")

        if host_script:
            launcher_opt += ['-E', '"$TEMP_HOST_SCRIPT"']
            wrpfile.write("""
TEMP_HOST_SCRIPT="/tmp/pcocc.host.$$"
cat <<"PCOCC_HOST_SCRIPT_EOF" >> "${TEMP_HOST_SCRIPT}"
""")
            wrpfile.write(host_script.read())
            wrpfile.write("""
PCOCC_HOST_SCRIPT_EOF
chmod u+x "$TEMP_HOST_SCRIPT"
""")

        wrpfile.write(
"""
PYTHONUNBUFFERED=true pcocc %s internal launcher %s %s %s %s %s %s &
trap "kill -15 $!; echo Signal received, waiting for pcocc to exit; SIGNAL=1" SIGTERM SIGINT
while true; do
  SIGNAL=0
  wait $!
  RET=$?
  if [[ $SIGNAL -eq 0 ]]; then
    break;
  fi
  echo "Restarting wait"
done

rm "$TEMP_BATCH_SCRIPT" 2>/dev/null
rm "$TEMP_HOST_SCRIPT" 2>/dev/null

exit $RET

""" % (' '.join(Config().verbose_opt),
            ' '.join(launcher_opt),
            ' '.join(ckpt_opt),
            ' '.join(docker_opt),
            ' '.join(mirror_opt),
            ' '.join(user_data_opt),
            cluster_definition))

        wrpfile.close()
        ret = config.batch.batch(cluster,
                                 batch_options +
                                 get_license_opts(cluster) +
                                 ['-n', '%d' % (len(cluster.vms))],
                                 wrpname)
        sys.exit(ret)

    except PcoccError as err:
        handle_error(err)

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
@docstring(batch_alloc_doc + alloc_doc)
def pcocc_alloc(restart_ckpt,
                alloc_script,
                user_data,
                batch_options,
                cluster_definition):
    # Hook to enable calling from other functions
    return _pcocc_alloc(restart_ckpt,
                        alloc_script,
                        user_data,
                        batch_options,
                        cluster_definition)


def _pcocc_alloc(restart_ckpt,
                 alloc_script,
                 user_data,
                 batch_options,
                 cluster_definition,
                 docker=False,
                 mirror_user=False,
                 config=None):
    try:
        # In 'pcocc docker alloc' you need the config prior to the allocation
        # in this case if the config is loaded a second time pcocc raises
        # a duplicate template error. Overloading the config is then a way
        # to circumvent this problem
        if config is None:
            config = load_config(process_type=ProcessType.OTHER)

        cluster = Cluster(cluster_definition)
        batch_options = list(batch_options)
        ckpt_opt = gen_ckpt_opt(restart_ckpt)
        docker_opt = ["--docker"] if docker else []
        mirror_opt = ["-m"] if mirror_user else []
        alloc_opt = gen_alloc_script_opt(alloc_script)
        user_data_opt = gen_user_data_opt(user_data)
        ret = config.batch.alloc(cluster,
                                 batch_options + get_license_opts(cluster) +
                                 ['-n', '%d' % (len(cluster.vms))],
                                 ['pcocc'] + Config().verbose_opt +
                                 ['internal', 'launcher'] + docker_opt +
                                 mirror_opt + alloc_opt + user_data_opt +
                                 ckpt_opt + [cluster_definition])

    except PcoccError as err:
        handle_error(err)

    logging.debug("All done")
    sys.exit(ret)

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
@click.option('--docker', is_flag=True,
              help='Instruct to setup the Docker daemon environment')
@click.option('-m', '--mirror-user', is_flag=True,
              help='Mirror user in allocated VMs')
@click.argument('cluster-definition', nargs=1)
def pcocc_launcher(restart_ckpt,
                   wait,
                   script,
                   alloc_script,
                   user_data,
                   docker,
                   mirror_user,
                   cluster_definition):
    signal.signal(signal.SIGINT, clean_exit)
    signal.signal(signal.SIGTERM, clean_exit)

    config = load_config(process_type=ProcessType.LAUNCHER)
    batch = config.batch

    logging.debug("Starting pcocc launcher for " + cluster_definition)

    if sys.stdin.isatty():
        oldterm = termios.tcgetattr(sys.stdin.fileno())
    else:
        oldterm = None

    cluster = Cluster(cluster_definition)

    batch.populate_env()

    if restart_ckpt:
        ckpt_opt = ['-r', restart_ckpt]
    else:
        ckpt_opt = []

    if docker:
        docker_opt = ['--docker']
    else:
        docker_opt = []

    # TODO: provide a way for the user to plugin his own pre-run scripts here
    try:
        os.mkdir(os.path.join(batch.cluster_state_dir, 'slurm'))
    except OSError as e:
        if e.errno == errno.EEXIST:
            pass

    for path in os.listdir(helperdir):
        path = os.path.abspath(os.path.join(helperdir, path))
        if os.path.isfile(path) and os.access(path, os.X_OK):
            subprocess.call(path, cwd=batch.cluster_state_dir)

    logging.debug("Launching hypervisors")
    # TODO: This cmdline should be tunable
    s_pjob = batch.run(cluster,
                       ['-Q', '-X', '--resv-port'],
                       ['pcocc'] +
                       Config().verbose_opt +
                       ['internal', 'run'] + docker_opt + gen_user_data_opt(user_data) +
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

    batch.write_key("cluster/user", "resource_definition", cluster.resource_definition)
    batch.write_key("cluster/user", "definition", cluster_definition)

    batch.write_key("cluster/user", "ca_cert", UserCA.new().dump_yaml())

    if docker:
        Docker.init_client_certs()
        print("Waiting for Docker VM to start ...")
        Docker.apply_mounts(cluster, CLIRangeSet("0", cluster))
        Docker.wait_for_docker_start(cluster,
                                     CLIRangeSet("0", cluster),
                                     timeout=DEFAULT_AGENT_TIMEOUT)

    if mirror_user:
        runner = Run.VirtualMachine(cluster)
        # We only insert the user and groups
        runner.mirror()

    term_sigfd = fake_signalfd([signal.SIGTERM, signal.SIGINT])

    monitor_list = [s_pjob.pid]

    if docker:
        s_exec = Docker.shell(cluster.vms[0],
                              script=alloc_script)
    elif script:
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
        shell_env['PROMPT_COMMAND'] = 'echo -n "(pcocc/%d) "' % (batch.batchid)
        shell_env['PCOCC_ALLOCATION'] = "1"
        shell = os.getenv('SHELL', default='bash')
        s_exec = subprocess.Popen(shell, env=shell_env)

    monitor_list.append(s_exec.pid)

    while True:
        status, pid, reason = wait_or_term_child(monitor_list,
                                                 signal.SIGTERM, term_sigfd, 40, "launcher")

        if pid == s_pjob.pid:
            if reason != CHILD_EXIT.NORMAL:
                sys.stderr.write("The cluster has been terminated due to a signal\n")
            elif status != 0:
                sys.stderr.write("The cluster terminated unexpectedly\n")
            else:
                sys.stderr.write("The cluster has shut down\n")

            if s_exec.poll() is None:
                if script or alloc_script:
                    logging.debug("Sending SIGTERM to alloc command")
                    s_exec.terminate()
                else:
                    logging.debug("Sending SIGHUP to alloc shell")
                    os.kill(s_exec.pid, signal.SIGHUP)

                time.sleep(1)

                if s_exec.poll() is None:
                    logging.debug("Sending SIGKILL to alloc shell/script")
                    s_exec.kill()

                s_exec.wait()
            break

        elif pid == s_exec.pid and not wait:
            sys.stderr.write("Terminating the cluster...\n")
            t = threading.Timer(40, wait_timeout, [s_pjob])
            t.start()
            s_pjob.send_signal(signal.SIGINT)
            s_pjob.wait()
            t.cancel()
            break

    # XXX: For some reason the terminal is sometimes broken when we shutdown a shell
    # running in a subprocess so restore previous settings to be sure
    if oldterm:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, oldterm)

    if reason == CHILD_EXIT.SIGNAL or os.WIFSIGNALED(status):
        sys.exit(1)
    else:
        sys.exit(os.WEXITSTATUS(status))

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
@click.option('--docker', is_flag=True,
              help='Instruct to setup the Docker daemon environment')
@click.option('--user-data', type=click.Path(exists=True),
              help='Override the user-data property of the templates')
def pcocc_internal_run(restart_ckpt, docker, user_data):
    signal.signal(signal.SIGINT, clean_exit)
    signal.signal(signal.SIGTERM, clean_exit)

    try:
        load_config(process_type=ProcessType.HYPERVISOR)
        cluster = load_batch_cluster()

        cluster.load_node_resources()

        if restart_ckpt:
            return cluster.run(ckpt_dir=restart_ckpt, docker=docker)
        else:
            return cluster.run(user_data=user_data, docker=docker)

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
              help='Cmd is a shell script to be copied'
                   ' to /tmp and executed in place')
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
@click.argument('action', type=click.Choice(['init',
                                             'cleanup',
                                             'create',
                                             'delete']))
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
        config.batch.dump_resources()
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

            for name, tpl in sorted(config.tpls.items()):
                if tpl.source_type == t:
                    tbl.append({'name': name,
                                'image': tpl.image,
                                'res': tpl.rset.name,
                                'desc': tpl.description})
            print(tbl)
            print()
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
        except KeyError:
            click.secho('Template not found: ' + template, fg='red', err=True)
            sys.exit(-1)

        tpl.display()
    except PcoccError as err:
        handle_error(err)


class CLIRangeSet(RangeSet):
    def __init__(self, indices=None, cluster=None):
        try:
            if indices == "all":
                super(CLIRangeSet, self).__init__(
                    "0-{}".format(cluster.vm_count() - 1))
            elif indices is not None:
                super(CLIRangeSet, self).__init__(indices)
            else:
                super(CLIRangeSet, self).__init__()
        except RangeSetParseError as e:
            raise PcoccError(str(e))


def per_cluster_cli(allows_user, allow_no_alloc=False):
    def decorator(func):
        def wrapper(*args, **kwargs):
            if (allow_no_alloc and
                    # Are we in an alloc shell
                    # (set in poccc internal launcher) ?
                    not os.getenv("PCOCC_ALLOCATION") and
                    # Is a jobid passed in arg ?
                    not kwargs["jobid"] and
                    # Is a jobname passed in arg ?
                    not kwargs["jobname"]):
                load_config(None, None, process_type=ProcessType.OTHER)
                kwargs["cluster"] = None
                return func(*args, **kwargs)
            elif allows_user:
                load_config(kwargs["jobid"],
                            kwargs["jobname"],
                            default_batchname='pcocc',
                            batchuser=kwargs["user"])
            else:
                load_config(kwargs["jobid"],
                            kwargs["jobname"],
                            default_batchname='pcocc')

            try:
                kwargs["cluster"] = load_batch_cluster()
                return func(*args, **kwargs)
            except PcoccError as err:
                handle_error(err)

        return wrapper
    return decorator


def display_vmagent_error(index, err):
    click.secho("vm{}: {}".format(index, err), fg='red', err=True)


@cli.group(hidden=True)
def agent():
    """ Manage VMs through the pcocc agent """

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
              help='Rangeset of VM indices on which'
                   ' the command should be executed')
@click.option('-s', '--script', is_flag=True,
              help='Cmd is a shell script to be copied'
                   ' to /tmp and executed in place')
@click.option('-m', '--mirror-env', is_flag=True,
              help='Propagate local environment variables')
@click.option('-t', '--timeout', default=DEFAULT_AGENT_TIMEOUT, type=int,
              help='Maximum time to wait for an answer from each VM')
@click.option('--pty',  is_flag=True, default=False,
              help='Run the command in a PTY')
@click.argument('cmd', nargs=-1, required=True, type=click.UNPROCESSED)
@per_cluster_cli(False)
def pcocc_agent_run(jobid,
                    jobname,
                    user,
                    indices,
                    script,
                    mirror_env,
                    cmd,
                    timeout,
                    pty,
                    cluster):
    try:
        rangeset = CLIRangeSet(indices, cluster)
        # This is where we pass the launch config
        runner = Run.VirtualMachine(cluster, rangeset, timeout)

        if not user:
            user = pwd.getpwuid(os.getuid()).pw_name

        runner.set_user(user)

        cmd = list(cmd)

        if script:
            runner.set_script(cmd[0])
        else:
            runner.set_argv(cmd)

        if mirror_env:
            for e, v in os.environ.items():
                runner.set_env_var(e, v)

        if pty:
            runner.set_pty()

        sys.exit(runner.run())
    except PcoccError as err:
        handle_error(err)


@agent.command(name='attach',
               short_help="Attach to a running command",
               context_settings=dict(ignore_unknown_options=True,
                                     allow_interspersed_args=False))
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-i', '--indices', default="all", type=str,
              help='Rangeset of VM indices on which'
                   ' the command should be executed')
@click.argument('exec_id', nargs=1, type=int, required=True)
@per_cluster_cli(False)
def pcocc_attach(jobid, jobname, indices, exec_id, cluster):
    try:
        rangeset = CLIRangeSet(indices, cluster)
        # This is where we pass the launch config
        runner = Run.VirtualMachine(cluster, rangeset)
        exit_code = runner.multiprocess_attach(rangeset, exec_id)
        sys.exit(exit_code)
    except PcoccError as err:
        handle_error(err)


@agent.command(name='writefile', short_help="Copy a file in VMs")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-i', '--indices', default="all", type=str,
              help='Rangeset of VM indices on which'
                   ' the command should be executed')
@click.option('-t', '--timeout', default=DEFAULT_AGENT_TIMEOUT, type=int,
              help='Maximum time to wait for an answer from each VM')
@click.argument('source', nargs=1, type=str)
@click.argument('dest', nargs=1, type=str)
@per_cluster_cli(False)
def pcocc_writefile(jobid, jobname, indices, source, dest, timeout, cluster):
    try:
        rangeset = CLIRangeSet(indices, cluster)
        runner = Run.VirtualMachine(cluster)
        runner.writefile(rangeset, source, dest, timeout)
    except PcoccError as err:
        handle_error(err)


@agent.command(name='freeze',
               short_help="Freeze the VM agents")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-i', '--indices', default="all", type=str,
              help='Rangeset of VM indices on which'
                   ' the command should be executed')
@click.option('-t', '--timeout', default=DEFAULT_AGENT_TIMEOUT, type=int,
              help='Maximum time to wait for an answer from each VM')
@per_cluster_cli(False)
def pcocc_freeze(jobid, jobname, indices, timeout, cluster):
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
              help='Rangeset of VM indices on which'
                   ' the command should be executed')
@click.option('-t', '--timeout', default=DEFAULT_AGENT_TIMEOUT, type=int,
              help='Maximum time to wait for an answer from each VM')
@per_cluster_cli(False)
def pcocc_listexec(jobid, jobname, indices, timeout, cluster):
    rangeset = CLIRangeSet(indices, cluster)

    ret = AgentCommand.listexec(cluster, rangeset, timeout=timeout)
    ret.iterate_all()
    click.echo(ret)

@agent.command(name='thaw',
               short_help="Thaw the VM agents")
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-i', '--indices', default="all", type=str,
              help='Rangeset of VM indices on which'
                   ' the command should be executed')
@click.option('-t', '--timeout', default=DEFAULT_AGENT_TIMEOUT, type=int,
              help='Maximum time to wait for an answer from each VM')
@per_cluster_cli(False)
def pcocc_thaw(jobid, jobname, indices, timeout, cluster):
    rangeset = CLIRangeSet(indices, cluster)
    start_time = time.time()

    ret = AgentCommand.thaw(cluster, rangeset, timeout=timeout)
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
              help='Rangeset of VM indices on which'
                   ' the command should be executed')
@click.option('-t', '--timeout', default=DEFAULT_AGENT_TIMEOUT, type=int,
              help='Maximum time to wait for an answer from each VM')
@per_cluster_cli(False)
def pcocc_ping(jobid, jobname, indices, timeout, cluster):
    rangeset = CLIRangeSet(indices, cluster)
    start_time = time.time()

    ret = AgentCommand.hello(cluster, rangeset, timeout=timeout)
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


@image.group(name="repo")
def img_repo():
    """ List and manage image repositories """


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

    print(tbl)

@img_repo.command(name='list',
                  short_help="List pcocc image repositories")
def pcocc_image_repo_list():
    try:
        config = load_config(process_type=ProcessType.OTHER)

        rlist = config.images.list_repos()
        print_repolist(rlist)
    except PcoccError as err:
        handle_error(err)


@img_repo.command(name='gc',
                  short_help="Cleanup unnecessary data in a repository")
@click.argument('repo', nargs=1, type=str)
def pcocc_image_repo_gc(repo):
    try:
        config = load_config(process_type=ProcessType.OTHER)

        config.images.garbage_collect(repo)
    except PcoccError as err:
        handle_error(err)


@image.command(name='import',
               short_help="Import an image to a repository")
@click.option('-t', '--fmt', type=str,
              help='Force source image format')
@click.argument('source', nargs=1, type=str)
@click.argument('dest', nargs=1, type=str)
def pcocc_image_import(fmt, source, dest):
    """Import the source image file to an image in the destination repository.

    Images in repositories are specified with URIs of the form
    [REPO:]IMAGE[@REVISION].

    The destination image name must not already be used in the destination
    repository and the revision is ignored since the import operation creates
    the first revision of a new image.
    """

    try:
        load_config(process_type=ProcessType.OTHER)
        Config().images.import_image(source, dest, fmt)
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
        load_config(process_type=ProcessType.OTHER)
        Config().images.delete_image(image)
    except PcoccError as err:
        handle_error(err)

@image.command(name='resize',
               short_help="Resize an image in a repository")
@click.argument('image', nargs=1, type=str)
@click.argument('new_sz', nargs=1, type=str)
def pcocc_image_resize(image, new_sz):
    """Resize an image in a repository

    Images in repositories are specified with URIs of the form
    [REPO:]IMAGE[@REVISION]

    A new image revision is created with the new image size.

    \b
    Example usage:
           pcocc image resize myimg 20G
    """
    try:
        load_config(process_type=ProcessType.OTHER)
        Config().images.resize_image(image, new_sz)
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
        load_config(process_type=ProcessType.OTHER)
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
        load_config(process_type=ProcessType.OTHER)
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
        load_config(process_type=ProcessType.OTHER)
        meta, _ = Config().images.get_image(image)
        ts = time.localtime(meta["timestamp"])
        str_time = time.strftime('%Y-%m-%d %H:%M:%S', ts)

        print("------------------------------")
        print(("%5s %24s" % ("Repo:", meta["repo"])))
        print(("%5s %24s" % ("Name:", meta["name"])))
        print(("%s %24s" % ("Type:",  meta["kind"])))
        print("------------------------------")
        print(("%5s %24s" % ("URI: ", meta["repo"] + ":" +
                            meta["name"] + "@" + str(meta["revision"]))))
        print(("%s %22s" % ("Layers:", str(len(meta["data_blobs"])))))
        print("------------------------------")
        print(("%7s %22s" % ("Owner: ", meta["owner"])))
        print(("%7s %21s" % ("Date:   ", str_time)))
        print("------------------------------")

        revisions = Config().images.image_revisions(image)
        print("")
        tbl = TextTable("%rev %size %date")
        tbl.header_labels = {'rev': 'Revision',
                             'size': 'Size',
                             'date': 'Creation Date'}

        for rev in revisions:
            meta, data = Config().images.get_image(image, rev)
            ts = time.localtime(meta["timestamp"])
            str_time = time.strftime('%Y-%m-%d %H:%M:%S', ts)

            tbl.append({'rev': str(rev),
                        'size': formatted_file_size(data),
                        'date': str_time})

        print(tbl)
    except PcoccError as err:
        handle_error(err)


def print_image_list(images):
    tbl = TextTable("%name %type %revision %repo %owner %date")
    for img in sorted(iter(images.values()),
                      key=lambda i: i[list(i.keys())[0]]["name"]):
        rev = max(img.keys())
        ts = time.localtime(img[rev]["timestamp"])
        str_time = time.strftime('%Y-%m-%d %H:%M:%S', ts)
        repo = img[rev]["repo"]

        tbl.append({'name': img[rev]["name"],
                    'type': img[rev]["kind"],
                    'revision': str(rev),
                    'repo': repo,
                    'owner': img[rev]["owner"],
                    "date": str_time})

    print(tbl)

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
        config = load_config(process_type=ProcessType.OTHER)
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
                print()

    except PcoccError as err:
        handle_error(err)


@image.group()
def cache():
    """ Manage container image cache """


CACHEABLE_ITEMS = ["cached_squashfs",  "cached_bundle"]


@cache.command(name='list',
               short_help="List images in repositories"
                          " in increasing order of last use")
def pcocc_image_cache_list():
    try:
        config = load_config(process_type=ProcessType.OTHER)

        metas = config.images.object_store.load_meta()

        all_blobs_key = {}

        for m in list(metas.values()):
            for rev, val in list(m.items()):
                name = val["name"]
                repo = val["repo"]

                for k in CACHEABLE_ITEMS:
                    key = config.images.cache_key("{}:{}@{}".format(repo,
                                                                    name,
                                                                    rev),
                                                  k)
                    hashed_key = config.images.object_store.cache.hash_key(key)
                    all_blobs_key[hashed_key] = {"repo": repo,
                                                 "name": name,
                                                 "rev": rev,
                                                 "type": k}

        all_blobs = config.images.object_store.cache.get_sorted_blob_list()

        tbl = TextTable("%repo %name %revision %type %hash")

        for b in all_blobs:
            if b.hash in all_blobs_key:
                elem = all_blobs_key[b.hash]
                tbl.append({'repo': elem["repo"],
                            'name': elem["name"],
                            'revision': str(elem["rev"]),
                            'type': elem["type"],
                            'hash': b.hash[:10]})
        print(tbl)
        print(("\nCache contains %d items"
              % len(config.images.object_store.cache)))
    except PcoccError as err:
        handle_error(err)

@cache.command(name='delete',
               short_help="Delete all cached items for a given image")
@click.argument('image', nargs=1, type=str)
def pcocc_image_cache_rm(image):
    try:
        config = load_config(process_type=ProcessType.OTHER)
        _, _ = config.images.get_image(image)
        for k in CACHEABLE_ITEMS:
            key = config.images.cache_key(image, k)
            del config.images.object_store.cache[key]
    except PcoccError as err:
        handle_error(err)

@cache.command(name='gc',
               short_help="Clean the cache by removing dangling objects")
@click.option('-b', '--force-below', type=int, default=None,
              help='Decimate the cache to store only count elements')
@click.option('-c', '--force-clear', is_flag=True,
              help='Remove all elements from the cache')
def pcocc_image_cache_gc(force_below, force_clear):
    try:
        config = load_config(process_type=ProcessType.OTHER)

        if force_clear:
            config.images.object_store.cache.clear()
            return

        if force_below:
            # Use regular decimation
            config.images.object_store.cache.decimate(count=force_below)
            return

        # Generate the set of all possible cached objects
        metas = config.images.object_store.load_meta()

        possible_keys = set()

        for m in list(metas.values()):
            for rev, val in list(m.items()):
                name = val["name"]
                repo = val["repo"]
                for k in CACHEABLE_ITEMS:
                    key = config.images.cache_key("{}:{}@{}".format(repo,
                                                                    name,
                                                                    rev),
                                                  k)
                    possible_keys.add(key)

        # Compute actual blob hash as keys are hashed
        possible_keys = list(map(config.images.object_store.cache.hash_key,
                            possible_keys))

        cache_keys = set(config.images.object_store.cache.keys())

        # Now proceed to delete elements which
        # are not from known images anymore
        for e in cache_keys.difference(possible_keys):
            print(("Deleting dangling cache blob {} ...".format(e[:10])))
            config.images.object_store.cache.delete_hash(e)

    except PcoccError as err:
        handle_error(err)


def formatted_file_size(path):
    size = os.path.getsize(path)
    if size < 1024:
        return "{0} Bytes".format(size)
    elif size < 1024 * 1024:
        return "{0} KB".format(float(size) // 1024.0)
    elif size < 1024 * 1024 * 1024:
        return "{0} MB".format(float(size) // (1024.0 * 1024.0))
    elif size < 1024 * 1024 * 1024 * 1024:
        return "{0} GB".format(float(size) // (1024.0 * 1024.0 * 1024.0))


@cli.command(name='ps',
             short_help='List current pcocc jobs')
@click.option('-a', '--all', 'allusers',
              is_flag=True, default=False,
              help='List jobs for all users')
@click.option('-u', '--user', default="",
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

        tbl = TextTable("%id %name %user %partition"
                        " %nodes %duration %timelimit")
        for j in sorted(joblist, key=lambda x: x['jobname']):
            tbl.append({'id': str(j["batchid"]),
                        'user': j["user"],
                        'partition': j["partition"],
                        'nodes': str(j["node_count"]),
                        'name': j["jobname"],
                        'duration': j["exectime"],
                        'timelimit': j["timelimit"]})

        print(tbl)

    except PcoccError as err:
        handle_error(err)


@internal.command(name='run-ctr',
                  short_help='Run a native container')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname', type=str,
              help='Job name of the selected cluster')
@click.argument('args', nargs=-1, type=click.UNPROCESSED)
@per_cluster_cli(False, allow_no_alloc=True)
def pcocc_internal_run_ctr(jobid,
                           jobname,
                           args,
                           cluster):
    try:
        runner = Run.Native()

        if not len(args):
            raise PcoccError("A configuration object must be passed")

        runner = Run.Container(runner, conf=json.loads(args[0]))
        sys.exit(runner.run())
    except PcoccError as err:
        handle_error(err)


@cli.command(name='run',
             context_settings=dict(allow_interspersed_args=False),
             short_help='Run a program in VM or container')
@click.option('-j', '--jobid', type=int,
              help='Select allocation or cluster by job id')
@click.option('-J', '--jobname', type=str,
              help='Select allocation or cluster by job name')
@click.option('-u', '--user', type=str, default=None,
              help='Username to use to run the command')
@click.option('-I', '--image', type=str,
              help='Spawn a container to run the command')
@click.option('--script', type=str, default=None,
              help='Execute a script stored on the host')
@click.option('-w', '--nodelist', type=str,
              help='Nodeset on which to run the command')
@click.option('--pty', is_flag=True, default=False,
              help='Execute first task in a pseudo terminal')
@click.option('-N', '--node', type=int, default=None,
              help='Number of nodes to use for running the command ')
@click.option('-n', '--process', type=int,
              help='Number of processes to launch')
@click.option('-c', '--core', type=int, default=None,
              help='Number of cores per process')
@click.option('-s', '--singleton', is_flag=True, default=False,
              help='Run a single task locally')
@click.option('-p', '--partition', type=str, default=None,
              help='Partition on which to run')
@click.option('--mirror-env', is_flag=True, default=False,
              help='Propagate local environment variables')
@click.option('--no-defaults', is_flag=True, default=False,
              help='Do not apply default container configuration')
@click.option('--no-user', is_flag=True, default=False,
              help='Do not inject the user inside the container or VM')
@click.option('-e', '--env', type=str, multiple=True,
              help='Environment variables to propagate')
@click.option('--path-prefix', type=str, multiple=True,
              help='Prepend values to a PATH type variable')
@click.option('--path-suffix', type=str, multiple=True,
              help='Append values to a PATH type variable')
@click.option('--mount', type=str, multiple=True,
              help='Mount a host directory in the container')
@click.option('--cwd', type=str, help='Work directory for the target executable')
@click.option('-M', '--module', type=str, default=None, multiple=True,
              help='Container configuration modules to apply')
@click.option('--entry-point', type=str, default=None,
              help='Override entry point of a Docker container')
@click.argument('cmd', nargs=-1, type=click.UNPROCESSED)
@per_cluster_cli(False, allow_no_alloc=True)
def pcocc_run(jobid,
              jobname,
              user,
              script,
              nodelist,
              pty,
              image,
              node,
              process,
              core,
              singleton,
              partition,
              mirror_env,
              no_defaults,
              no_user,
              env,
              path_prefix,
              path_suffix,
              mount,
              cwd,
              module,
              cmd,
              entry_point,
              cluster):
    try:
        cmd = list(cmd)

        if not cmd and not image and not script:
            raise PcoccError("You must specify a command, an image name "
                             "or a script")

        if node:
            if process and process < node:
                raise PcoccError("If you specify {} nodes".format(node) +
                                 " you need at least " +
                                 "{} processes not {}".format(node, process))
            elif not process:
                # Assume N = P
                process = node

        if not process:
            # Assume n=1 if not configured otherwise
            process = 1

        if pty:
            if process > 1:
                raise PcoccError("Cannot run in a PTY on more than 1 process")
            if not sys.stdout.isatty():
                raise PcoccError("Cannot run in a PTY as stdout is not a TTY")

        if singleton:
            runner = Run.Native()
        elif cluster:
            runner = Run.VirtualMachine(cluster)
        else:
            runner = Run.Slurm()

        # Propagate and validate run config to runner
        runner.set_configuration(process,
                                 node,
                                 core,
                                 nodelist,
                                 partition)

        if user:
            runner.set_user(user)

        if image:
            if module:
                module_set = set()
                for e in module:
                    module_set.update(e.split(","))

            else:
                module_set = ()

            runner = Run.Container(runner,
                                   image=image,
                                   modules=list(module_set),
                                   no_user=no_user,
                                   no_defaults=no_defaults,
                                   command=cmd)

        if entry_point:
            if image:
                runner.set_entrypoint(shlex.split(entry_point))
            else:
                raise PcoccError("Entrypoint can only be defined for container images")

        if script:
            runner.set_script(script)
        elif cmd:
            runner.set_argv(cmd)

        if pty:
            # Also propagate the TERM variable
            if "TERM" in os.environ:
                Run.Env.append(runner, ["TERM"])
            runner.set_pty()

        if cwd:
            # Set CWD and inform the runner that it is forced
            # the reason for this is that some docker image
            # rely on an internal CWD we therefore want
            # this docker-image CWD to have a higher priority
            # than the silent CWD propagation
            # a value "-" forces the use of the OCI value
            runner.set_cwd(cwd, forced=True)
        else:
            if os.getcwd() == os.path.realpath(os.environ['PWD']):
                runner.set_cwd(os.environ['PWD'])
            else:
                runner.set_cwd(os.getcwd())

        # It is important to set mirror before manipulating
        # the env variables as it defines if current vars
        # are reachable in the "Native" and "Slurm" configuration
        if mirror_env:
            runner.mirror_env()

        # Pass env modifiers from command-line
        Run.Env.append(runner, env)
        Run.Env.path_prefix(runner, path_prefix)
        Run.Env.path_suffix(runner, path_suffix)

        # Add command-line mountpoints (only meaningful for containers)
        Run.Mount.add(runner, mount)

        # Run the program
        sys.exit(runner.run())

    except subprocess.CalledProcessError as e:
        # Here we catch the error from the native
        # exec when running locally (runner is not wrapped)
        click.secho("Could not execute program", fg='red', err=True)
        sys.exit(e.returncode)
    except PcoccError as err:
        handle_error(err)


@cli.group()
def docker():
    """ Use a Docker daemon running in a VM """


@docker.command(name='import',
                short_help='Import an image from a pcocc repository')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-i', '--index', type=int, default=0,
              help='Index of the VM to connect to')
@click.argument('source', nargs=1, type=str)
@click.argument('dest', nargs=1, type=str)
@per_cluster_cli(False)
def docker_import(jobid, jobname, cluster, index, source, dest):
    try:
        Docker.send_image(cluster.vms[index], source, dest)
    except PcoccError as err:
        handle_error(err)


@docker.command(name='export',
                short_help='Export an image to a pcocc repository')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-i', '--index', type=int, default=0,
              help='Index of the VM to connect to')
@click.argument('source', nargs=1, type=str)
@click.argument('dest', nargs=1, type=str)
@per_cluster_cli(False)
def docker_export(jobid, jobname, cluster, index, source, dest):
    try:
        Docker.get_image(cluster.vms[index], dest, source)
    except PcoccError as err:
        handle_error(err)


@docker.command(name='build',
                short_help='Build a pcocc image from a Dockerfile')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-i', '--index', type=int, default=0,
              help='Index of the VM to connect to')
@click.argument('path', nargs=1, type=str)
@click.argument('dest', nargs=1, type=str)
@per_cluster_cli(False)
def docker_build(jobid, jobname, cluster, index, path, dest):
    try:
        Config().images.check_overwrite(dest)
        Docker.build_image(cluster.vms[index], dest, path)
    except PcoccError as err:
        handle_error(err)


@docker.command(name='alloc',
                context_settings=dict(ignore_unknown_options=True),
                short_help='Spawn a Docker VM (interactive mode)')
@click.option('-E', '--alloc-script', metavar='SCRIPT',
              help='Execute a script on the allocation node')
@click.option('-T', '--docker-timeout', type=int,
              help='Time in seconds to wait for docker to start in the VM')
@click.option('-t', '--template', type=str,
              help='Template to use to spawn the docker VM')
@click.argument('batch-options', nargs=-1, type=click.UNPROCESSED)
def docker_alloc(alloc_script, docker_timeout, batch_options, template):
    try:
        config = load_config(process_type=ProcessType.OTHER)
        pod = template or config.containers.config.docker_pod

        batch_options = list(batch_options)

        return _pcocc_alloc(None,
                            alloc_script,
                            None,
                            batch_options,
                            pod + ":1",
                            docker=True,
                            mirror_user=True,
                            config=config)
    except PcoccError as err:
        handle_error(err)


@docker.command(name='batch',
                context_settings=dict(ignore_unknown_options=True),
                short_help="Spawn a Docker VM (batch mode)")
@click.option('-E', '--host-script', type=click.File('r'),
              help='Launch a batch script on the first host')
@click.option('-t', '--template', type=str,
              help='Template to use to spawn the docker VM')
@click.argument('batch-options', nargs=-1, type=click.UNPROCESSED)
@docstring(batch_alloc_doc + batch_doc)
def docker_batch(host_script,
                 batch_options, template):
    try:
        config = load_config(process_type=ProcessType.OTHER)
        pod = template or config.containers.config.docker_pod
        batch_options = list(batch_options)
        # Hook to enable calling from other functions
        return _pcocc_batch(None,
                            None,
                            host_script,
                            None,
                            batch_options,
                            pod,
                            docker=True,
                            mirror_user=True,
                            config=config)
    except PcoccError as err:
        handle_error(err)


@docker.command(name='shell',
                short_help='Launch a shell for interacting with a Docker VM')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@click.option('-E', '--script', metavar='SCRIPT',
              help='Execute a script inside the docker shell')
@click.option('-i', '--index', type=int, default=0,
              help='Index of the VM to connect to')
@click.option('-T', '--docker-timeout', type=int, default=200,
              help='Time in seconds to wait for docker to start in the VM')
@per_cluster_cli(False)
def docker_shell(jobid, index, jobname, cluster, script, docker_timeout):
    try:
        Config().batch.populate_env()
        print("Waiting for the Docker VM to start ...")
        Docker.wait_for_docker_start(cluster, CLIRangeSet("0", cluster),
                                     timeout=docker_timeout)
        shell = Docker.shell(cluster.vms[index], script)
        sys.exit(shell.wait())
    except PcoccError as err:
        handle_error(err)


@docker.command(name='env',
                short_help='Display variables for interacting with a Docker VM')
@click.option('-j', '--jobid', type=int,
              help='Jobid of the selected cluster')
@click.option('-i', '--index', type=int, default=0,
              help='Index of the VM to connect to')
@click.option('-J', '--jobname',
              help='Job name of the selected cluster')
@per_cluster_cli(False)
def docker_env(jobid, jobname, index, cluster):
    try:
        Docker.env(cluster.vms[index])
    except PcoccError as err:
        handle_error(err)
