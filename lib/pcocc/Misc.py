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

import signal
import threading
import os
import fcntl
import select
import logging
import errno
import socket
import datetime
import jsonschema
import yaml
import atexit
import pwd
from queue import Queue
from threading import Thread
from ctypes import c_uint, c_char_p, c_int, POINTER, cdll, c_int32, byref
from ctypes.util import find_library

from pcocc.Backports import  enum
from pcocc.Config import Config
from pcocc.Error import PcoccError



class runAtExit(object):

    def __init__(self):
        self.to_run = []
        # Register in atexit
        atexit.register(self.run_exit)

    def run_exit(self):
        # Iterate on a copy as some callbacks may deregister
        # themselves
        to_run = self.to_run[:]
        for e in to_run:
            logging.debug("Running exit callback %s", e)
            try:
                e()
            except:
                pass
        self.to_run = []

    def register(self, callback):
        self.to_run.append(callback)

    def deregister(self, callback):
        logging.debug("Unregistering exit callback %s", callback)
        if callback in self.to_run:
            del self.to_run[self.to_run.index(callback)]

# Instanciate the at_exit singleton
# to centralize the atexit events
pcocc_at_exit = runAtExit()


def path_join(*args):
    """A version of path.join which accepts concatenations
       of paths starting with / as later argument

    Returns:
        str -- a string corresponding to the concatenated path
    """
    paths = list(args)

    def remove_start_sep(path):
        return path[1:] if path.startswith(os.sep) else path

    paths = [paths[0]] + list(map(remove_start_sep, paths[1:]))
    return os.path.join(*paths)

stop_threads = threading.Event()

def fake_signalfd(sigs):
    sig_r, sig_w = os.pipe()
    fcntl.fcntl(sig_w, fcntl.F_SETFL, os.O_NONBLOCK)
    for sig in sigs:
        def _fake_sigfd_handler(signum, frame):
            logging.debug("Signalfd handler injecting "
                          "event for signal %s", signum)
            os.write(sig_w, 'x'.encode('ascii'))
        signal.signal(sig, _fake_sigfd_handler)
    return sig_r

def _nanny_thread(child_proc, pipe, return_val, name):
    logging.debug("Started nanny thread%s for %s", name, child_proc)

    if isinstance(child_proc, int):
        pid, r = os.waitpid(child_proc, 0)
    elif isinstance(child_proc, list):
        while True:
            pid, r = os.wait()
            if pid in child_proc:
                break
    else:
        r = child_proc.wait()
        pid = child_proc.pid

    logging.debug("Nanny thread%s detected termination "
                  "of pid %s, status %s", name, pid, r)

    return_val['val'] = r
    return_val['pid'] = pid
    os.write(pipe, 'x'.encode('ascii'))

CHILD_EXIT = enum('NORMAL', 'SIGNAL', 'KILL')

def wait_or_term_child(child_proc, sig, sigfd, timeout, name=""):
    """ Wait until child_proc terminates or sigfd is written to.
    In the latter case, send sig to child_proc and resume waiting """

    child_r, child_w = os.pipe()
    return_val={'val':  None}

    if name:
        name = " ({})".format(name)

    nanny = threading.Thread(None, _nanny_thread,
                             None, args=(child_proc, child_w,
                                         return_val, name))

    nanny.start()
    cur_timeout = None
    status = CHILD_EXIT.NORMAL
    next_sig = 0
    logging.debug("Wait/Term child starting for %s", str(child_proc))

    while True:
        try:
            rdy, _ , _ = select.select([child_r, sigfd], [], [], cur_timeout)
        except select.error as e:
            if e.args[0] == errno.EINTR:
                continue
            else:
                raise

        if child_r in rdy:
            os.read(child_r, 1024)
            logging.debug("Wait/Term child%s: child has exited", name)

            break
        else:
            if sigfd in rdy:
                logging.debug("Wait/Term child: Signal received (%s)", str(child_proc))
                os.read(sigfd,1024)
                status = CHILD_EXIT.SIGNAL
                logging.debug("Wait/Term child%s: Signal received", name)
            else:
                logging.info("Wait or Term: Timeout (%s)", str(child_proc))
                status = CHILD_EXIT.KILL
                logging.debug("Wait/Term child%s: Timeout", name)

            cur_timeout = timeout

            delay = next_sig - datetime_to_epoch(datetime.datetime.utcnow())

            if delay > 0:
                logging.debug("Wait/Term child%s:"
                              "Waiting a maximum of %d more seconds "
                              "before sending next signal", name, delay)
                cur_timeout = delay
                continue

            logging.debug("Wait/Term child%s: "
                          "Sending sig %s to %s", name, sig, child_proc)
            try:
                if isinstance(child_proc, int):
                    os.kill(child_proc, sig)
                elif isinstance(child_proc, list):
                    os.kill(child_proc[0], sig)
                else:
                    os.kill(child_proc.pid, sig)
            except:
                logging.info("Wait/Term child: Failed to kill process")

            # Next time force kill
            next_sig = datetime_to_epoch(datetime.datetime.utcnow()) + timeout
            sig = signal.SIGKILL


    nanny.join()
    return return_val['val'], return_val['pid'], status

def systemd_notify(status, ready=False, watchdog=False):
    sock_path = os.getenv("NOTIFY_SOCKET", None)
    if sock_path is None:
        return False

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.connect(sock_path)

    s = "STATUS={0}".format(status)
    if ready:
        s = "READY=1\n{0}".format(s)
    if watchdog:
        s = "WATCHDOG=1\n{0}".format(s)

    sock.send(s.encode('ascii'))
    sock.close()

    return True

epoch = datetime.datetime.utcfromtimestamp(0)
def datetime_to_epoch(dt):
    return int((dt - epoch).total_seconds())

#Schema to validate the global key state in the key/value store

id_allocation_schema = """
type: array
items:
  type: object
  properties:
    pkey_index:
      type: integer
    batchid:
       type: integer
  required:
    - pkey_index
    - batchid
"""

class IDAllocator(object):
    def __init__(self, key_path, num_ids):
        if num_ids <= 0:
            raise ValueError('Invalid allocator maximum count: {0}'.format(
                num_ids))

        self.num_ids = num_ids
        self.key_path = key_path

    def alloc_one(self):
        return self.alloc(1)[0]

    def coll_alloc_one(self, master, key):
        return self.coll_alloc(1, master, key)[0]

    def free_one(self, old_id):
        return self.free([old_id])

    def alloc(self, count):
        return Config().batch.atom_update_key(
            'global',
            self.key_path,
            self._do_alloc_ids,
            count)

    def coll_alloc(self, count, master, key):
        # Master allocates the ids and broadcasts to the others
        coll_path = os.path.join('coll_alloc', self.key_path, key)

        if Config().batch.node_rank == master:
            ids = Config().batch.atom_update_key(
                'global',
                self.key_path,
                self._do_alloc_ids,
                count)

            Config().batch.write_key('cluster',
                                     coll_path,
                                     yaml.dump(ids))
        else:
            ids = Config().batch.read_key('cluster',
                                          coll_path,
                                          blocking=True,
                                          timeout=30)

            ids = yaml.safe_load(ids)

        return ids

    def free(self, ids):
        return Config().batch.atom_update_key(
            'global',
            self.key_path,
            self._do_free_ids,
            ids)

    def _do_free_ids(self, id_indexes, id_alloc_state):
        """Helper to free unique ids using the key/value store"""
        id_alloc_state = yaml.safe_load(id_alloc_state)
        jsonschema.validate(id_alloc_state,
                            yaml.safe_load(id_allocation_schema))

        batchid = Config().batch.batchid
        id_alloc_state[:] = [ allocated_id for allocated_id in id_alloc_state if
                              allocated_id['batchid'] != batchid or
                              allocated_id['pkey_index'] not in id_indexes ]

        return yaml.dump(id_alloc_state), None

    def _do_alloc_ids(self, count, id_alloc_state):
        """Helper to allocate unique ids using the key/value store"""
        batch = Config().batch

        if not id_alloc_state:
            id_alloc_state = []
        else:
            id_alloc_state = yaml.safe_load(id_alloc_state)

        jsonschema.validate(id_alloc_state,
                            yaml.safe_load(id_allocation_schema))

        num_ids_preclean = len(id_alloc_state)
        # Cleanup completed jobs
        try:
            joblist = batch.list_all_jobs()
            id_alloc_state = [ pk for pk in id_alloc_state
                                 if int(pk['batchid']) in joblist ]
        except PcoccError:
            pass

        num_ids = len(id_alloc_state)
        stray_ids = num_ids_preclean - num_ids
        if stray_ids > 0:
            logging.warning(
                'Found %s leftover Ids, will try to cleanup',
                    stray_ids)

        if num_ids + count > self.num_ids:
            raise PcoccError('Not enough free ids in %s' %
                             self.key_path)

        id_indexes = []
        i = 0
        for allocated_id in sorted(id_alloc_state,
                                   key=lambda x: x['pkey_index']):

            while i < allocated_id['pkey_index'] and count > 0:
                id_indexes.append(i)
                i+=1
                count -= 1

            if count == 0:
                break

            i+=1
        else:
            id_indexes += [ i for i in range(i, i +  count) ]

        for i in id_indexes:
            id_alloc_state.append({'pkey_index': i,
                                   'batchid': batch.batchid})

        return yaml.dump(id_alloc_state), id_indexes

class Worker(Thread):
    """Thread executing tasks from a given tasks queue"""
    def __init__(self, pool):
        Thread.__init__(self)
        self.pool = pool
        self.daemon = True
        self.start()

    def run(self):
        while True:
            try:
                func, key, args, kargs = self.pool.tasks.get()
                try:
                    ret = func(key, *args, **kargs)
                    self.pool.retq.put((key, ret))
                except Exception as e:
                    self.pool.exception = e
                    self.pool.retq.put((key, e))
                finally:
                    self.pool.tasks.task_done()
            except:
                # Workaround python2 race condition issue
                # at interpretor shutdwon for daemon threads
                return


class ThreadPool(object):
    """Pool of threads consuming tasks from a queue"""
    def __init__(self, num_threads):
        self.tasks = Queue()
        self.retq = Queue()
        self.exception = None
        self.num_tasks = 0

        for _ in range(num_threads):
            Worker(self)

    def add_task(self, func, key, *args, **kargs):
        """Add a task to the queue"""
        self.num_tasks = self.num_tasks + 1
        self.tasks.put((func, key, args, kargs))

    def completion_iterator(self, timeout=None):
        """Iterate over task results as they complete"""
        while True:
            if self.num_tasks <= 0:
                return

            self.num_tasks = self.num_tasks - 1
            yield self.retq.get(timeout=timeout)

    def wait_completion(self):
        """Wait for completion of all the tasks in the queue"""
        self.tasks.join()

        if self.exception is not None:
            raise self.exception # pylint: disable-msg=E0702


libc = cdll.LoadLibrary(find_library('libc'))
libc_getgrouplist = libc.getgrouplist

def get_current_user():
    return pwd.getpwuid(os.getuid())

def getgrouplist(user, gid):
    # FROM https://stackoverflow.com/a/49775683
    max_groups = 50
    libc_getgrouplist.argtypes = [c_char_p, c_uint, POINTER(c_uint * max_groups), POINTER(c_int)]
    libc_getgrouplist.restype = c_int32

    grouplist = (c_uint * max_groups)()
    ngrouplist = c_int(max_groups)

    u = pwd.getpwnam(user)
    ct = libc_getgrouplist(bytes(u.pw_name, 'UTF-8'), u.pw_gid, byref(grouplist), byref(ngrouplist))

    # if 50 groups was not enough this will be -1, try again
    # luckily the last call put the correct number of groups in ngrouplist
    if ct < 0:
        libc_getgrouplist.argtypes = [c_char_p,
                                      c_uint,
                                      POINTER(c_uint * int(ngrouplist.value)),
                                      POINTER(c_int)]
        grouplist = (c_uint * int(ngrouplist.value))()
        ct = libc_getgrouplist(bytes(u.pw_name, 'UTF-8'), u.pw_gid, byref(grouplist), byref(ngrouplist))

    r = grouplist[:ct]
    if  gid not in r:
        return [gid] + r
    else:
        return r
