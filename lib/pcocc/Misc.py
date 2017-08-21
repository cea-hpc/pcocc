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

from Batch import BatchError
from Backports import  enum
from Config import Config
from Error import PcoccError

stop_threads = threading.Event()

def fake_signalfd(sigs):
    sig_r, sig_w = os.pipe()
    fcntl.fcntl(sig_w, fcntl.F_SETFL, os.O_NONBLOCK)
    for sig in sigs:
        def _fake_sigfd_handler(signum, frame):
            logging.debug("Signalfd handler injecting "
                          "event for signal {0}".format(signum))
            os.write(sig_w, 'x')
        signal.signal(sig, _fake_sigfd_handler)
    return sig_r

def _nanny_thread(child_proc, pipe, return_val):
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

    logging.debug("Nanny thread detected termination "
                  "of pid {0}".format(pid))
    return_val['val'] = r
    return_val['pid'] = pid
    os.write(pipe, 'x')

CHILD_EXIT = enum('NORMAL', 'SIGNAL', 'KILL')

def wait_or_term_child(child_proc, sig, sigfd, timeout):
    """ Wait until child_proc terminates or sigfd is written to.
    In the latter case, send sig to child_proc and resume waiting """

    child_r, child_w = os.pipe()
    return_val={'val':  None}

    nanny = threading.Thread(None, _nanny_thread,
                             None, args=(child_proc, child_w,
                                         return_val))

    nanny.start()
    cur_timeout = None
    status = CHILD_EXIT.NORMAL
    while True:
        try:
            rdy, _ , _ = select.select([child_r, sigfd], [], [], cur_timeout)
        except select.error as e:
            if e[0] == errno.EINTR:
                continue
            else:
                raise

        if child_r in rdy:
            os.read(child_r, 1024)
            logging.debug("Wait/Term child: child has exited")
            break
        else:
            if sigfd in rdy:
                os.read(sigfd,1024)
                status = CHILD_EXIT.SIGNAL
            else:
                status = CHILD_EXIT.KILL

            cur_timeout = timeout
            logging.debug("Wait/Term child: "
                          "Sending sig {0} to {1}".format(sig, child_proc))
            try:
                if isinstance(child_proc, int):
                    os.kill(child_proc, sig)
                elif isinstance(child_proc, list):
                    os.kill(child_proc[0], sig)
                else:
                    os.kill(child_proc.pid, sig)
            except:
                pass

            # Next time force kill
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

    sock.send(s)
    sock.close()

    return True

epoch = datetime.datetime.utcfromtimestamp(0)
def datetime_to_epoch(dt):
    return int((dt - epoch).total_seconds())



def extend_validator_with_default(validator_class):
    """Customize jsonschema validator to apply default values"""
    validate_properties = validator_class.VALIDATORS["properties"]

    def set_defaults(validator, properties, instance, schema):
        for property, subschema in properties.iteritems():
            if "default-value" in subschema:
                instance.setdefault(property, subschema["default-value"])

        for error in validate_properties(
            validator, properties, instance, schema,
        ):
            yield error
            break

    return jsonschema.validators.extend(
        validator_class, {"properties" : set_defaults},
    )


DefaultValidatingDraft4Validator = extend_validator_with_default(jsonschema.Draft4Validator)

"""Schema to validate the global key state in the key/value store"""
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

    def free_one(self, id):
        return self.free([id])

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

    def _do_free_ids(id_indexes, id_alloc_state):
        """Helper to free unique ids using the key/value store"""
        id_alloc_state = yaml.safe_load(id_alloc_state)
        jsonschema.validate(id_alloc_state,
                            yaml.safe_load(id_allocation_schema))

        batchid = Config().batch.batchid
        id_alloc_state[:] = [ allocated_id for allocated_id in id_alloc_state if
                              allocated_id['batchid'] != batchid or
                              allocated_id['pkey_index'] not in id_indexes ]

        return yaml.dump(id_alloc_state), None

    def _do_alloc_ids(count, id_alloc_state):
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
        except BatchError:
            pass

        num_ids = len(id_alloc_state)
        stray_ids = num_ids_preclean - num_ids
        if stray_ids > 0:
            logging.warning(
                'Found {0} leftover Ids, will try to cleanup'.format(
                    stray_ids))

        if num_ids + count > self.num_ids:
            raise PcoccError('Not enough free ids in {0}'.format(
                self.key_path))

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
            id_indexes += [ i for i in xrange(i, i +  count) ]

        for i in id_indexes:
            id_alloc_state.append({'pkey_index': i,
                                   'batchid': batch.batchid})

        return yaml.dump(id_alloc_state), id_indexes
