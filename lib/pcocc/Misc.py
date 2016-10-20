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

from Backports import  enum

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
