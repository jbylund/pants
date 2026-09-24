# Copyright 2026 Pants project contributors (see CONTRIBUTORS.md).
# Licensed under the Apache License, Version 2.0 (see LICENSE).

"""Release the POSIX semaphores of LMDB environments whose store is about to be deleted.

On macOS, LMDB (built with `MDB_USE_POSIX_SEM`) creates two named semaphores per environment,
named after the lock file's device and inode, and removes them only in `mdb_env_close`. If a
process never closes an environment (it is killed, or exits while still holding the store), and
the store's directory is then deleted, the names can no longer be derived and the semaphores leak
until reboot. Once the system-wide limit (`kern.posix.sem.max`) is reached, every attempt to open a
store fails with "No space left on device".

Each lock file records the names of its semaphores in its header, so they can be released just
before the directory is deleted.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import fcntl
import logging
import os
import re
import sys
from functools import cache

logger = logging.getLogger(__name__)

_SEMAPHORE_NAME = re.compile(rb"/MDB[rw][\x21-\x7e]{10}(?=\x00)")


@cache
def _sem_unlink():
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.sem_unlink.argtypes = [ctypes.c_char_p]
    libc.sem_unlink.restype = ctypes.c_int
    return libc.sem_unlink


def _is_lock_file(filename: str) -> bool:
    return filename == "lock.mdb" or filename.endswith("-lock")


def release_lmdb_semaphores(store_dir: str, *, include_open: bool = False) -> int:
    """Unlink the semaphores of the LMDB environments under `store_dir`, returning how many.

    Environments open in another process are skipped (their names are in use), unless
    `include_open`. An environment open in this process is always released: a process's own locks
    never conflict with it. So only call this for a store this process is done with.

    A no-op except on macOS, where LMDB uses named semaphores.
    """
    if sys.platform != "darwin":
        return 0
    released = 0
    for dirpath, _dirnames, filenames in os.walk(store_dir):
        for filename in filenames:
            if not _is_lock_file(filename):
                continue
            path = os.path.join(dirpath, filename)
            try:
                fd = os.open(path, os.O_RDWR)
            except OSError:
                continue
            try:
                if not include_open:
                    try:
                        # An environment open elsewhere holds a shared lock on its lock file.
                        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except OSError:
                        continue
                header = os.pread(fd, 4096, 0)
            finally:
                os.close(fd)
            for name in set(_SEMAPHORE_NAME.findall(header)):
                if _sem_unlink()(name) == 0:
                    released += 1
    if released:
        logger.debug(f"Released {released} LMDB semaphores of {store_dir}.")
    return released
