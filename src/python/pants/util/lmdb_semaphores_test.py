# Copyright 2026 Pants project contributors (see CONTRIBUTORS.md).
# Licensed under the Apache License, Version 2.0 (see LICENSE).

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import sys
from pathlib import Path

import pytest

from pants.util.lmdb_semaphores import release_lmdb_semaphores

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin", reason="LMDB uses named semaphores on macOS"
)


def _libc():
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.sem_open.restype = ctypes.c_void_p
    libc.sem_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
    libc.sem_close.argtypes = [ctypes.c_void_p]
    libc.sem_unlink.argtypes = [ctypes.c_char_p]
    return libc


def _exists(libc, name: bytes) -> bool:
    handle = libc.sem_open(name, 0, 0, 0)
    if handle in (None, ctypes.c_void_p(-1).value):
        # NB: `sem_open` is variadic, which ctypes can't call portably, so the test's semaphores
        # may have been created with an unusable mode: only a missing name means it doesn't exist.
        return ctypes.get_errno() != errno.ENOENT
    libc.sem_close(handle)
    return True


def test_releases_semaphores_named_in_lock_files(tmp_path: Path) -> None:
    libc = _libc()
    # Names in LMDB's format (`/MDB[rw]` and 10 characters), unique to this test run.
    suffix = f"{os.getpid():010d}"[-10:]
    names = [f"/MDBr{suffix}".encode(), f"/MDBw{suffix}".encode()]
    for name in names:
        handle = libc.sem_open(name, os.O_CREAT, 0o600, 1)
        assert handle not in (None, ctypes.c_void_p(-1).value)
        libc.sem_close(handle)

    shard = tmp_path / "files" / "0"
    shard.mkdir(parents=True)
    # Lock file headers hold the names as NUL-terminated strings.
    (shard / "lock.mdb").write_bytes(b"\x00" * 64 + names[0] + b"\x00" + names[1] + b"\x00" * 64)
    (shard / "data.mdb").write_bytes(names[0] + b"\x00")

    try:
        assert release_lmdb_semaphores(str(tmp_path)) == 2
        assert not any(_exists(libc, name) for name in names)
        assert release_lmdb_semaphores(str(tmp_path)) == 0
    finally:
        for name in names:
            libc.sem_unlink(name)


def test_skips_lock_files_locked_by_another_process(tmp_path: Path) -> None:
    import fcntl

    libc = _libc()
    suffix = f"{os.getpid() + 1:010d}"[-10:]
    name = f"/MDBr{suffix}".encode()
    handle = libc.sem_open(name, os.O_CREAT, 0o600, 1)
    libc.sem_close(handle)
    lock_file = tmp_path / "lock.mdb"
    lock_file.write_bytes(b"\x00" * 8 + name + b"\x00")

    locked_r, locked_w = os.pipe()
    done_r, done_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        # A shared lock, as LMDB holds while an environment is open.
        fd = os.open(lock_file, os.O_RDWR)
        fcntl.lockf(fd, fcntl.LOCK_SH)
        os.write(locked_w, b"x")
        os.read(done_r, 1)
        os._exit(0)
    try:
        os.read(locked_r, 1)
        assert release_lmdb_semaphores(str(tmp_path)) == 0
        assert _exists(libc, name)
        assert release_lmdb_semaphores(str(tmp_path), include_open=True) == 1
    finally:
        os.write(done_w, b"x")
        os.waitpid(pid, 0)
        libc.sem_unlink(name)
