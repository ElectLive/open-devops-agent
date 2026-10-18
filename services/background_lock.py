"""One API process owns the queue and retention loops.

Uvicorn's default is two worker processes. Each process imports the app and
would otherwise start its own queue loop against a shared store.
"""
from __future__ import annotations

import os
import tempfile
from typing import Optional, TextIO


def background_lock_path() -> str:
    configured = os.getenv("BACKGROUND_WORKER_LOCK", "").strip()
    if configured:
        return configured
    return os.path.join(tempfile.gettempdir(), "devops-agent-background.lock")


def acquire_background_worker_lock() -> Optional[TextIO]:
    """Return an open lock file, or None when another process already holds it."""
    handle = open(background_lock_path(), "a+")
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None
    except OSError:
        handle.close()
        if os.name == "nt":
            return None
        raise
    return handle


def release_background_worker_lock(handle: Optional[TextIO]) -> None:
    if handle is None:
        return
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()
