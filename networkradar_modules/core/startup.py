"""Reliable single-instance locking and local HTTP server binding.

The OS-managed byte-range lock is authoritative. The lock file remains on disk
after shutdown; its existence alone does not indicate a running instance.
"""
from __future__ import annotations

import os
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Type

_lock_handle = None
_lock_guard = threading.Lock()


class StartupError(RuntimeError):
    """Raised when another instance is active or local startup cannot proceed."""


def acquire_instance_lock(path: str | os.PathLike[str]) -> None:
    """Acquire an OS-managed exclusive lock, released automatically on exit."""
    global _lock_handle
    lock_path = Path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with _lock_guard:
        if _lock_handle is not None:
            return
        handle = open(lock_path, "a+b")
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise StartupError(
                        "Another NetworkRadar instance holds the startup lock."
                    ) from exc
            else:
                import fcntl
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    raise StartupError(
                        "Another NetworkRadar instance holds the startup lock."
                    ) from exc
            handle.seek(0)
            handle.truncate()
            handle.write(f"pid={os.getpid()}\n".encode("ascii"))
            handle.flush()
            _lock_handle = handle
        except Exception:
            handle.close()
            raise


def release_instance_lock() -> None:
    """Release the current process's startup lock."""
    global _lock_handle
    with _lock_guard:
        handle, _lock_handle = _lock_handle, None
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


class LocalOnlyHTTPServer(ThreadingHTTPServer):
    """Local application HTTP server with conservative socket reuse defaults."""
    allow_reuse_address = False
    daemon_threads = True
    block_on_close = False


def bind_local_server(
    handler: type,
    host: str,
    requested_port: int,
    allow_alternate: bool = False,
    search_span: int = 20,
    server_class: Type[ThreadingHTTPServer] = LocalOnlyHTTPServer,
) -> tuple[ThreadingHTTPServer, int]:
    """Bind the requested port, searching alternatives only when explicitly allowed."""
    if not (1 <= int(requested_port) <= 65535):
        raise StartupError(f"Invalid TCP port: {requested_port}")
    ports = [int(requested_port)]
    if allow_alternate:
        ports.extend(
            range(
                int(requested_port) + 1,
                min(65536, int(requested_port) + search_span + 1),
            )
        )
    last_error = None
    for port in ports:
        try:
            server = server_class((host, port), handler)
            return server, int(server.server_address[1])
        except OSError as exc:
            last_error = exc
    message = f"{host}:{requested_port} could not be bound ({last_error})."
    if allow_alternate:
        message += f" Tried next {search_span} ports."
    else:
        message += (
            " Choose another port with NETWORKRADAR_PORT or explicitly "
            "use --allow-alt-port."
        )
    raise StartupError(message) from last_error
