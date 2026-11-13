"""Reliable single-instance locking and local HTTP server binding.

The lock is an OS-managed byte-range lock, so Windows releases it when the
process exits. The lock file itself is intentionally retained; its existence
does not mean a process is running.
"""
from __future__ import annotations

import os
import socket
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Type

_lock_handle = None
_lock_guard = threading.Lock()


class StartupError(RuntimeError):
    """Raised when another instance is active or local startup cannot proceed."""


def _legacy_pid_is_alive(raw: bytes) -> int | None:
    """Recognise the previous JSON PID lock so old and new builds do not overlap."""
    import json
    try:
        text = raw.decode("utf-8", errors="ignore").strip()
        if not text:
            return None
        if text.startswith("{"):
            pid = int(json.loads(text).get("pid", 0))
        elif text.startswith("pid="):
            pid = int(text.split("=", 1)[1].strip())
        else:
            return None
        if pid <= 0 or pid == os.getpid():
            return None
        os.kill(pid, 0)
        return pid
    except PermissionError:
        return pid
    except (ValueError, OSError, ProcessLookupError):
        return None


def acquire_instance_lock(path: str | os.PathLike[str]) -> None:
    global _lock_handle
    lock_path = Path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with _lock_guard:
        if _lock_handle is not None:
            return
        handle = open(lock_path, "a+b")
        try:
            handle.seek(0)
            legacy_pid = _legacy_pid_is_alive(handle.read())
            if legacy_pid:
                raise StartupError(
                    f"A previous NetworkRadar process (PID {legacy_pid}) appears "
                    f"to be running; stop it before starting this build."
                )
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
                        f"Another NetworkRadar instance appears to hold "
                        f"the startup lock: {lock_path}"
                    ) from exc
            else:
                import fcntl
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    raise StartupError(
                        f"Another NetworkRadar instance appears to hold "
                        f"the startup lock: {lock_path}"
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
    """HTTP server that refuses address reuse and uses daemon request threads."""
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
    """Bind the requested port; only search alternatives when explicitly allowed.

    Binding itself is authoritative. A preliminary connect/socket probe is
    deliberately avoided because it is subject to a time-of-check/time-of-use
    race.
    """
    if not (1 <= int(requested_port) <= 65535):
        raise StartupError(f"Invalid TCP port: {requested_port}")
    candidates = [int(requested_port)]
    if allow_alternate:
        candidates.extend(
            p for p in range(int(requested_port) + 1,
                              min(65536, int(requested_port) + search_span + 1))
        )
    last_error = None
    for port in candidates:
        try:
            server = server_class((host, port), handler)
            return server, int(server.server_address[1])
        except OSError as exc:
            last_error = exc
    detail = f"{host}:{requested_port} could not be bound ({last_error})."
    if allow_alternate:
        detail += f" No available port found in the next {search_span} ports."
    else:
        detail += " Choose another port with NETWORKRADAR_PORT or explicitly use --allow-alt-port."
    raise StartupError(detail) from last_error
