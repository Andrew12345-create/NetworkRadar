"""Reliable single-instance locking and local HTTP server binding.

The OS-managed byte-range lock is authoritative. The lock file remains on disk
after shutdown; its existence alone does not indicate a running instance.
"""
from __future__ import annotations

import errno
import os
import re
import subprocess
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


def _windows_excluded_tcp_ports(port: int) -> list[tuple[str, int, int, bool]]:
    """Return Windows TCP excluded-port ranges containing port, if discoverable.

    Windows may deny bind() with WSAEACCES (10013) for an excluded/reserved
    port even when no process is listening on it. Query both address families;
    failure to run netsh is deliberately non-fatal.
    """
    if os.name != "nt":
        return []

    matches: list[tuple[str, int, int, bool]] = []
    for family in ("ipv4", "ipv6"):
        try:
            result = subprocess.run(
                [
                    "netsh", "interface", family, "show",
                    "excludedportrange", "protocol=tcp",
                ],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode != 0:
            continue

        header = ""
        for line in (result.stdout or "").splitlines():
            lowered = line.lower()
            if "start" in lowered and ("end" in lowered or "number" in lowered):
                header = lowered
                continue
            row = re.match(r"^\s*(\d+)\s+(\d+)(?:\s+(\*))?\s*$", line)
            if not row:
                continue
            start, second = int(row.group(1)), int(row.group(2))
            # netsh versions/locales may label the second column as either
            # End Port or Number of Ports.
            if "number" in header:
                end = start + max(0, second - 1)
            elif "end" in header:
                end = second
            else:
                end = second if second >= start else start + max(0, second - 1)
            if start <= port <= end:
                matches.append((family, start, end, bool(row.group(3))))
    return matches


def _bind_error_hint(port: int, exc: OSError) -> str:
    """Explain common Windows bind failures without assuming a process owns the port."""
    winerror = getattr(exc, "winerror", None)
    if os.name == "nt" and (
        winerror == 10013 or exc.errno in (errno.EACCES, errno.EPERM)
    ):
        ranges = _windows_excluded_tcp_ports(port)
        if ranges:
            details = ", ".join(
                f"{family} {start}-{end}" + (" (system-managed)" if starred else "")
                for family, start, end, starred in ranges
            )
            return (
                " Windows denied the bind (WSAEACCES/10013). "
                f"TCP port {port} is in an excluded/reserved range ({details}); "
                "no listening process is required for this bind failure."
            )
        return (
            " Windows denied the bind (WSAEACCES/10013). This can be caused by "
            "an excluded/reserved TCP port or a local security policy, even when "
            "no process is listening. Check the command 'netsh interface ipv4 "
            "show excludedportrange protocol=tcp' and the IPv6 equivalent."
        )
    if winerror == 10048 or exc.errno == errno.EADDRINUSE:
        return (
            " The port is already bound by another socket. Check the owning "
            "process with Get-NetTCPConnection -LocalPort "
            f"{port} -State Listen."
        )
    return ""


def bind_local_server(
    handler: type,
    host: str,
    requested_port: int,
    allow_alternate: bool = False,
    search_span: int = 20,
    server_class: Type[ThreadingHTTPServer] = LocalOnlyHTTPServer,
) -> tuple[ThreadingHTTPServer, int]:
    """Bind the requested port; search alternatives only with explicit consent.

    Binding is attempted directly rather than using a probe socket, avoiding a
    check-then-bind race. Failed partially-created servers are always closed.
    """
    try:
        port = int(requested_port)
    except (TypeError, ValueError) as exc:
        raise StartupError(f"Invalid TCP port: {requested_port!r}") from exc
    if not (1 <= port <= 65535):
        raise StartupError(f"Invalid TCP port: {requested_port}")
    try:
        span = int(search_span)
    except (TypeError, ValueError) as exc:
        raise StartupError(f"Invalid alternate-port search span: {search_span!r}") from exc
    if span < 0 or span > 1024:
        raise StartupError("Alternate-port search span must be between 0 and 1024.")

    ports = [port]
    if allow_alternate and span:
        ports.extend(range(port + 1, min(65536, port + span + 1)))

    requested_error: OSError | None = None
    alternate_errors: list[OSError] = []
    for candidate in ports:
        server = None
        try:
            # Separate construction from bind/activate so a failed bind can be
            # closed deterministically instead of relying on garbage collection.
            server = server_class((host, candidate), handler, bind_and_activate=False)
            server.server_bind()
            server.server_activate()
            return server, int(server.server_address[1])
        except OSError as exc:
            if server is not None:
                try:
                    server.server_close()
                except OSError:
                    pass
            if candidate == port:
                requested_error = exc
            else:
                alternate_errors.append(exc)

    assert requested_error is not None
    message = f"{host}:{port} could not be bound ({requested_error})."
    message += _bind_error_hint(port, requested_error)
    if allow_alternate:
        tried = len(ports) - 1
        message += f" Tried {tried} alternative port(s)."
        if alternate_errors:
            message += f" Last alternative failure: {alternate_errors[-1]}."
    else:
        message += (
            " Choose another port with NETWORKRADAR_PORT or explicitly "
            "use --allow-alt-port."
        )
    raise StartupError(message) from requested_error
