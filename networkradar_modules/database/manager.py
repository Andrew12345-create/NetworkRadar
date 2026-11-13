"""SQLite write-queue manager used by the NetworkRadar application.

This module owns the serialized writer thread and short-lived read-only
connections. It deliberately does not own schema definitions or application
business logic.
"""
from __future__ import annotations

import queue as _queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path


class NestedWriteError(RuntimeError):
    pass

class DatabaseManager:
    def __init__(self, path, busy_ms=15000, queue_max=10000, batch_interval=0.03,
                 batch_max=200):
        self.path = Path(path)
        self.busy_ms = busy_ms
        self.q = _queue.Queue(maxsize=queue_max)
        self.batch_interval = batch_interval
        self.batch_max = batch_max
        self.stop_flag = threading.Event()
        self.ready = threading.Event()
        self.start_error = None
        self.thread = None
        self.wconn = None
        self.in_txn = threading.local()
        self.health_data = {"running": False, "processed": 0, "failed": 0,
                            "last_write_ms": 0.0, "last_error": "",
                            "dropped_async": 0}
        self.hlock = threading.Lock()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_flag.clear()
        self.ready.clear()
        self.start_error = None
        self.thread = threading.Thread(target=self._loop, daemon=True,
                                       name="NR-DBWriter")
        self.thread.start()
        if not self.ready.wait(10):
            raise RuntimeError("Database writer did not become ready.")
        if self.start_error:
            raise RuntimeError(f"Database writer startup failed: {self.start_error}")
        with self.hlock:
            self.health_data["running"] = True

    def stop(self, timeout=10.0):
        self.stop_flag.set()
        if self.thread:
            self.thread.join(timeout=timeout)
        alive = bool(self.thread and self.thread.is_alive())
        with self.hlock:
            self.health_data["running"] = alive
            if alive:
                self.health_data["last_error"] = "Writer did not stop before timeout."
        return not alive

    @contextmanager
    def read(self):
        conn = sqlite3.connect(self.path, timeout=self.busy_ms / 1000,
                               check_same_thread=False)
        try:
            conn.execute(f"PRAGMA busy_timeout={self.busy_ms}")
            conn.execute("PRAGMA query_only=ON")
            conn.row_factory = sqlite3.Row
            yield conn
        finally:
            conn.close()

    def write(self, fn, timeout=30.0):
        if getattr(self.in_txn, "active", False):
            raise NestedWriteError(
                "Write from inside a write. Pass the existing conn instead.")
        if self.stop_flag.is_set():
            raise RuntimeError("Database writer is stopping.")
        holder, done = {}, threading.Event()

        def _wrap(conn):
            self.in_txn.active = True
            try:
                return fn(conn)
            finally:
                self.in_txn.active = False

        try:
            self.q.put(("write", _wrap, holder, done), timeout=max(0.1, timeout))
        except _queue.Full:
            raise TimeoutError("Database write queue remained full.")
        if not done.wait(timeout):
            raise TimeoutError(
                "Database write is still queued or executing; check database health.")
        if "error" in holder:
            raise holder["error"]
        return holder.get("result")

    def submit_async(self, fn):
        if self.stop_flag.is_set():
            with self.hlock:
                self.health_data["dropped_async"] += 1
            return False
        try:
            self.q.put_nowait(("async", fn, None, None))
            return True
        except _queue.Full:
            with self.hlock:
                self.health_data["failed"] += 1
                self.health_data["dropped_async"] += 1
            return False

    def flush(self, timeout=10.0):
        done = threading.Event()
        if not self.thread or not self.thread.is_alive():
            return self.q.empty()
        try:
            self.q.put(("flush", None, None, done), timeout=min(2.0, timeout))
        except _queue.Full:
            return False
        return done.wait(timeout)

    def health(self):
        with self.hlock:
            return dict(self.health_data, queued=self.q.qsize())

    def _loop(self):
        try:
            self.wconn = sqlite3.connect(
                self.path, timeout=self.busy_ms / 1000, check_same_thread=False)
            self.wconn.execute(f"PRAGMA busy_timeout={self.busy_ms}")
            self.wconn.execute("PRAGMA journal_mode=WAL")
            self.wconn.execute("PRAGMA synchronous=NORMAL")
            self.wconn.execute("PRAGMA foreign_keys=ON")
            self.wconn.row_factory = sqlite3.Row
            self.ready.set()
        except Exception as exc:
            self.start_error = str(exc)
            self.ready.set()
            return

        while not self.stop_flag.is_set():
            batch, barriers = self._drain()
            if batch:
                self._exec(batch)
            for barrier in barriers:
                barrier.set()
            if not batch and not barriers:
                time.sleep(0.01)

        while True:
            batch, barriers = self._drain(final=True)
            if batch:
                self._exec(batch)
            for barrier in barriers:
                barrier.set()
            if not batch and not barriers:
                break
        try:
            self.wconn.close()
        except Exception:
            pass

    def _drain(self, final=False):
        batch, barriers = [], []
        deadline = time.monotonic() + self.batch_interval
        while len(batch) < self.batch_max:
            try:
                if not batch and not barriers:
                    item = self.q.get(timeout=0.05 if not final else 0.001)
                else:
                    item = self.q.get_nowait()
            except _queue.Empty:
                if final or time.monotonic() >= deadline:
                    break
                continue
            if item[0] == "flush":
                barriers.append(item[3])
                break
            batch.append(item)
        return batch, barriers

    def _exec(self, batch):
        started = time.perf_counter()
        failures = 0
        try:
            self.wconn.execute("BEGIN IMMEDIATE")
            for index, (_, fn, holder, done) in enumerate(batch):
                savepoint = f"nr_op_{index}"
                try:
                    self.wconn.execute(f"SAVEPOINT {savepoint}")
                    result = fn(self.wconn)
                    self.wconn.execute(f"RELEASE SAVEPOINT {savepoint}")
                    if holder is not None:
                        holder["result"] = result
                except Exception as exc:
                    failures += 1
                    self.wconn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                    self.wconn.execute(f"RELEASE SAVEPOINT {savepoint}")
                    if holder is not None:
                        holder["error"] = exc
                    with self.hlock:
                        self.health_data["last_error"] = str(exc)[:200]
            self.wconn.execute("COMMIT")
            for _, _, _, done in batch:
                if done is not None:
                    done.set()
            with self.hlock:
                self.health_data["processed"] += len(batch) - failures
                self.health_data["failed"] += failures
                self.health_data["last_write_ms"] = round(
                    (time.perf_counter() - started) * 1000, 2)
        except Exception as exc:
            try:
                self.wconn.execute("ROLLBACK")
            except Exception:
                pass
            for _, _, holder, done in batch:
                if holder is not None:
                    holder["error"] = exc
                if done is not None:
                    done.set()
            with self.hlock:
                self.health_data["failed"] += len(batch)
                self.health_data["last_error"] = str(exc)[:200]
