"""Small bounded TTL cache for repeat identity-name observations."""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Callable, Any


class IdentityLookupCache:
    """Cache successful reverse-name results longer than negative observations."""

    def __init__(self, *, positive_ttl: float = 600.0,
                 negative_ttl: float = 60.0, max_entries: int = 2048,
                 clock: Callable[[], float] = time.monotonic):
        self.positive_ttl = max(1.0, float(positive_ttl))
        self.negative_ttl = max(1.0, float(negative_ttl))
        self.max_entries = max(16, int(max_entries))
        self._clock = clock
        self._lock = threading.RLock()
        self._items: OrderedDict[tuple, tuple[float, Any]] = OrderedDict()

    def get(self, source: str, ip: str, network: str,
            loader: Callable[[], Any]) -> Any:
        key = (str(source), str(network), str(ip))
        now = self._clock()
        with self._lock:
            cached = self._items.get(key)
            if cached and cached[0] > now:
                self._items.move_to_end(key)
                return cached[1]
            if cached:
                self._items.pop(key, None)
        value = loader()
        ttl = self.positive_ttl if value else self.negative_ttl
        with self._lock:
            self._items[key] = (self._clock() + ttl, value)
            self._items.move_to_end(key)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)
        return value

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
