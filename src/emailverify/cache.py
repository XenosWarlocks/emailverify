"""SQLite-backed result cache.

Two reasons this exists, both about money and time:

* Domain results are shared. A 50k-row export typically has a few thousand
  distinct domains, and half the rows are gmail.com. One DNS lookup each.
* API results are billable. Re-running the pipeline after a crash, or on an
  export that overlaps last week's, must not pay twice. The cache also gives
  us resume-for-free: a killed run picks up where it stopped.

Thread-safe via a single connection behind a lock. The writes are tiny and the
workers spend their time on the network, so lock contention is not a factor.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS domain_cache (
    domain     TEXT PRIMARY KEY,
    payload    TEXT NOT NULL,
    checked_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS api_cache (
    email      TEXT PRIMARY KEY,
    payload    TEXT NOT NULL,
    checked_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class ResultCache:
    """Key-value cache with per-table TTLs. Use as a context manager."""

    def __init__(self, path: str | Path | None, enabled: bool = True) -> None:
        self.enabled = enabled and path is not None
        self.path = Path(path) if path is not None else None
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self.hits = 0
        self.misses = 0

    # -- lifecycle ---------------------------------------------------------- #

    def open(self) -> ResultCache:
        if not self.enabled or self.path is None:
            return self
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        # WAL keeps readers from blocking the writer; the cache is append-heavy.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.commit()
        return self

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.commit()
                self._conn.close()
                self._conn = None

    def __enter__(self) -> ResultCache:
        return self.open()

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- generic access ----------------------------------------------------- #

    def _get(self, table: str, key_col: str, key: str, ttl_hours: float) -> dict[str, Any] | None:
        if self._conn is None:
            return None
        cutoff = time.time() - ttl_hours * 3600.0
        with self._lock:
            row = self._conn.execute(
                f"SELECT payload, checked_at FROM {table} WHERE {key_col} = ?", (key,)
            ).fetchone()
        if row is None:
            self.misses += 1
            return None
        payload, checked_at = row
        if checked_at < cutoff:
            self.misses += 1
            return None
        self.hits += 1
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            # Corrupt row -- treat as a miss rather than failing the run.
            self.misses += 1
            return None

    def _put(self, table: str, key_col: str, key: str, payload: dict[str, Any]) -> None:
        if self._conn is None:
            return
        blob = json.dumps(payload, default=str)
        with self._lock:
            self._conn.execute(
                f"INSERT INTO {table} ({key_col}, payload, checked_at) VALUES (?, ?, ?) "
                f"ON CONFLICT({key_col}) DO UPDATE SET payload=excluded.payload, "
                f"checked_at=excluded.checked_at",
                (key, blob, time.time()),
            )
            self._conn.commit()

    # -- typed helpers ------------------------------------------------------ #

    def get_domain(self, domain: str, ttl_hours: float) -> dict[str, Any] | None:
        return self._get("domain_cache", "domain", domain, ttl_hours)

    def put_domain(self, domain: str, payload: dict[str, Any]) -> None:
        self._put("domain_cache", "domain", domain, payload)

    def get_api(self, email: str, ttl_hours: float) -> dict[str, Any] | None:
        return self._get("api_cache", "email", email, ttl_hours)

    def put_api(self, email: str, payload: dict[str, Any]) -> None:
        self._put("api_cache", "email", email, payload)

    # -- maintenance -------------------------------------------------------- #

    def stats(self) -> dict[str, int]:
        out = {"hits": self.hits, "misses": self.misses, "domains": 0, "emails": 0}
        if self._conn is None:
            return out
        with self._lock:
            out["domains"] = self._conn.execute("SELECT COUNT(*) FROM domain_cache").fetchone()[0]
            out["emails"] = self._conn.execute("SELECT COUNT(*) FROM api_cache").fetchone()[0]
        return out

    def purge(self, which: str = "all") -> int:
        """Delete cached rows. Returns the number removed."""
        if self._conn is None:
            return 0
        tables = {"all": ("domain_cache", "api_cache"), "domains": ("domain_cache",),
                  "api": ("api_cache",)}[which]
        removed = 0
        with self._lock:
            for t in tables:
                cur = self._conn.execute(f"DELETE FROM {t}")
                removed += cur.rowcount if cur.rowcount > 0 else 0
            self._conn.commit()
        return removed


class NullCache(ResultCache):
    """Drop-in no-op, used when --no-cache is passed."""

    def __init__(self) -> None:
        super().__init__(path=None, enabled=False)

    def open(self) -> NullCache:
        return self

    def get_domain(self, domain: str, ttl_hours: float) -> None:
        return None

    def put_domain(self, domain: str, payload: dict[str, Any]) -> None:
        return None

    def get_api(self, email: str, ttl_hours: float) -> None:
        return None

    def put_api(self, email: str, payload: dict[str, Any]) -> None:
        return None
