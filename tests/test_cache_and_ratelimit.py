"""Cache TTL/concurrency behaviour and the token-bucket limiter."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from emailverify.cache import NullCache, ResultCache
from emailverify.ratelimit import TokenBucket


class TestCache:
    def test_round_trip(self, tmp_path: Path) -> None:
        with ResultCache(tmp_path / "c.sqlite3") as cache:
            cache.put_domain("example.com", {"status": "active"})
            assert cache.get_domain("example.com", 1.0) == {"status": "active"}

    def test_miss_returns_none(self, tmp_path: Path) -> None:
        with ResultCache(tmp_path / "c.sqlite3") as cache:
            assert cache.get_domain("nope.example", 1.0) is None
            assert cache.misses == 1

    def test_expired_entry_is_a_miss(self, tmp_path: Path) -> None:
        with ResultCache(tmp_path / "c.sqlite3") as cache:
            cache.put_api("a@b.com", {"verdict": "deliverable"})
            assert cache.get_api("a@b.com", ttl_hours=0.0) is None

    def test_domains_and_emails_are_separate_namespaces(self, tmp_path: Path) -> None:
        with ResultCache(tmp_path / "c.sqlite3") as cache:
            cache.put_domain("x", {"kind": "domain"})
            cache.put_api("x", {"kind": "api"})
            assert cache.get_domain("x", 1.0)["kind"] == "domain"
            assert cache.get_api("x", 1.0)["kind"] == "api"

    def test_upsert_overwrites(self, tmp_path: Path) -> None:
        with ResultCache(tmp_path / "c.sqlite3") as cache:
            cache.put_domain("x", {"v": 1})
            cache.put_domain("x", {"v": 2})
            assert cache.get_domain("x", 1.0) == {"v": 2}
            assert cache.stats()["domains"] == 1

    def test_persists_across_connections(self, tmp_path: Path) -> None:
        path = tmp_path / "c.sqlite3"
        with ResultCache(path) as cache:
            cache.put_api("a@b.com", {"verdict": "deliverable"})
        with ResultCache(path) as cache:
            assert cache.get_api("a@b.com", 1.0) is not None

    def test_creates_parent_directory(self, tmp_path: Path) -> None:
        path = tmp_path / "nested" / "deeper" / "c.sqlite3"
        with ResultCache(path) as cache:
            cache.put_domain("x", {})
        assert path.exists()

    def test_corrupt_payload_is_a_miss_not_a_crash(self, tmp_path: Path) -> None:
        path = tmp_path / "c.sqlite3"
        with ResultCache(path) as cache:
            cache.put_domain("x", {"ok": True})
            cache._conn.execute("UPDATE domain_cache SET payload = ? WHERE domain = ?",
                                ("{not json", "x"))
            cache._conn.commit()
            assert cache.get_domain("x", 1.0) is None

    def test_purge(self, tmp_path: Path) -> None:
        with ResultCache(tmp_path / "c.sqlite3") as cache:
            cache.put_domain("a", {})
            cache.put_domain("b", {})
            cache.put_api("c@d.com", {})
            assert cache.purge("domains") == 2
            assert cache.stats()["domains"] == 0
            assert cache.stats()["emails"] == 1
            cache.purge("all")
            assert cache.stats()["emails"] == 0

    def test_concurrent_writes_are_safe(self, tmp_path: Path) -> None:
        # The DNS and API stages both write from a thread pool.
        with ResultCache(tmp_path / "c.sqlite3") as cache:
            def worker(n: int) -> None:
                for i in range(20):
                    cache.put_domain(f"d{n}-{i}.example", {"n": n, "i": i})

            threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert cache.stats()["domains"] == 160

    def test_null_cache_never_stores(self) -> None:
        cache = NullCache()
        cache.open()
        cache.put_domain("x", {"a": 1})
        cache.put_api("y", {"a": 1})
        assert cache.get_domain("x", 1.0) is None
        assert cache.get_api("y", 1.0) is None
        assert cache.stats()["domains"] == 0
        cache.close()

    def test_unopened_cache_is_inert(self, tmp_path: Path) -> None:
        cache = ResultCache(tmp_path / "c.sqlite3")
        assert cache.get_domain("x", 1.0) is None
        cache.put_domain("x", {})      # must not raise


class TestTokenBucket:
    def test_burst_is_immediate(self) -> None:
        bucket = TokenBucket(rate_per_second=10.0, burst=5)
        started = time.monotonic()
        for _ in range(5):
            bucket.acquire()
        assert time.monotonic() - started < 0.1

    def test_throttles_past_the_burst(self) -> None:
        bucket = TokenBucket(rate_per_second=20.0, burst=1)
        bucket.acquire()
        started = time.monotonic()
        bucket.acquire()
        # Second token has to wait ~1/20s to refill.
        assert time.monotonic() - started >= 0.03

    def test_rejects_nonpositive_rate(self) -> None:
        with pytest.raises(ValueError):
            TokenBucket(0)
        with pytest.raises(ValueError):
            TokenBucket(-1)

    def test_total_rate_is_respected_across_threads(self) -> None:
        bucket = TokenBucket(rate_per_second=50.0, burst=1)
        started = time.monotonic()

        def worker() -> None:
            for _ in range(5):
                bucket.acquire()

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 20 tokens at 50/s with a burst of 1 cannot finish faster than ~0.38s.
        assert time.monotonic() - started >= 0.3
