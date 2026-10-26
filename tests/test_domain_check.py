"""Stage 2 domain liveness, against a scripted resolver."""

from __future__ import annotations

import dns.exception
import dns.resolver

from emailverify.cache import ResultCache
from emailverify.config import DnsConfig
from emailverify.models import DomainStatus
from emailverify.stages.domain_check import DomainChecker


class FakeMX:
    def __init__(self, preference: int, exchange: str) -> None:
        self.preference = preference
        self.exchange = exchange


class FakeTXT:
    def __init__(self, value: str) -> None:
        # dnspython exposes TXT rdata as a tuple of byte strings that must be
        # concatenated -- records longer than 255 bytes arrive split.
        self.strings = tuple(
            value.encode()[i:i + 255] for i in range(0, max(len(value.encode()), 1), 255)
        ) or (b"",)


class FakeAnswer:
    def __init__(self, records: list) -> None:
        self._records = records
        self.rrset = records if records else None

    def __iter__(self):
        return iter(self._records)

    def __len__(self) -> int:
        return len(self._records)


class FakeResolver:
    """Scripted resolver. `script` maps (name, rdtype) -> records | Exception."""

    def __init__(self, script: dict) -> None:
        self.script = script
        self.queries: list[tuple[str, str]] = []
        self.timeout = 1.0
        self.lifetime = 2.0
        self.nameservers: list[str] = []

    def resolve(self, name: str, rdtype: str, raise_on_no_answer: bool = True):
        key = (name.lower(), rdtype.upper())
        self.queries.append(key)
        outcome = self.script.get(key, [])
        if isinstance(outcome, Exception):
            raise outcome
        return FakeAnswer(outcome)


def make_checker(script: dict, cfg: DnsConfig | None = None, cache=None) -> DomainChecker:
    return DomainChecker(cfg or DnsConfig(), cache=cache, resolver=FakeResolver(script))


class TestStatus:
    def test_mx_records_mean_active(self) -> None:
        checker = make_checker({
            ("example.com", "MX"): [FakeMX(10, "mx1.example.com."),
                                    FakeMX(20, "mx2.example.com.")],
        })
        res = checker.check("example.com")
        assert res.status is DomainStatus.ACTIVE
        assert res.is_active
        # Sorted by preference, trailing dot stripped.
        assert res.mx_hosts == ["mx1.example.com", "mx2.example.com"]
        assert res.provider == "example.com"

    def test_mx_sorted_by_preference(self) -> None:
        checker = make_checker({
            ("example.com", "MX"): [FakeMX(50, "backup.example.com."),
                                    FakeMX(5, "primary.example.com.")],
        })
        assert checker.check("example.com").mx_hosts[0] == "primary.example.com"

    def test_null_mx_is_definitively_dead(self) -> None:
        # RFC 7505: a single "." exchange is an explicit "accepts no mail".
        checker = make_checker({("nomail.example", "MX"): [FakeMX(0, ".")]})
        res = checker.check("nomail.example")
        assert res.status is DomainStatus.NO_MAIL_SERVER
        assert res.null_mx
        assert "7505" in res.error

    def test_falls_back_to_a_record(self) -> None:
        # RFC 5321 5.1: no MX means the A record is an implicit MX.
        checker = make_checker({
            ("legacy.example", "MX"): [],
            ("legacy.example", "A"): ["93.184.216.34"],
        })
        res = checker.check("legacy.example")
        assert res.status is DomainStatus.ACTIVE
        assert res.implicit_mx
        assert res.has_a_record

    def test_falls_back_to_aaaa_record(self) -> None:
        checker = make_checker({
            ("v6.example", "MX"): [],
            ("v6.example", "A"): [],
            ("v6.example", "AAAA"): ["2606:2800:220:1:248:1893:25c8:1946"],
        })
        assert checker.check("v6.example").status is DomainStatus.ACTIVE

    def test_no_mx_and_no_address_is_dead(self) -> None:
        checker = make_checker({
            ("parked.example", "MX"): [],
            ("parked.example", "A"): [],
            ("parked.example", "AAAA"): [],
        })
        res = checker.check("parked.example")
        assert res.status is DomainStatus.NO_MAIL_SERVER
        assert not res.is_active

    def test_nxdomain(self) -> None:
        checker = make_checker({("gone.example", "MX"): dns.resolver.NXDOMAIN()})
        res = checker.check("gone.example")
        assert res.status is DomainStatus.NXDOMAIN

    def test_timeout_is_unknown_not_dead(self) -> None:
        # The crucial distinction: a resolver hiccup must never mark a good
        # contact invalid.
        checker = make_checker({("slow.example", "MX"): dns.exception.Timeout()})
        res = checker.check("slow.example")
        assert res.status is DomainStatus.DNS_ERROR
        assert not res.is_active

    def test_no_nameservers_is_unknown(self) -> None:
        checker = make_checker({("x.example", "MX"): dns.resolver.NoNameservers()})
        assert checker.check("x.example").status is DomainStatus.DNS_ERROR

    def test_empty_domain(self) -> None:
        assert make_checker({}).check("").status is DomainStatus.NXDOMAIN

    def test_trailing_dot_and_case_normalized(self) -> None:
        checker = make_checker({("example.com", "MX"): [FakeMX(10, "mx.example.com.")]})
        assert checker.check("EXAMPLE.COM.").status is DomainStatus.ACTIVE


class TestSpfDmarc:
    def test_not_queried_by_default(self) -> None:
        resolver = FakeResolver({("example.com", "MX"): [FakeMX(10, "mx.example.com.")]})
        checker = DomainChecker(DnsConfig(), resolver=resolver)
        res = checker.check("example.com")
        assert not res.spf_checked
        assert ("example.com", "TXT") not in resolver.queries

    def test_spf_detected(self) -> None:
        checker = make_checker(
            {
                ("example.com", "MX"): [FakeMX(10, "mx.example.com.")],
                ("example.com", "TXT"): [FakeTXT("v=spf1 include:_spf.google.com ~all")],
            },
            DnsConfig(check_spf=True, check_dmarc=True),
        )
        res = checker.check("example.com")
        assert res.spf_checked and res.has_spf
        assert res.dmarc_checked and not res.has_dmarc

    def test_dmarc_detected_at_subdomain(self) -> None:
        checker = make_checker(
            {
                ("example.com", "MX"): [FakeMX(10, "mx.example.com.")],
                ("_dmarc.example.com", "TXT"): [FakeTXT("v=DMARC1; p=reject")],
            },
            DnsConfig(check_dmarc=True),
        )
        assert checker.check("example.com").has_dmarc

    def test_unrelated_txt_is_not_spf(self) -> None:
        checker = make_checker(
            {
                ("example.com", "MX"): [FakeMX(10, "mx.example.com.")],
                ("example.com", "TXT"): [FakeTXT("google-site-verification=abc")],
            },
            DnsConfig(check_spf=True),
        )
        res = checker.check("example.com")
        assert res.spf_checked and not res.has_spf


class TestBatchAndCache:
    def test_check_many_deduplicates(self) -> None:
        resolver = FakeResolver({("gmail.com", "MX"): [FakeMX(10, "gmail-smtp-in.l.google.com.")]})
        checker = DomainChecker(DnsConfig(workers=4), resolver=resolver)
        results = checker.check_many(["gmail.com"] * 5 + ["GMAIL.COM"])
        assert set(results) == {"gmail.com"}
        # Five rows on one domain must cost one lookup, not five.
        assert resolver.queries.count(("gmail.com", "MX")) == 1

    def test_cache_round_trip(self, tmp_path) -> None:
        script = {("example.com", "MX"): [FakeMX(10, "mx.example.com.")]}
        with ResultCache(tmp_path / "c.sqlite3") as cache:
            first = make_checker(script, cache=cache).check("example.com")
            assert not first.from_cache

            # A fresh checker with an empty script must still answer, from cache.
            second = make_checker({}, cache=cache).check("example.com")
            assert second.from_cache
            assert second.status is DomainStatus.ACTIVE
            assert second.mx_hosts == ["mx.example.com"]

    def test_transient_errors_are_not_cached(self, tmp_path) -> None:
        # Caching a timeout would pin a good domain to "unknown" for the TTL.
        with ResultCache(tmp_path / "c.sqlite3") as cache:
            make_checker(
                {("flaky.example", "MX"): dns.exception.Timeout()}, cache=cache
            ).check("flaky.example")
            assert cache.get_domain("flaky.example", 168.0) is None

    def test_dead_domains_are_cached(self, tmp_path) -> None:
        with ResultCache(tmp_path / "c.sqlite3") as cache:
            make_checker(
                {("gone.example", "MX"): dns.resolver.NXDOMAIN()}, cache=cache
            ).check("gone.example")
            assert cache.get_domain("gone.example", 168.0) is not None


def test_smtp_probe_failure_does_not_change_status(monkeypatch) -> None:
    # Port 25 is blocked on most networks, so a failed probe is information
    # about us, not about the domain. It must never downgrade a verdict.
    import socket

    def refuse(*_a, **_k):
        raise OSError("connection refused")

    monkeypatch.setattr(socket, "create_connection", refuse)
    checker = make_checker(
        {("example.com", "MX"): [FakeMX(10, "mx.example.com.")]},
        DnsConfig(smtp_probe=True),
    )
    res = checker.check("example.com")
    assert res.status is DomainStatus.ACTIVE
    assert res.smtp_reachable is False
