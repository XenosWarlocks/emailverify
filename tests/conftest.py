from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
# src/ for the package under test; ROOT so `tests.conftest` is importable by
# the helper classes the pipeline tests share.
for entry in (str(SRC), str(ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from emailverify.config import ApiConfig, Config, DnsConfig, RuleConfig  # noqa: E402
from emailverify.models import DomainResult, DomainStatus  # noqa: E402


@pytest.fixture
def sample_csv() -> Path:
    return ROOT / "data" / "raw" / "sample_hubspot_export.csv"


@pytest.fixture
def rule_cfg() -> RuleConfig:
    return RuleConfig()


@pytest.fixture
def base_config(tmp_path: Path, sample_csv: Path) -> Config:
    cfg = Config(
        input_path=sample_csv,
        outdir=tmp_path / "out",
        cache_path=tmp_path / "cache.sqlite3",
    )
    cfg.dns = DnsConfig(workers=4, timeout=1.0, lifetime=2.0)
    cfg.api = ApiConfig(api_key="test-key", requests_per_second=1000.0)
    return cfg


class FakeDomainChecker:
    """Stand-in for DomainChecker with a scripted domain -> status map."""

    def __init__(self, statuses: dict[str, DomainStatus], mx: str = "mx.example.com"):
        self.statuses = statuses
        self.mx = mx
        self.calls: list[str] = []

    def check(self, domain: str) -> DomainResult:
        self.calls.append(domain)
        status = self.statuses.get(domain, DomainStatus.ACTIVE)
        res = DomainResult(domain=domain, status=status)
        if status is DomainStatus.ACTIVE:
            res.mx_hosts = [self.mx]
            res.provider = "example.com"
        elif status is DomainStatus.NXDOMAIN:
            res.error = "domain does not exist"
        elif status is DomainStatus.NO_MAIL_SERVER:
            res.error = "no MX and no A/AAAA record"
        return res

    def check_many(self, domains, progress=None) -> dict[str, DomainResult]:
        out = {}
        for d in sorted({x for x in domains if x}):
            out[d] = self.check(d)
            if progress is not None:
                progress(d, out[d])
        return out


@pytest.fixture
def fake_domain_checker():
    return FakeDomainChecker
