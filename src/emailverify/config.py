"""Configuration: defaults, environment overrides, CLI overrides.

Precedence (lowest to highest): dataclass defaults -> .env / environment ->
explicit CLI flags.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:  # python-dotenv is a convenience, not a requirement
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    def load_dotenv(*_args, **_kwargs):  # type: ignore[misc]
        return False


class ConfigError(Exception):
    """Raised for a configuration problem the user must fix."""


def _env_str(key: str, default: str) -> str:
    v = os.environ.get(key, "").strip()
    return v or default


def _env_int(key: str, default: int) -> int:
    v = os.environ.get(key, "").strip()
    if not v:
        return default
    try:
        return int(v)
    except ValueError as exc:
        raise ConfigError(f"{key}={v!r} is not an integer") from exc


def _env_float(key: str, default: float) -> float:
    v = os.environ.get(key, "").strip()
    if not v:
        return default
    try:
        return float(v)
    except ValueError as exc:
        raise ConfigError(f"{key}={v!r} is not a number") from exc


@dataclass(slots=True)
class RuleConfig:
    """Stage 1 knobs."""

    disposable_list: Path | None = None
    free_list: Path | None = None
    relay_list: Path | None = None
    role_list: Path | None = None
    detect_typos: bool = True
    # Treat a disposable address as a hard reject rather than merely risky.
    reject_disposable: bool = True


@dataclass(slots=True)
class DnsConfig:
    """Stage 2 knobs."""

    workers: int = 16
    timeout: float = 5.0
    lifetime: float = 10.0
    nameservers: list[str] = field(default_factory=list)
    check_spf: bool = False
    check_dmarc: bool = False
    # TCP-connect to port 25 on the primary MX. Off by default: most consumer
    # and cloud networks block outbound 25, which makes the result meaningless
    # rather than merely slow.
    smtp_probe: bool = False
    smtp_probe_timeout: float = 5.0
    cache_ttl_hours: float = 168.0  # 7 days


@dataclass(slots=True)
class ApiConfig:
    """Stage 3 knobs."""

    api_key: str = ""
    base_url: str = "https://api.verimail.io/v3"
    # Per-verification SMTP budget sent to Verimail. Their max is 45s; 15s
    # catches the overwhelming majority and keeps a large run bounded.
    verify_timeout_ms: int = 15000
    http_timeout: float = 60.0
    requests_per_second: float = 5.0
    max_retries: int = 4
    evidence: bool = False
    cache_ttl_hours: float = 720.0  # 30 days
    # Hard ceiling on billable calls per run. A guard rail against a bad CSV
    # eating a month of credits; 0 means unlimited.
    max_calls: int = 0

    def require_key(self) -> str:
        if not self.api_key:
            raise ConfigError(
                "No Verimail API key. Set VERIMAIL_KEY in .env or pass --api-key, "
                "or run with --skip-api to use stages 1-2 only."
            )
        return self.api_key


@dataclass(slots=True)
class Config:
    input_path: Path = Path("data/raw/sample_hubspot_export.csv")
    outdir: Path = Path("data/out")
    email_column: str = "Email"
    id_column: str = "Record ID"
    cache_path: Path = Path(".cache/emailverify.sqlite3")
    use_cache: bool = True
    limit: int = 0
    skip_domain: bool = False
    skip_api: bool = False
    # Which rows reach the paid API:
    #   "rules"        -> every address that passes stage 1
    #   "rules+domain" -> stage 1 passers whose domain is not provably dead
    #   "unresolved"   -> only rows stages 1-2 could not settle
    api_gate: str = "rules+domain"
    # Send only one API call per canonical mailbox and copy the answer to its
    # duplicates (a.b+tag@gmail.com and ab@gmail.com are one inbox).
    dedupe: bool = True
    split_outputs: bool = True
    rules: RuleConfig = field(default_factory=RuleConfig)
    dns: DnsConfig = field(default_factory=DnsConfig)
    api: ApiConfig = field(default_factory=ApiConfig)

    @classmethod
    def from_env(cls, env_file: str | Path | None = ".env") -> Config:
        if env_file and Path(env_file).exists():
            load_dotenv(env_file, override=False)
        cfg = cls()
        cfg.cache_path = Path(_env_str("EV_CACHE_PATH", str(cfg.cache_path)))
        cfg.dns.workers = _env_int("EV_DNS_WORKERS", cfg.dns.workers)
        cfg.dns.timeout = _env_float("EV_DNS_TIMEOUT", cfg.dns.timeout)
        cfg.api.api_key = _env_str("VERIMAIL_KEY", cfg.api.api_key)
        cfg.api.base_url = _env_str("VERIMAIL_BASE_URL", cfg.api.base_url).rstrip("/")
        cfg.api.requests_per_second = _env_float("VERIMAIL_RPS", cfg.api.requests_per_second)
        cfg.api.verify_timeout_ms = _env_int("VERIMAIL_TIMEOUT_MS", cfg.api.verify_timeout_ms)
        return cfg

    def validate(self) -> None:
        if not self.input_path.exists():
            raise ConfigError(f"Input CSV not found: {self.input_path}")
        if self.api_gate not in {"rules", "rules+domain", "unresolved"}:
            raise ConfigError(
                f"--api-gate must be rules, rules+domain or unresolved (got {self.api_gate!r})"
            )
        if not 1000 <= self.api.verify_timeout_ms <= 45000:
            raise ConfigError("Verimail timeout must be between 1000 and 45000 ms")
        if self.api.requests_per_second <= 0:
            raise ConfigError("requests-per-second must be > 0")
        if self.dns.workers < 1:
            raise ConfigError("dns workers must be >= 1")
        for label, p in (
            ("--disposable-list", self.rules.disposable_list),
            ("--free-list", self.rules.free_list),
            ("--relay-list", self.rules.relay_list),
            ("--role-list", self.rules.role_list),
        ):
            if p is not None and not Path(p).exists():
                raise ConfigError(f"{label}: file not found: {p}")
