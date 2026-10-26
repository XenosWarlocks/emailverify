"""Core value types shared by every stage.

Design note on the code vocabulary: the local rule engine deliberately emits the
*same* numeric reason codes that Verimail's API uses (100-105 for syntax
failures, 400 for no mail server, ...). That means one lookup table explains a
rejection regardless of whether it came from stage 1, 2 or 3, and a row's
`reason` is comparable across stages.
See https://verimail.io/docs/results for the upstream table.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """Final deliverability judgement. Mirrors Verimail's four verdicts."""

    DELIVERABLE = "deliverable"
    UNDELIVERABLE = "undeliverable"
    RISKY = "risky"
    UNKNOWN = "unknown"


class Action(str, Enum):
    """What to actually do with the contact."""

    ACCEPT = "accept"
    ACCEPT_AND_CONFIRM = "accept_and_confirm"
    REJECT = "reject"


class InitialStatus(str, Enum):
    """Stage 1 + stage 2 outcome, before the paid API is consulted.

    This is the "initial status is okay" the pipeline is built around: syntax
    passed AND the domain answers for mail.
    """

    OK = "ok"
    INVALID_SYNTAX = "invalid_syntax"
    DEAD_DOMAIN = "dead_domain"
    UNKNOWN = "unknown"


class DomainStatus(str, Enum):
    ACTIVE = "active"            # has usable MX, or an A/AAAA fallback
    NO_MAIL_SERVER = "no_mail_server"   # resolves, but null MX / no MX and no A
    NXDOMAIN = "nxdomain"        # domain does not exist
    DNS_ERROR = "dns_error"      # timeout / SERVFAIL / resolver unreachable
    NOT_CHECKED = "not_checked"


# --------------------------------------------------------------------------- #
# Reason codes (shared vocabulary -- see module docstring)
# --------------------------------------------------------------------------- #

REASON_CODES: dict[int, tuple[str, Verdict, Action]] = {
    # --- local syntax failures (never billed, never need network) ---
    100: ("empty_address", Verdict.UNDELIVERABLE, Action.REJECT),
    101: ("address_too_long", Verdict.UNDELIVERABLE, Action.REJECT),
    102: ("missing_at_sign", Verdict.UNDELIVERABLE, Action.REJECT),
    103: ("local_part_too_long", Verdict.UNDELIVERABLE, Action.REJECT),
    104: ("invalid_domain", Verdict.UNDELIVERABLE, Action.REJECT),
    105: ("invalid_local_part", Verdict.UNDELIVERABLE, Action.REJECT),
    # --- deliverable ---
    200: ("mailbox_exists", Verdict.DELIVERABLE, Action.ACCEPT),
    204: ("mailbox_accepted", Verdict.DELIVERABLE, Action.ACCEPT),
    # --- risky ---
    300: ("provider_catch_all", Verdict.RISKY, Action.ACCEPT_AND_CONFIRM),
    301: ("domain_catch_all_known", Verdict.RISKY, Action.ACCEPT_AND_CONFIRM),
    302: ("domain_catch_all", Verdict.RISKY, Action.ACCEPT_AND_CONFIRM),
    406: ("mailbox_full", Verdict.RISKY, Action.ACCEPT_AND_CONFIRM),
    # --- undeliverable (network-derived) ---
    400: ("no_mail_server", Verdict.UNDELIVERABLE, Action.REJECT),
    405: ("mailbox_rejected", Verdict.UNDELIVERABLE, Action.REJECT),
    407: ("dropped_at_rcpt", Verdict.UNDELIVERABLE, Action.REJECT),
    409: ("greeting_rejected", Verdict.UNDELIVERABLE, Action.REJECT),
    410: ("no_smtp_service", Verdict.UNDELIVERABLE, Action.REJECT),
    417: ("mailbox_gone", Verdict.UNDELIVERABLE, Action.REJECT),
    # --- unknown (not billed by Verimail) ---
    404: ("greylisted", Verdict.UNKNOWN, Action.ACCEPT_AND_CONFIRM),
    408: ("no_verdict", Verdict.UNKNOWN, Action.ACCEPT_AND_CONFIRM),
    411: ("accepts_unverified", Verdict.UNKNOWN, Action.ACCEPT_AND_CONFIRM),
    412: ("relay_blocked", Verdict.UNKNOWN, Action.ACCEPT_AND_CONFIRM),
    413: ("server_busy", Verdict.UNKNOWN, Action.ACCEPT_AND_CONFIRM),
    414: ("tarpit", Verdict.UNKNOWN, Action.ACCEPT_AND_CONFIRM),
    415: ("no_greeting", Verdict.UNKNOWN, Action.ACCEPT_AND_CONFIRM),
    416: ("relay_deferred", Verdict.UNKNOWN, Action.ACCEPT_AND_CONFIRM),
    418: ("dns_unavailable", Verdict.UNKNOWN, Action.ACCEPT_AND_CONFIRM),
    419: ("timeout", Verdict.UNKNOWN, Action.ACCEPT_AND_CONFIRM),
    500: ("no_relay_available", Verdict.UNKNOWN, Action.ACCEPT_AND_CONFIRM),
    # --- locally-assigned, outside Verimail's range ---
    600: ("disposable_domain", Verdict.RISKY, Action.REJECT),
    601: ("role_account", Verdict.RISKY, Action.ACCEPT_AND_CONFIRM),
    602: ("relay_alias", Verdict.RISKY, Action.ACCEPT_AND_CONFIRM),
    603: ("not_checked", Verdict.UNKNOWN, Action.ACCEPT_AND_CONFIRM),
    604: ("duplicate", Verdict.UNKNOWN, Action.ACCEPT_AND_CONFIRM),
}

REASON_BY_NAME: dict[str, int] = {name: code for code, (name, _, _) in REASON_CODES.items()}


def reason_name(code: int | None) -> str:
    if code is None:
        return ""
    entry = REASON_CODES.get(code)
    return entry[0] if entry else f"code_{code}"


# --------------------------------------------------------------------------- #
# Stage results
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class Flags:
    """Metadata about an address. Flags describe, they do not reject.

    The one exception the pipeline makes is `disposable`, which is treated as a
    hard reject by default because a throwaway mailbox has no marketing value
    even when it is technically deliverable today.
    """

    disposable: bool = False
    role_account: bool = False
    free_provider: bool = False
    relay_provider: bool = False
    catch_all: bool = False
    plus_tagged: bool = False
    typo_suspect: bool = False
    ip_literal: bool = False
    non_ascii: bool = False

    def as_list(self) -> list[str]:
        return [k for k, v in asdict(self).items() if v]


@dataclass(slots=True)
class RuleResult:
    """Stage 1: everything decidable without touching the network."""

    raw: str
    ok: bool
    code: int
    normalized: str = ""
    local_part: str = ""
    domain: str = ""
    ascii_domain: str = ""
    canonical: str = ""
    did_you_mean: str = ""
    flags: Flags = field(default_factory=Flags)
    detail: str = ""

    @property
    def reason(self) -> str:
        return reason_name(self.code)


@dataclass(slots=True)
class DomainResult:
    """Stage 2: does this domain actually accept mail?"""

    domain: str
    status: DomainStatus = DomainStatus.NOT_CHECKED
    mx_hosts: list[str] = field(default_factory=list)
    provider: str = ""
    has_a_record: bool = False
    implicit_mx: bool = False       # no MX, falling back to A/AAAA per RFC 5321 5.1
    null_mx: bool = False           # explicit "." MX -- domain declares it takes no mail
    has_spf: bool = False
    has_dmarc: bool = False
    # Whether the lookup actually ran. Without this, has_spf=False is
    # ambiguous between "domain publishes no SPF" and "we never asked",
    # and scoring must not penalise the second case.
    spf_checked: bool = False
    dmarc_checked: bool = False
    smtp_banner: str = ""
    smtp_reachable: bool | None = None
    error: str = ""
    elapsed_ms: int = 0
    from_cache: bool = False

    @property
    def is_active(self) -> bool:
        return self.status is DomainStatus.ACTIVE


@dataclass(slots=True)
class ApiResult:
    """Stage 3: Verimail's answer."""

    email: str
    verdict: Verdict = Verdict.UNKNOWN
    reason: str = ""
    code: int | None = None
    suggested_action: Action = Action.ACCEPT_AND_CONFIRM
    did_you_mean: str = ""
    billed: bool = False
    provider: str = ""
    latency_ms: int = 0
    flags: Flags = field(default_factory=Flags)
    deliverable: bool = False
    result_label: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    from_cache: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass(slots=True)
class Verification:
    """One row of the export, fully judged."""

    record_id: str
    email_raw: str
    rule: RuleResult
    domain: DomainResult
    api: ApiResult | None = None
    initial_status: InitialStatus = InitialStatus.UNKNOWN
    final_verdict: Verdict = Verdict.UNKNOWN
    final_code: int | None = None
    action: Action = Action.ACCEPT_AND_CONFIRM
    risk_score: int = 0
    confidence: str = "low"
    # When dedupe collapses a sub-addressed form onto the mailbox it reaches,
    # this records which address was actually sent to the API. Group rows by
    # it (or by rule.canonical) to find contacts sharing one inbox.
    verified_as: str = ""
    notes: list[str] = field(default_factory=list)
    checked_at: str = ""

    @property
    def final_reason(self) -> str:
        return reason_name(self.final_code)
