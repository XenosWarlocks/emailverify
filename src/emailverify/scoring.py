"""Turning three stage results into one decision.

Precedence is strict and deliberate:

  1. Stage 1 (syntax) is absolute. If it fails, nothing else is consulted --
     there is no point resolving DNS for "not an email", and we must never pay
     the API to tell us so.
  2. Stage 3 (Verimail) wins over stage 2 when present, because an SMTP-level
     answer strictly dominates a DNS-level guess.
  3. Stage 2 (DNS) is the fallback and the source of `initial_status`.

The risk score is advisory: a 0-100 number for sorting and for HubSpot
segmentation, NOT an input to the verdict. Two addresses can share a verdict
and differ wildly in score (a role account at a real company vs. a personal
mailbox), and that difference is what a human actually wants to sort on.
"""

from __future__ import annotations

from emailverify.models import (
    Action,
    DomainResult,
    DomainStatus,
    InitialStatus,
    RuleResult,
    Verdict,
    Verification,
)

# Penalty weights. Tuned so that any single signal leaves an address usable,
# but a stack of them does not.
_RISK_WEIGHTS = {
    "undeliverable": 100,
    "dead_domain": 100,
    "invalid_syntax": 100,
    "disposable": 90,
    "typo_suspect": 45,
    "catch_all": 30,
    "mailbox_full": 30,
    "relay_provider": 25,
    "role_account": 20,
    "unknown": 25,
    "no_spf": 10,
    "free_provider": 5,
    "plus_tagged": 5,
}


def initial_status(rule: RuleResult, domain: DomainResult) -> InitialStatus:
    """The stage 1 + stage 2 answer -- 'is this okay to start with?'"""
    if not rule.ok:
        return InitialStatus.INVALID_SYNTAX
    if domain.status is DomainStatus.ACTIVE:
        return InitialStatus.OK
    if domain.status in (DomainStatus.NO_MAIL_SERVER, DomainStatus.NXDOMAIN):
        return InitialStatus.DEAD_DOMAIN
    # NOT_CHECKED (stage skipped) and DNS_ERROR both mean "we don't know yet",
    # which is importantly different from "bad".
    return InitialStatus.UNKNOWN


def risk_score(v: Verification) -> tuple[int, list[str]]:
    """Advisory 0-100 risk score plus the flags that produced it."""
    penalties: list[tuple[str, int]] = []

    def add(name: str) -> None:
        penalties.append((name, _RISK_WEIGHTS[name]))

    if not v.rule.ok:
        add("invalid_syntax")
    if v.initial_status is InitialStatus.DEAD_DOMAIN:
        add("dead_domain")

    flags = v.rule.flags
    if flags.disposable:
        add("disposable")
    if flags.typo_suspect:
        add("typo_suspect")
    if flags.relay_provider:
        add("relay_provider")
    if flags.role_account:
        add("role_account")
    if flags.free_provider:
        add("free_provider")
    if flags.plus_tagged:
        add("plus_tagged")

    if v.api is not None and v.api.ok:
        if v.api.verdict is Verdict.UNDELIVERABLE:
            add("undeliverable")
        if v.api.verdict is Verdict.UNKNOWN:
            add("unknown")
        if v.api.flags.catch_all:
            add("catch_all")
        if v.api.reason == "mailbox_full":
            add("mailbox_full")
    elif v.initial_status is InitialStatus.UNKNOWN:
        add("unknown")

    # A live domain that publishes no SPF is unusual for anyone who sends real
    # mail. Only scored when --check-spf actually ran.
    if (
        v.domain.spf_checked
        and v.domain.status is DomainStatus.ACTIVE
        and not v.domain.has_spf
    ):
        add("no_spf")

    score = min(100, sum(w for _, w in penalties))
    return score, [name for name, _ in penalties]


def confidence(v: Verification) -> str:
    """How much to trust `final_verdict`."""
    if not v.rule.ok:
        return "high"           # syntax is deterministic
    if v.final_code == 600:
        # A disposable-provider match is a list lookup, not an inference: we
        # are certain about the decision even though the mailbox may well
        # accept mail right now.
        return "high"
    if v.api is not None and v.api.ok:
        if v.api.verdict in (Verdict.DELIVERABLE, Verdict.UNDELIVERABLE):
            return "high"
        if v.api.verdict is Verdict.RISKY:
            return "medium"
        return "low"            # unknown
    if v.domain.status is DomainStatus.NXDOMAIN or v.domain.null_mx:
        return "high"           # an explicit "no" from DNS is definitive
    if v.domain.status is DomainStatus.ACTIVE:
        return "low"            # domain is alive; the mailbox is unproven
    return "low"


def reconcile(v: Verification, reject_disposable: bool = True) -> Verification:
    """Fill in initial_status, final verdict/code, action, score and confidence."""
    v.initial_status = initial_status(v.rule, v.domain)

    # 1. Syntax is absolute.
    if not v.rule.ok:
        v.final_verdict = Verdict.UNDELIVERABLE
        v.final_code = v.rule.code
        v.action = Action.REJECT

    # 2. The API's answer, when we have a usable one.
    elif v.api is not None and v.api.ok:
        v.final_verdict = v.api.verdict
        v.final_code = v.api.code
        v.action = v.api.suggested_action

    # 3. Otherwise fall back to DNS.
    elif v.initial_status is InitialStatus.DEAD_DOMAIN:
        v.final_verdict = Verdict.UNDELIVERABLE
        v.final_code = 400                      # no_mail_server
        v.action = Action.REJECT
    elif v.initial_status is InitialStatus.OK:
        # The domain accepts mail but we never proved this mailbox exists, so
        # the honest verdict is unknown -- not "valid".
        v.final_verdict = Verdict.UNKNOWN
        v.final_code = 603                      # not_checked
        v.action = Action.ACCEPT_AND_CONFIRM
        v.notes.append("domain active; mailbox not individually verified")
    else:
        v.final_verdict = Verdict.UNKNOWN
        v.final_code = 418 if v.domain.status is DomainStatus.DNS_ERROR else 603
        v.action = Action.ACCEPT_AND_CONFIRM

    # Disposable is a business rule, not a deliverability one: these addresses
    # usually *do* accept mail, which is exactly why neither DNS nor SMTP will
    # flag them. Applied last so it can override an "accept".
    if v.rule.ok and (v.rule.flags.disposable or (v.api is not None and v.api.flags.disposable)):
        v.rule.flags.disposable = True
        if reject_disposable:
            v.final_verdict = Verdict.RISKY
            v.final_code = 600                  # disposable_domain
            v.action = Action.REJECT
            v.notes.append("disposable mailbox provider")
        elif v.final_verdict is Verdict.DELIVERABLE:
            v.final_verdict = Verdict.RISKY
            v.notes.append("disposable mailbox provider (not rejected by config)")

    # Carry the API's catch-all finding onto the row's flags so the CSV shows it.
    if v.api is not None and v.api.flags.catch_all:
        v.rule.flags.catch_all = True

    # Prefer the API's spelling suggestion; it sees typos our list cannot.
    if v.api is not None and v.api.did_you_mean and not v.rule.did_you_mean:
        v.rule.did_you_mean = v.api.did_you_mean
        v.rule.flags.typo_suspect = True

    # Score and confidence read the final verdict, so they come last.
    v.risk_score, flags = risk_score(v)
    v.confidence = confidence(v)
    if flags:
        v.notes.append("risk: " + ",".join(flags))
    return v


def mailable(v: Verification) -> bool:
    """Would you put this address in a campaign?"""
    return v.action is not Action.REJECT and v.final_verdict is not Verdict.UNDELIVERABLE
