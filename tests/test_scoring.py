"""Reconciliation: how three stage results collapse into one decision."""

from __future__ import annotations

from emailverify.models import (
    Action,
    ApiResult,
    DomainResult,
    DomainStatus,
    Flags,
    InitialStatus,
    Verdict,
    Verification,
)
from emailverify.rules import RuleEngine
from emailverify.scoring import mailable, reconcile

ENGINE = RuleEngine()


def build(email: str, domain_status=DomainStatus.ACTIVE, api: ApiResult | None = None):
    rule = ENGINE.check(email)
    dom = DomainResult(domain=rule.ascii_domain, status=domain_status)
    if domain_status is DomainStatus.ACTIVE:
        dom.mx_hosts = ["mx.example.com"]
    v = Verification(record_id="1", email_raw=email, rule=rule, domain=dom, api=api)
    return reconcile(v)


class TestInitialStatus:
    def test_ok_when_syntax_passes_and_domain_is_live(self) -> None:
        v = build("kdanny@akrodlabs.com")
        assert v.initial_status is InitialStatus.OK

    def test_invalid_syntax(self) -> None:
        v = build("not-an-email")
        assert v.initial_status is InitialStatus.INVALID_SYNTAX

    def test_dead_domain(self) -> None:
        assert build("a@gone.example", DomainStatus.NXDOMAIN).initial_status is (
            InitialStatus.DEAD_DOMAIN
        )
        assert build("a@parked.example", DomainStatus.NO_MAIL_SERVER).initial_status is (
            InitialStatus.DEAD_DOMAIN
        )

    def test_dns_error_is_unknown_not_dead(self) -> None:
        v = build("a@flaky.example", DomainStatus.DNS_ERROR)
        assert v.initial_status is InitialStatus.UNKNOWN
        assert v.final_verdict is Verdict.UNKNOWN
        # A resolver problem must not reject a contact.
        assert mailable(v)

    def test_skipped_domain_stage_is_unknown(self) -> None:
        v = build("a@example.com", DomainStatus.NOT_CHECKED)
        assert v.initial_status is InitialStatus.UNKNOWN


class TestPrecedence:
    def test_syntax_failure_beats_everything(self) -> None:
        api = ApiResult(email="x", verdict=Verdict.DELIVERABLE, reason="mailbox_exists", code=200)
        v = build("not-an-email", api=api)
        assert v.final_verdict is Verdict.UNDELIVERABLE
        assert v.action is Action.REJECT
        assert v.confidence == "high"

    def test_api_overrides_a_live_domain(self) -> None:
        api = ApiResult(
            email="a@example.com", verdict=Verdict.UNDELIVERABLE,
            reason="mailbox_rejected", code=405, suggested_action=Action.REJECT,
        )
        v = build("a@example.com", DomainStatus.ACTIVE, api)
        assert v.final_verdict is Verdict.UNDELIVERABLE
        assert v.final_reason == "mailbox_rejected"
        assert not mailable(v)

    def test_api_can_rescue_a_domain_dns_could_not_resolve(self) -> None:
        api = ApiResult(
            email="a@example.com", verdict=Verdict.DELIVERABLE,
            reason="mailbox_exists", code=200, suggested_action=Action.ACCEPT,
        )
        v = build("a@example.com", DomainStatus.DNS_ERROR, api)
        assert v.final_verdict is Verdict.DELIVERABLE
        assert v.confidence == "high"

    def test_live_domain_without_api_is_unknown_not_valid(self) -> None:
        # The domain accepting mail does not prove this mailbox exists.
        v = build("someone@akrodlabs.com", DomainStatus.ACTIVE)
        assert v.final_verdict is Verdict.UNKNOWN
        assert v.final_reason == "not_checked"
        assert v.action is Action.ACCEPT_AND_CONFIRM
        assert v.confidence == "low"
        assert mailable(v)

    def test_dead_domain_without_api_is_undeliverable(self) -> None:
        v = build("a@gone.example", DomainStatus.NXDOMAIN)
        assert v.final_verdict is Verdict.UNDELIVERABLE
        assert v.final_code == 400
        assert v.confidence == "high"
        assert not mailable(v)


class TestDisposable:
    def test_rejected_by_default(self) -> None:
        v = build("fakeha3890@ofags.com")
        assert v.rule.flags.disposable
        assert v.action is Action.REJECT
        assert v.final_reason == "disposable_domain"
        assert not mailable(v)
        # A list lookup is deterministic, so the decision is certain even
        # though the mailbox probably does accept mail today.
        assert v.confidence == "high"

    def test_overrides_a_deliverable_api_verdict(self) -> None:
        # Throwaway mailboxes really do accept mail, which is why neither DNS
        # nor SMTP flags them. The business rule has to win.
        api = ApiResult(
            email="fakeha3890@ofags.com", verdict=Verdict.DELIVERABLE,
            reason="mailbox_exists", code=200, suggested_action=Action.ACCEPT,
        )
        v = build("fakeha3890@ofags.com", DomainStatus.ACTIVE, api)
        assert v.final_verdict is Verdict.RISKY
        assert v.action is Action.REJECT

    def test_allow_disposable_downgrades_instead_of_rejecting(self) -> None:
        rule = ENGINE.check("fakeha3890@ofags.com")
        v = Verification(
            record_id="1", email_raw=rule.normalized, rule=rule,
            domain=DomainResult(domain=rule.ascii_domain, status=DomainStatus.ACTIVE,
                                mx_hosts=["mx.example.com"]),
            api=ApiResult(email=rule.normalized, verdict=Verdict.DELIVERABLE,
                          reason="mailbox_exists", code=200,
                          suggested_action=Action.ACCEPT),
        )
        reconcile(v, reject_disposable=False)
        assert v.final_verdict is Verdict.RISKY
        assert v.action is Action.ACCEPT
        assert mailable(v)

    def test_api_flag_catches_what_the_local_list_misses(self) -> None:
        api = ApiResult(
            email="a@brand-new-temp.example", verdict=Verdict.DELIVERABLE,
            reason="mailbox_exists", code=200, suggested_action=Action.ACCEPT,
            flags=Flags(disposable=True),
        )
        v = build("a@brand-new-temp.example", DomainStatus.ACTIVE, api)
        assert v.rule.flags.disposable       # promoted onto the row
        assert v.action is Action.REJECT


class TestRiskScore:
    def test_clean_corporate_address_scores_zero(self) -> None:
        api = ApiResult(email="k@akrodlabs.com", verdict=Verdict.DELIVERABLE,
                        reason="mailbox_exists", code=200, suggested_action=Action.ACCEPT)
        assert build("kdanny@akrodlabs.com", DomainStatus.ACTIVE, api).risk_score == 0

    def test_free_provider_is_a_small_penalty_only(self) -> None:
        api = ApiResult(email="a@gmail.com", verdict=Verdict.DELIVERABLE,
                        reason="mailbox_exists", code=200, suggested_action=Action.ACCEPT)
        v = build("mufij7114@gmail.com", DomainStatus.ACTIVE, api)
        assert 0 < v.risk_score <= 10
        assert mailable(v)

    def test_disposable_scores_high(self) -> None:
        assert build("fakeha3890@ofags.com").risk_score >= 90

    def test_invalid_syntax_scores_max(self) -> None:
        assert build("not-an-email").risk_score == 100

    def test_score_is_capped_at_100(self) -> None:
        v = build("sales@ofags.com", DomainStatus.NXDOMAIN)
        assert v.risk_score == 100

    def test_relay_and_role_accumulate(self) -> None:
        clean = build("kdanny@akrodlabs.com").risk_score
        relay = build("h1_analyst_jack@wearehackerone.com").risk_score
        assert relay > clean

    def test_no_spf_only_penalised_when_checked(self) -> None:
        rule = ENGINE.check("a@akrodlabs.com")
        unchecked = Verification(
            record_id="1", email_raw="a@akrodlabs.com", rule=rule,
            domain=DomainResult(domain="akrodlabs.com", status=DomainStatus.ACTIVE,
                                mx_hosts=["mx.example.com"], spf_checked=False),
        )
        checked = Verification(
            record_id="2", email_raw="a@akrodlabs.com", rule=ENGINE.check("a@akrodlabs.com"),
            domain=DomainResult(domain="akrodlabs.com", status=DomainStatus.ACTIVE,
                                mx_hosts=["mx.example.com"], spf_checked=True, has_spf=False),
        )
        reconcile(unchecked)
        reconcile(checked)
        assert checked.risk_score > unchecked.risk_score


def test_api_typo_suggestion_is_adopted() -> None:
    api = ApiResult(email="a@exampel.com", verdict=Verdict.UNDELIVERABLE,
                    reason="no_mail_server", code=400, suggested_action=Action.REJECT,
                    did_you_mean="a@example.com")
    v = build("a@exampel.com", DomainStatus.NO_MAIL_SERVER, api)
    assert v.rule.did_you_mean == "a@example.com"
    assert v.rule.flags.typo_suspect


def test_api_error_falls_back_to_dns() -> None:
    # A failed API call must degrade to the stage-2 answer, not to "invalid".
    broken = ApiResult(email="a@example.com", error="network error: timed out")
    v = build("a@akrodlabs.com", DomainStatus.ACTIVE, broken)
    assert v.final_verdict is Verdict.UNKNOWN
    assert v.initial_status is InitialStatus.OK
    assert mailable(v)
