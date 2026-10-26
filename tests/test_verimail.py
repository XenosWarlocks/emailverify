"""Stage 3 client: response parsing, error classes, retries, caching, billing."""

from __future__ import annotations

import json

import pytest
import requests

from emailverify.cache import ResultCache
from emailverify.config import ApiConfig
from emailverify.models import Action, Verdict
from emailverify.stages.verimail import (
    VerimailClient,
    VerimailFatalError,
    VerimailRequestError,
    VerimailTransientError,
)


class FakeResponse:
    def __init__(self, status_code: int, body=None, headers: dict | None = None) -> None:
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.text = "" if body is None else json.dumps(body)

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeSession:
    """Replays a scripted list of responses and records what was sent."""

    def __init__(self, responses: list) -> None:
        self.responses = list(responses)
        self.requests: list[dict] = []

    def post(self, url, data=None, headers=None, timeout=None):
        self.requests.append(
            {"url": url, "data": data, "headers": headers, "timeout": timeout}
        )
        if not self.responses:
            raise AssertionError("FakeSession ran out of scripted responses")
        nxt = self.responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


def make_client(responses: list, cfg: ApiConfig | None = None, cache=None) -> VerimailClient:
    cfg = cfg or ApiConfig(api_key="k", requests_per_second=1000.0, max_retries=2)
    return VerimailClient(cfg, cache=cache, session=FakeSession(responses))


DELIVERABLE = {
    "email": "emma.wilson@acme-corp.com",
    "verdict": "deliverable",
    "reason": "mailbox_exists",
    "code": 200,
    "billed": True,
    "suggested_action": "accept",
    "did_you_mean": "",
    "flags": {"disposable": False, "role_account": False,
              "free_provider": False, "catch_all": False},
    "provider": "google.com",
    "latency_ms": 412,
    "deliverable": True,
    "result": "deliverable",
    "status": "success",
}


class TestRequestShape:
    def test_posts_to_verify_with_bearer_auth(self) -> None:
        client = make_client([FakeResponse(200, DELIVERABLE)])
        client.verify("emma.wilson@acme-corp.com")
        sent = client.session.requests[0]
        assert sent["url"] == "https://api.verimail.io/v3/verify"
        assert sent["headers"]["Authorization"] == "Bearer k"
        assert sent["data"]["email"] == "emma.wilson@acme-corp.com"
        assert sent["data"]["timeout"] == "15000"
        # evidence is opt-in; it makes responses much larger.
        assert "evidence" not in sent["data"]

    def test_evidence_flag_is_forwarded(self) -> None:
        cfg = ApiConfig(api_key="k", requests_per_second=1000.0, evidence=True)
        client = make_client([FakeResponse(200, DELIVERABLE)], cfg)
        client.verify("a@b.com")
        assert client.session.requests[0]["data"]["evidence"] == "true"

    def test_custom_base_url(self) -> None:
        cfg = ApiConfig(api_key="k", base_url="https://proxy.internal/v3",
                        requests_per_second=1000.0)
        client = make_client([FakeResponse(200, DELIVERABLE)], cfg)
        client.verify("a@b.com")
        assert client.session.requests[0]["url"] == "https://proxy.internal/v3/verify"

    def test_missing_key_is_a_config_error(self) -> None:
        from emailverify.config import ConfigError

        client = make_client([], ApiConfig(api_key=""))
        with pytest.raises(ConfigError):
            client._post({"email": "a@b.com"})


class TestParsing:
    def test_deliverable(self) -> None:
        res = make_client([FakeResponse(200, DELIVERABLE)]).verify("emma.wilson@acme-corp.com")
        assert res.ok
        assert res.verdict is Verdict.DELIVERABLE
        assert res.reason == "mailbox_exists"
        assert res.code == 200
        assert res.suggested_action is Action.ACCEPT
        assert res.billed
        assert res.provider == "google.com"
        assert res.latency_ms == 412

    def test_undeliverable_no_mail_server(self) -> None:
        body = {**DELIVERABLE, "verdict": "undeliverable", "reason": "no_mail_server",
                "code": 400, "suggested_action": "reject", "deliverable": False}
        res = make_client([FakeResponse(200, body)]).verify("a@dead.example")
        assert res.verdict is Verdict.UNDELIVERABLE
        assert res.suggested_action is Action.REJECT

    def test_risky_catch_all_sets_flag(self) -> None:
        body = {**DELIVERABLE, "verdict": "risky", "reason": "domain_catch_all",
                "code": 302, "suggested_action": "accept_and_confirm",
                "flags": {"catch_all": True, "disposable": False,
                          "role_account": False, "free_provider": False}}
        res = make_client([FakeResponse(200, body)]).verify("a@b.com")
        assert res.verdict is Verdict.RISKY
        assert res.flags.catch_all
        assert res.suggested_action is Action.ACCEPT_AND_CONFIRM

    def test_unknown_timeout_is_not_billed(self) -> None:
        body = {**DELIVERABLE, "verdict": "unknown", "reason": "timeout",
                "code": 419, "billed": False, "suggested_action": "accept_and_confirm"}
        res = make_client([FakeResponse(200, body)]).verify("a@b.com")
        assert res.verdict is Verdict.UNKNOWN
        assert not res.billed

    def test_did_you_mean_is_captured(self) -> None:
        body = {**DELIVERABLE, "verdict": "undeliverable", "reason": "mailbox_rejected",
                "code": 405, "did_you_mean": "someone@gmail.com"}
        assert make_client([FakeResponse(200, body)]).verify("a@gmial.com").did_you_mean == (
            "someone@gmail.com"
        )

    def test_legacy_response_shape(self) -> None:
        # Older keys can be pinned to the pre-2019 field set, with no `verdict`.
        legacy = {"status": "success", "email": "a@b.com", "result": "catch_all",
                  "deliverable": True, "code": 302, "email_valid": True,
                  "user": "a", "domain": "b.com"}
        res = make_client([FakeResponse(200, legacy)]).verify("a@b.com")
        assert res.verdict is Verdict.RISKY
        assert res.suggested_action is Action.ACCEPT_AND_CONFIRM
        assert res.code == 302

    def test_reason_without_code_is_resolved_from_the_name(self) -> None:
        body = {"email": "a@b.com", "verdict": "undeliverable", "reason": "mailbox_rejected"}
        assert make_client([FakeResponse(200, body)]).verify("a@b.com").code == 405

    def test_unrecognised_verdict_degrades_to_unknown(self) -> None:
        body = {"email": "a@b.com", "verdict": "something_new", "reason": "?"}
        assert make_client([FakeResponse(200, body)]).verify("a@b.com").verdict is Verdict.UNKNOWN


class TestErrors:
    @pytest.mark.parametrize("status", [401, 402, 403])
    def test_auth_and_quota_errors_are_fatal(self, status: int) -> None:
        client = make_client([FakeResponse(status, {"status": "error", "message": "nope"})])
        res = client.verify("a@b.com")
        assert not res.ok
        assert "fatal" in res.error
        assert isinstance(client.fatal, VerimailFatalError)
        assert client.fatal.status == status

    def test_fatal_error_short_circuits_later_calls(self) -> None:
        # Burning through 50k rows after the quota runs out is pure waste.
        client = make_client([FakeResponse(402, {"message": "limit reached"})])
        client.verify("a@b.com")
        second = client.verify("c@d.com")
        assert "skipped" in second.error
        assert len(client.session.requests) == 1

    def test_400_is_per_address_not_fatal(self) -> None:
        client = make_client([
            FakeResponse(400, {"status": "error", "message": "bad parameter"}),
            FakeResponse(200, DELIVERABLE),
        ])
        first = client.verify("bad")
        assert not first.ok
        assert "400" in first.error
        assert client.fatal is None
        assert client.verify("good@example.com").ok

    def test_retries_on_500_then_succeeds(self, monkeypatch) -> None:
        monkeypatch.setattr("time.sleep", lambda _s: None)
        client = make_client([
            FakeResponse(500, {"message": "boom"}),
            FakeResponse(200, DELIVERABLE),
        ])
        assert client.verify("a@b.com").ok
        assert len(client.session.requests) == 2

    def test_retries_exhausted_returns_error(self, monkeypatch) -> None:
        monkeypatch.setattr("time.sleep", lambda _s: None)
        cfg = ApiConfig(api_key="k", requests_per_second=1000.0, max_retries=1)
        client = make_client([FakeResponse(503, {"message": "down"})] * 2, cfg)
        res = client.verify("a@b.com")
        assert not res.ok
        assert client.fatal is None       # transient failure is not fatal

    def test_honours_retry_after(self, monkeypatch) -> None:
        slept: list[float] = []
        monkeypatch.setattr("time.sleep", lambda s: slept.append(s))
        client = make_client([
            FakeResponse(429, {"message": "slow down"}, {"Retry-After": "7"}),
            FakeResponse(200, DELIVERABLE),
        ])
        assert client.verify("a@b.com").ok
        assert 7.0 in slept

    def test_network_exception_is_retried(self, monkeypatch) -> None:
        monkeypatch.setattr("time.sleep", lambda _s: None)
        client = make_client([
            requests.ConnectionError("reset"),
            FakeResponse(200, DELIVERABLE),
        ])
        assert client.verify("a@b.com").ok

    def test_unparseable_200_is_retried(self, monkeypatch) -> None:
        monkeypatch.setattr("time.sleep", lambda _s: None)
        client = make_client([FakeResponse(200, None), FakeResponse(200, DELIVERABLE)])
        assert client.verify("a@b.com").ok


class TestCachingAndBudget:
    def test_cache_hit_costs_nothing(self, tmp_path) -> None:
        with ResultCache(tmp_path / "c.sqlite3") as cache:
            first = make_client([FakeResponse(200, DELIVERABLE)], cache=cache)
            r1 = first.verify("emma.wilson@acme-corp.com")
            assert r1.billed and not r1.from_cache

            # Empty response script: any HTTP call would raise.
            second = make_client([], cache=cache)
            r2 = second.verify("emma.wilson@acme-corp.com")
            assert r2.from_cache
            assert r2.verdict is Verdict.DELIVERABLE
            assert not r2.billed           # a re-run must not pay twice
            assert second.addresses_sent == 0

    def test_errors_are_not_cached(self, tmp_path) -> None:
        with ResultCache(tmp_path / "c.sqlite3") as cache:
            make_client([FakeResponse(400, {"message": "bad"})], cache=cache).verify("x")
            assert cache.get_api("x", 720.0) is None

    def test_max_calls_budget_counts_credits(self) -> None:
        cfg = ApiConfig(api_key="k", requests_per_second=1000.0, max_calls=1)
        client = make_client([FakeResponse(200, DELIVERABLE)], cfg)
        assert client.verify("a@b.com").ok
        blocked = client.verify("c@d.com")
        assert "budget" in blocked.error
        assert len(client.session.requests) == 1

    def test_budget_is_not_overshot_by_concurrent_workers(self) -> None:
        # The pipeline verifies from a thread pool. A read-then-increment
        # budget check lets one call per worker slip through, which is how a
        # "stop at 3 credits" guard rail ends up spending 7.
        import threading
        import time as _time

        cfg = ApiConfig(api_key="k", requests_per_second=1000.0, max_calls=3)
        lock = threading.Lock()

        class SlowSession(FakeSession):
            def post(self, url, data=None, headers=None, timeout=None):
                # Linger inside the request so every worker that got through
                # the budget check is still in flight when the others check.
                _time.sleep(0.05)
                with lock:
                    return super().post(url, data, headers, timeout)

        client = VerimailClient(cfg, cache=None, session=SlowSession(
            [FakeResponse(200, DELIVERABLE)] * 20
        ))
        threads = [
            threading.Thread(target=client.verify, args=(f"u{i}@example.com",))
            for i in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert client.calls_billed <= 3
        assert len(client.session.requests) <= 3

    def test_unbilled_results_do_not_consume_budget(self) -> None:
        # unknown verdicts are free, so they must not eat the credit budget.
        unknown = {**DELIVERABLE, "verdict": "unknown", "reason": "timeout",
                   "code": 419, "billed": False}
        cfg = ApiConfig(api_key="k", requests_per_second=1000.0, max_calls=1)
        client = make_client([FakeResponse(200, unknown)] * 3, cfg)
        for addr in ("a@b.com", "c@d.com", "e@f.com"):
            assert client.verify(addr).ok
        assert client.calls_billed == 0
        assert len(client.session.requests) == 3


class TestPreflight:
    def test_empty_address_probe_validates_the_key_for_free(self) -> None:
        # An empty email returns 200 + syntax_error, which Verimail does not
        # bill -- so the key can be checked without spending anything.
        body = {"email": "", "verdict": "undeliverable", "reason": "empty_address",
                "code": 100, "billed": False}
        client = make_client([FakeResponse(200, body)])
        assert "accepted" in client.preflight()
        assert client.calls_billed == 0

    def test_bad_key_raises(self) -> None:
        client = make_client([FakeResponse(401, {"message": "invalid key"})])
        with pytest.raises(VerimailFatalError):
            client.preflight()

    def test_400_on_the_empty_probe_still_proves_the_key_works(self) -> None:
        client = make_client([FakeResponse(400, {"message": "email required"})])
        assert "accepted" in client.preflight()

    def test_network_failure_is_not_reported_as_success(self, monkeypatch) -> None:
        # A connection failure is not a working key. Reporting "ok" here would
        # send someone into a 50k-row run with a key that was never checked.
        monkeypatch.setattr("time.sleep", lambda _s: None)
        cfg = ApiConfig(api_key="k", requests_per_second=1000.0, max_retries=1)
        client = make_client([requests.ConnectionError("ssl failure")] * 2, cfg)
        with pytest.raises(VerimailTransientError):
            client.preflight()

    def test_server_error_is_not_reported_as_success(self, monkeypatch) -> None:
        monkeypatch.setattr("time.sleep", lambda _s: None)
        cfg = ApiConfig(api_key="k", requests_per_second=1000.0, max_retries=1)
        client = make_client([FakeResponse(500, {"message": "boom"})] * 2, cfg)
        with pytest.raises(VerimailTransientError):
            client.preflight()


def test_error_classes_are_distinct() -> None:
    assert issubclass(VerimailFatalError, Exception)
    assert not issubclass(VerimailTransientError, VerimailFatalError)
    assert not issubclass(VerimailRequestError, VerimailFatalError)
