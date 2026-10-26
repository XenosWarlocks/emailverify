"""End-to-end pipeline runs over the sample export, with both networked
stages stubbed out."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from emailverify.models import (
    Action,
    ApiResult,
    DomainStatus,
    InitialStatus,
    Verdict,
)
from emailverify.pipeline import Pipeline


class StubApiClient:
    """Verimail stand-in. Records every address it is asked about."""

    def __init__(self, answers: dict[str, ApiResult] | None = None, default=None) -> None:
        self.answers = answers or {}
        self.default = default or (
            lambda email: ApiResult(
                email=email, verdict=Verdict.DELIVERABLE, reason="mailbox_exists",
                code=200, suggested_action=Action.ACCEPT, billed=True,
            )
        )
        self.asked: list[str] = []
        self.calls_billed = 0
        self.addresses_sent = 0
        self.fatal = None

    def verify(self, email: str) -> ApiResult:
        self.asked.append(email)
        self.addresses_sent += 1
        res = self.answers.get(email) or self.default(email)
        if res.billed:
            self.calls_billed += 1
        return res


def run(cfg, domain_statuses=None, api_client=None, checker_cls=None):
    from tests.conftest import FakeDomainChecker

    cls = checker_cls or FakeDomainChecker
    checker = cls(domain_statuses or {})
    client = api_client if api_client is not None else StubApiClient()
    result = Pipeline(
        cfg, domain_checker=checker, api_client=client
    ).run()
    return result, checker, client


class TestEndToEnd:
    def test_processes_every_row(self, base_config) -> None:
        result, _, _ = run(base_config)
        assert len(result.verifications) == 10
        assert result.summary["total_rows"] == 10

    def test_writes_all_expected_outputs(self, base_config) -> None:
        result, _, _ = run(base_config)
        assert result.outputs["enriched_csv"].exists()
        assert result.outputs["jsonl"].exists()
        assert result.outputs["summary"].exists()
        # Segment files appear only for segments that have rows.
        assert any(k.startswith("segment_") for k in result.outputs)

    def test_enriched_csv_row_count_matches_input(self, base_config) -> None:
        result, _, _ = run(base_config)
        with result.outputs["enriched_csv"].open(encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 10
        assert all(r["ev_final_verdict"] for r in rows)

    def test_jsonl_is_one_valid_object_per_row(self, base_config) -> None:
        result, _, _ = run(base_config)
        lines = result.outputs["jsonl"].read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 10
        payloads = [json.loads(line) for line in lines]
        assert all("final_verdict" in p for p in payloads)

    def test_summary_json_round_trips(self, base_config) -> None:
        result, _, _ = run(base_config)
        loaded = json.loads(result.outputs["summary"].read_text(encoding="utf-8"))
        assert loaded["total_rows"] == 10
        assert "initial_status" in loaded


class TestStageGating:
    def test_dns_called_once_per_unique_domain(self, base_config) -> None:
        # The sample has 10 rows across 4 domains, 6 of them gmail.com.
        _, checker, _ = run(base_config)
        assert sorted(checker.calls) == [
            "akrodlabs.com", "gmail.com", "ofags.com", "wearehackerone.com",
        ]

    def test_disposable_never_reaches_the_paid_api(self, base_config) -> None:
        _, _, client = run(base_config)
        assert not any("ofags.com" in addr for addr in client.asked)

    def test_dead_domains_are_skipped_under_the_default_gate(self, base_config) -> None:
        # Verimail bills for its own no_mail_server answer, so once DNS has
        # said the domain is dead there is nothing to buy.
        _, _, client = run(base_config, {"akrodlabs.com": DomainStatus.NXDOMAIN})
        assert not any("akrodlabs.com" in addr for addr in client.asked)

    def test_rules_gate_sends_dead_domains_anyway(self, base_config) -> None:
        base_config.api_gate = "rules"
        _, _, client = run(base_config, {"akrodlabs.com": DomainStatus.NXDOMAIN})
        assert any("akrodlabs.com" in addr for addr in client.asked)

    def test_dns_error_still_reaches_the_api(self, base_config) -> None:
        # "We could not resolve it" is not "it is dead" -- the API gets a go.
        _, _, client = run(base_config, {"akrodlabs.com": DomainStatus.DNS_ERROR})
        assert any("akrodlabs.com" in addr for addr in client.asked)

    def test_unresolved_gate(self, base_config) -> None:
        base_config.api_gate = "unresolved"
        _, _, client = run(base_config, {"akrodlabs.com": DomainStatus.NXDOMAIN})
        assert not any("akrodlabs.com" in addr for addr in client.asked)

    def test_skip_api(self, base_config) -> None:
        base_config.skip_api = True
        result, _, client = run(base_config)
        assert client.asked == []
        assert all(v.api is None for v in result.verifications)
        assert any("stage 3" in w for w in result.warnings)

    def test_skip_domain(self, base_config) -> None:
        base_config.skip_domain = True
        result, checker, _ = run(base_config)
        assert checker.calls == []
        assert any("stage 2" in w for w in result.warnings)
        statuses = {v.initial_status for v in result.verifications if v.rule.ok}
        assert statuses == {InitialStatus.UNKNOWN}

    def test_limit(self, base_config) -> None:
        base_config.limit = 3
        result, _, _ = run(base_config)
        assert len(result.verifications) == 3


class TestDedupe:
    def test_tagged_gmail_collapses_to_one_api_call(self, base_config) -> None:
        # anupam936574+11@gmail.com and anupam936574@gmail.com are one inbox.
        base_config.limit = 0
        _, _, client = run(base_config)
        assert "anupam936574@gmail.com" in client.asked
        assert "anupam936574+11@gmail.com" not in client.asked

    def test_collapsed_rows_record_the_mailbox_actually_verified(self, base_config) -> None:
        result, _, _ = run(base_config)
        tagged = next(
            v for v in result.verifications if v.email_raw == "anupam936574+11@gmail.com"
        )
        assert tagged.api is not None
        assert tagged.verified_as == "anupam936574@gmail.com"

    def test_rows_sent_verbatim_have_no_verified_as(self, base_config) -> None:
        result, _, _ = run(base_config)
        plain = next(v for v in result.verifications if v.email_raw == "mufij7114@gmail.com")
        assert plain.verified_as == ""

    def test_no_dedupe_sends_the_literal_address(self, base_config) -> None:
        base_config.dedupe = False
        _, _, client = run(base_config)
        assert "anupam936574+11@gmail.com" in client.asked


class TestVerdicts:
    def test_disposable_row_is_rejected(self, base_config) -> None:
        result, _, _ = run(base_config)
        v = next(x for x in result.verifications if x.email_raw.endswith("@ofags.com"))
        assert v.rule.flags.disposable
        assert v.action is Action.REJECT

    def test_relay_rows_are_flagged(self, base_config) -> None:
        result, _, _ = run(base_config)
        relays = [v for v in result.verifications if "wearehackerone" in v.email_raw]
        assert len(relays) == 2
        assert all(v.rule.flags.relay_provider for v in relays)

    def test_undeliverable_api_answer_lands_in_the_segment_file(self, base_config) -> None:
        client = StubApiClient(default=lambda email: ApiResult(
            email=email, verdict=Verdict.UNDELIVERABLE, reason="mailbox_rejected",
            code=405, suggested_action=Action.REJECT, billed=True,
        ))
        result, _, _ = run(base_config, api_client=client)
        seg = base_config.outdir / "segments" / "undeliverable.csv"
        assert seg.exists()
        with seg.open(encoding="utf-8-sig", newline="") as fh:
            assert len(list(csv.DictReader(fh))) >= 1

    def test_summary_tallies_add_up(self, base_config) -> None:
        result, _, _ = run(base_config)
        assert sum(result.summary["final_verdict"].values()) == 10
        assert sum(result.summary["initial_status"].values()) == 10
        assert (
            result.summary["mailable"] + result.summary["not_mailable"]
            == result.summary["total_rows"]
        )


class TestResilience:
    def test_fatal_api_error_still_produces_output(self, base_config) -> None:
        class FatalClient(StubApiClient):
            def __init__(self) -> None:
                super().__init__()
                self.fatal = RuntimeError("HTTP 402: monthly limit exhausted")

            def verify(self, email: str) -> ApiResult:
                self.asked.append(email)
                return ApiResult(email=email, error="fatal: quota exhausted")

        result, _, _ = run(base_config, api_client=FatalClient())
        # Partial results are still written, and fall back to the DNS verdict.
        assert result.outputs["enriched_csv"].exists()
        assert any("aborted" in w for w in result.warnings)
        live = [v for v in result.verifications if v.initial_status is InitialStatus.OK]
        assert all(v.final_verdict is not Verdict.UNDELIVERABLE for v in live)

    def test_empty_csv_body_is_handled(self, base_config, tmp_path: Path) -> None:
        p = tmp_path / "headers_only.csv"
        p.write_text("Record ID,Email\n", encoding="utf-8")
        base_config.input_path = p
        result, _, _ = run(base_config)
        assert result.verifications == []
        assert any("no data rows" in w for w in result.warnings)

    def test_blank_email_is_rejected_not_crashed(self, base_config, tmp_path: Path) -> None:
        p = tmp_path / "blank.csv"
        p.write_text("Record ID,Email\n1,\n2,ok@akrodlabs.com\n", encoding="utf-8")
        base_config.input_path = p
        result, _, _ = run(base_config)
        assert result.verifications[0].initial_status is InitialStatus.INVALID_SYNTAX
        assert result.verifications[0].final_reason == "empty_address"


def test_rerun_spends_no_credits(base_config) -> None:
    """A second run over the same export must cost nothing.

    Uses the real VerimailClient over a fake HTTP session so the cache is
    genuinely exercised: the second run's session has no scripted responses
    at all, so any HTTP call would raise.
    """
    from tests.conftest import FakeDomainChecker
    from tests.test_verimail import DELIVERABLE, FakeResponse, FakeSession
    from emailverify.stages.verimail import VerimailClient

    def pipeline_with(responses):
        session = FakeSession(responses)
        client = VerimailClient(base_config.api, cache=None, session=session)
        # The pipeline owns the cache, so hand the client the same one it opens.
        pipe = Pipeline(base_config, domain_checker=FakeDomainChecker({}))
        client.cache = pipe.cache
        pipe.api_client = client
        return pipe.run(), client, session

    # 10 rows, 4 domains, and dedupe collapses the +tag gmail pair; ofags.com
    # is disposable and never sent. Script plenty of responses.
    first, client1, session1 = pipeline_with([FakeResponse(200, DELIVERABLE)] * 20)
    assert client1.addresses_sent > 0
    assert len(session1.requests) == client1.addresses_sent

    second, client2, session2 = pipeline_with([])
    assert session2.requests == []          # no HTTP at all
    assert client2.calls_billed == 0
    assert second.summary["api_cache_hits"] > 0
    assert second.summary["total_rows"] == first.summary["total_rows"]
