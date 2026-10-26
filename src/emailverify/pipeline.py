"""The orchestrator: stage 1 -> stage 2 -> stage 3 -> reconcile -> write.

Ordering is a cost decision as much as a correctness one. Each stage is
strictly more expensive than the last (free / one DNS query / one paid credit),
so each one narrows the set the next one sees:

    all rows
      -> stage 1 rules      (free, instant, kills malformed + disposable)
      -> stage 2 DNS        (cheap, cached per *domain*, kills dead domains)
      -> stage 3 Verimail   (paid, cached per *mailbox*, only the survivors)

Dedupe sits between 2 and 3: `a.b+tag@gmail.com` and `ab@gmail.com` are one
inbox, so one credit answers for both.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

from emailverify import scoring
from emailverify.cache import NullCache, ResultCache
from emailverify.config import Config
from emailverify.io.hubspot import ContactRow, HubspotReader
from emailverify.io import writers
from emailverify.models import ApiResult, DomainResult, InitialStatus, Verification
from emailverify.rules import RuleEngine
from emailverify.stages.domain_check import DomainChecker
from emailverify.stages.verimail import VerimailClient

ProgressFn = Callable[[str, int, int, str], None]


def _noop_progress(stage: str, done: int, total: int, detail: str) -> None:
    return None


@dataclass
class PipelineResult:
    verifications: list[Verification] = field(default_factory=list)
    rows: list[ContactRow] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    outputs: dict[str, Path] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class Pipeline:
    def __init__(
        self,
        cfg: Config,
        progress: ProgressFn | None = None,
        cache: ResultCache | None = None,
        domain_checker: DomainChecker | None = None,
        api_client: VerimailClient | None = None,
    ) -> None:
        self.cfg = cfg
        self.progress = progress or _noop_progress
        self.cache = cache if cache is not None else (
            ResultCache(cfg.cache_path) if cfg.use_cache else NullCache()
        )
        self._owns_cache = cache is None
        self.rules = RuleEngine(cfg.rules)
        self.domain_checker = domain_checker
        self.api_client = api_client
        self.warnings: list[str] = []

    # -- orchestration ------------------------------------------------------ #

    def run(self) -> PipelineResult:
        started = time.perf_counter()
        if self._owns_cache:
            self.cache.open()
        try:
            return self._run(started)
        finally:
            if self._owns_cache:
                self.cache.close()

    def _run(self, started: float) -> PipelineResult:
        result = PipelineResult()

        # ---- read ---------------------------------------------------------
        reader = HubspotReader(self.cfg.input_path, self.cfg.email_column, self.cfg.id_column)
        rows = reader.read_all(limit=self.cfg.limit)
        result.rows = rows
        result.columns = reader.fieldnames
        if not rows:
            self.warnings.append("input CSV contained no data rows")
            result.summary = writers.build_summary([], {"elapsed_seconds": 0.0})
            result.warnings = self.warnings
            return result
        self.progress("read", len(rows), len(rows), f"{reader.email_column!r} column")

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")

        # ---- stage 1: rules ----------------------------------------------
        verifications: list[Verification] = []
        for i, row in enumerate(rows, start=1):
            rule = self.rules.check(row.email)
            verifications.append(
                Verification(
                    record_id=row.record_id,
                    email_raw=row.email,
                    rule=rule,
                    domain=DomainResult(domain=rule.ascii_domain),
                    checked_at=now,
                )
            )
            if i % 500 == 0 or i == len(rows):
                self.progress("rules", i, len(rows), "")
        result.verifications = verifications

        rule_pass = [v for v in verifications if v.rule.ok]
        self.progress(
            "rules", len(rows), len(rows),
            f"{len(rule_pass)} passed, {len(rows) - len(rule_pass)} rejected",
        )

        # ---- stage 2: domain liveness ------------------------------------
        domain_results: dict[str, DomainResult] = {}
        if self.cfg.skip_domain:
            self.warnings.append("stage 2 (domain check) skipped by --skip-domain")
        elif rule_pass:
            domains = {v.rule.ascii_domain for v in rule_pass}
            checker = self.domain_checker or DomainChecker(self.cfg.dns, self.cache)
            done = 0
            total = len(domains)

            def on_domain(domain: str, _res: DomainResult) -> None:
                nonlocal done
                done += 1
                if done % 25 == 0 or done == total:
                    self.progress("domain", done, total, domain)

            domain_results = checker.check_many(domains, progress=on_domain)
            for v in rule_pass:
                v.domain = domain_results.get(
                    v.rule.ascii_domain, DomainResult(domain=v.rule.ascii_domain)
                )

        # The initial status has to exist before the API gate can use it.
        for v in verifications:
            v.initial_status = scoring.initial_status(v.rule, v.domain)

        # ---- stage 3: Verimail -------------------------------------------
        api_targets = self._select_for_api(verifications)
        credits_billed = 0
        addresses_sent = 0
        duplicates = 0

        if self.cfg.skip_api:
            self.warnings.append("stage 3 (Verimail) skipped by --skip-api")
        elif not api_targets:
            self.progress("api", 0, 0, "nothing reached the API gate")
        else:
            client = self.api_client or VerimailClient(self.cfg.api, self.cache)
            by_canonical, duplicates = self._group_canonical(api_targets)
            answers = self._call_api(client, sorted(by_canonical))

            for canonical, api in answers.items():
                for v in by_canonical[canonical]:
                    # Everyone in the group shares the answer; rows whose own
                    # address was not the one sent record which mailbox was.
                    v.api = api
                    if v.rule.normalized != canonical:
                        v.verified_as = canonical
            credits_billed = client.calls_billed
            addresses_sent = client.addresses_sent
            if client.fatal is not None:
                self.warnings.append(f"Verimail aborted: {client.fatal}")

        # ---- reconcile ----------------------------------------------------
        for v in verifications:
            scoring.reconcile(v, reject_disposable=self.cfg.rules.reject_disposable)

        # ---- write --------------------------------------------------------
        elapsed = time.perf_counter() - started
        cache_stats = self.cache.stats()
        result.summary = writers.build_summary(
            verifications,
            {
                "input": str(self.cfg.input_path),
                "api_addresses_eligible": len(api_targets),
                "api_calls_sent": addresses_sent,
                "api_credits_billed": credits_billed,
                "api_cache_hits": sum(1 for v in verifications if v.api and v.api.from_cache),
                "domains_resolved": len(domain_results),
                "domain_cache_hits": sum(
                    1 for d in domain_results.values() if d.from_cache
                ),
                "duplicates_collapsed": duplicates,
                "cache": cache_stats,
                "elapsed_seconds": round(elapsed, 2),
                "generated_at": now,
                "warnings": self.warnings,
            },
        )
        result.outputs = self._write_outputs(result)
        result.warnings = self.warnings
        return result

    # -- stage 3 helpers ---------------------------------------------------- #

    def _select_for_api(self, verifications: Sequence[Verification]) -> list[Verification]:
        """Apply --api-gate. Stage 1 failures never qualify, under any gate."""
        gate = self.cfg.api_gate
        out: list[Verification] = []
        for v in verifications:
            if not v.rule.ok:
                continue
            # A disposable address is already decided; paying to confirm that a
            # throwaway inbox accepts mail buys nothing.
            if v.rule.flags.disposable and self.cfg.rules.reject_disposable:
                continue
            if gate == "rules":
                out.append(v)
            elif gate == "rules+domain":
                # Skip provably dead domains (DNS already said no, and Verimail
                # bills for its own no_mail_server answer). DNS_ERROR is not
                # "dead", so those still go through.
                if v.initial_status is not InitialStatus.DEAD_DOMAIN:
                    out.append(v)
            elif gate == "unresolved":
                if v.initial_status in (InitialStatus.OK, InitialStatus.UNKNOWN):
                    out.append(v)
        return out

    def _group_canonical(
        self, targets: Sequence[Verification]
    ) -> tuple[dict[str, list[Verification]], int]:
        """Group addresses by the mailbox they actually reach."""
        groups: dict[str, list[Verification]] = {}
        for v in targets:
            key = v.rule.canonical if self.cfg.dedupe else v.rule.normalized
            groups.setdefault(key, []).append(v)
        duplicates = sum(len(g) - 1 for g in groups.values())
        return groups, duplicates

    def _call_api(
        self, client: VerimailClient, canonicals: list[str]
    ) -> dict[str, ApiResult]:
        total = len(canonicals)
        answers: dict[str, ApiResult] = {}
        done = 0

        # The client's token bucket does the pacing, so a small pool just hides
        # per-request latency; it cannot exceed the configured rate.
        workers = max(1, min(8, int(self.cfg.api.requests_per_second) or 1, total))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="api") as pool:
            for canonical, api in zip(canonicals, pool.map(client.verify, canonicals)):
                answers[canonical] = api
                done += 1
                if done % 10 == 0 or done == total:
                    self.progress("api", done, total, canonical)
                if client.fatal is not None:
                    # Stop issuing work; verify() already short-circuits, but
                    # bailing here keeps the progress output honest.
                    break
        return answers

    # -- output ------------------------------------------------------------- #

    def _write_outputs(self, result: PipelineResult) -> dict[str, Path]:
        outdir = self.cfg.outdir
        outdir.mkdir(parents=True, exist_ok=True)
        outputs: dict[str, Path] = {}

        paired = list(zip((r.data for r in result.rows), result.verifications))

        enriched = outdir / "verified.csv"
        writers.write_enriched_csv(enriched, result.columns, paired)
        outputs["enriched_csv"] = enriched

        detail = outdir / "results.jsonl"
        writers.write_jsonl(detail, result.verifications)
        outputs["jsonl"] = detail

        summary_path = outdir / "summary.json"
        writers.write_summary(summary_path, result.summary)
        outputs["summary"] = summary_path

        if self.cfg.split_outputs:
            segments: dict[str, list] = {}
            for data, v in paired:
                segments.setdefault(writers.segment_of(v), []).append((data, v))
            segdir = outdir / "segments"
            for name, items in sorted(segments.items()):
                path = segdir / f"{name}.csv"
                writers.write_segment_csv(path, result.columns, items)
                outputs[f"segment_{name}"] = path

        return outputs


def run_pipeline(cfg: Config, progress: ProgressFn | None = None) -> PipelineResult:
    return Pipeline(cfg, progress=progress).run()
