"""Merge the output of several runs into one decision file.

Why this exists: a real cleanup is never one run. You do a free rules+DNS pass
over the whole book, then spend credits on a subset, maybe a second subset next
week. That leaves several `verified.csv` files describing overlapping sets of
contacts at different evidence levels, and no single file you can sort and act
on.

This consolidates them into one row per CRM record, keeping the *strongest*
evidence seen for each, and adds a single `ev_decision` column to filter on.

Two rules govern the merge:

* **Stronger evidence wins.** An SMTP-level answer from the API beats a
  DNS-level answer, which beats a syntax-only answer. A later run that only
  did rules must never overwrite an earlier run's API verdict.
* **"Not checked" is not a verdict.** Most of a book typically never reaches
  the paid API. Those rows are reported as `KEEP` at verification level
  `domain_checked`, never as confirmed-good, because nothing proved the
  mailbox exists.

Duplicate detection runs across the merged set, not per run: two CRM records
sharing one real mailbox are only visible once everything is in one place.
"""

from __future__ import annotations

import csv
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

# --------------------------------------------------------------------------- #
# Decisions
# --------------------------------------------------------------------------- #

REMOVE = "REMOVE"
REMOVE_DUPLICATE = "REMOVE_DUPLICATE"
FIX = "FIX"
REVIEW = "REVIEW"
KEEP = "KEEP"

# Sort order in the output file: things to delete first, so the file is
# actionable top-down.
DECISION_PRIORITY = {
    REMOVE: 1,
    REMOVE_DUPLICATE: 2,
    FIX: 3,
    REVIEW: 4,
    KEEP: 5,
}

# Evidence strength. Used both to pick a winner when runs disagree and to
# report honestly how a row was judged.
LEVEL_API = "api_verified"
LEVEL_DOMAIN = "domain_checked"
LEVEL_RULES = "rules_only"
LEVEL_NONE = "unchecked"

LEVEL_RANK = {LEVEL_NONE: 0, LEVEL_RULES: 1, LEVEL_DOMAIN: 2, LEVEL_API: 3}

# Columns this module adds, in front of everything else so they are the first
# thing visible when the file opens in Excel.
DECISION_COLUMNS = [
    "ev_decision",
    "ev_priority",
    "ev_decision_reason",
    "ev_action",
    "ev_verification_level",
    "ev_duplicate_of_record",
    "ev_source_run",
    "ev_runs_seen",
]

# Identity columns for --lean output, in this order. Missing ones are skipped.
LEAN_IDENTITY = [
    "Record ID",
    "Email",
    "ev_email_normalized",
    "ev_canonical_email",
    "First Name",
    "Last Name",
    "Associated Company",
    "Create Date",
    "jsmon_plan",
    "jsmon_scans_total",
    "jsmon_user_last_active_at",
]

LEAN_EVIDENCE = [
    "ev_final_verdict",
    "ev_final_reason",
    "ev_risk_score",
    "ev_confidence",
    "ev_domain",
    "ev_domain_status",
    "ev_api_verdict",
    "ev_api_reason",
    "ev_disposable",
    "ev_role_account",
    "ev_relay_provider",
    "ev_catch_all",
    "ev_typo_suspect",
    "ev_did_you_mean",
]


class ConsolidateError(Exception):
    """Raised when the inputs cannot be consolidated."""


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().upper() in {"TRUE", "1", "YES"}


# --------------------------------------------------------------------------- #
# Reading runs
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class RunFile:
    """One run's verified.csv."""

    path: Path
    name: str
    rows: list[dict[str, str]] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)


def resolve_input(target: str | Path) -> Path:
    """Accept either a verified.csv or the output directory containing one."""
    p = Path(target)
    if p.is_dir():
        candidate = p / "verified.csv"
        if not candidate.exists():
            raise ConsolidateError(
                f"{p} is a directory but holds no verified.csv. "
                "Pass the CSV path directly, or an --outdir from a previous run."
            )
        return candidate
    if not p.exists():
        raise ConsolidateError(f"Not found: {p}")
    return p


def read_run(target: str | Path, name: str | None = None) -> RunFile:
    path = resolve_input(target)
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            raise ConsolidateError(f"{path} has no header row")
        columns = [c for c in reader.fieldnames if c and c.strip()]
        if "ev_final_verdict" not in columns:
            raise ConsolidateError(
                f"{path} does not look like an emailverify output "
                "(no ev_final_verdict column). Run `emailverify run` on it first."
            )
        rows = [{k: (v or "") for k, v in row.items() if k} for row in reader]
    # Name runs after their parent directory, which is what distinguishes
    # data/out/verified.csv from data/out/real/verified.csv.
    label = name or (path.parent.name or path.stem)
    return RunFile(path=path, name=label, rows=rows, columns=columns)


# --------------------------------------------------------------------------- #
# Evidence level and merging
# --------------------------------------------------------------------------- #


def evidence_level(row: dict[str, str]) -> str:
    """How strongly was this row judged?"""
    # An API row only counts as API-verified if it came back with a verdict;
    # a row where the call errored out carries no SMTP evidence.
    if (row.get("ev_api_verdict") or "").strip():
        return LEVEL_API
    domain_status = (row.get("ev_domain_status") or "").strip()
    if domain_status and domain_status not in {"not_checked"}:
        return LEVEL_DOMAIN
    if (row.get("ev_rule_ok") or "").strip():
        return LEVEL_RULES
    return LEVEL_NONE


def merge_key(row: dict[str, str]) -> str:
    """Identify the CRM record a row describes.

    Record ID is the right key: it survives an email correction, and two
    different records sharing one email address are a duplicate to flag, not
    two readings of one contact to merge. Falls back to the normalized email
    for exports with no ID column.
    """
    rid = (row.get("Record ID") or "").strip()
    if rid:
        return f"id:{rid}"
    email = (row.get("ev_email_normalized") or row.get("Email") or "").strip().lower()
    return f"email:{email}"


@dataclass(slots=True)
class MergedRecord:
    key: str
    row: dict[str, str]
    level: str
    source_run: str
    runs_seen: int = 1


def merge_runs(runs: Iterable[RunFile]) -> dict[str, MergedRecord]:
    """One record per CRM contact, holding the strongest evidence available.

    Later runs win ties, so re-running the same scope refreshes the result.
    """
    merged: dict[str, MergedRecord] = {}
    for run in runs:
        for row in run.rows:
            key = merge_key(row)
            level = evidence_level(row)
            existing = merged.get(key)
            if existing is None:
                merged[key] = MergedRecord(key, row, level, run.name)
                continue
            existing.runs_seen += 1
            # >= so a later run of equal strength refreshes; < keeps the
            # stronger earlier verdict rather than letting a rules-only
            # re-run erase an API answer.
            if LEVEL_RANK[level] >= LEVEL_RANK[existing.level]:
                existing.row = row
                existing.level = level
                existing.source_run = run.name
    return merged


# --------------------------------------------------------------------------- #
# Decisions
# --------------------------------------------------------------------------- #


def decide(row: dict[str, str], level: str) -> tuple[str, str, str]:
    """Return (decision, reason, action) for one merged row."""
    verdict = (row.get("ev_final_verdict") or "").strip().lower()
    reason = (row.get("ev_final_reason") or "").strip()
    rule_detail = (row.get("ev_rule_detail") or "").strip()
    did_you_mean = (row.get("ev_did_you_mean") or "").strip()
    domain = (row.get("ev_domain") or "").strip()

    # --- confident removals -------------------------------------------------
    if reason in {"empty_address", "missing_at_sign", "address_too_long",
                  "local_part_too_long", "invalid_domain", "invalid_local_part"}:
        return (
            REMOVE,
            f"malformed address ({rule_detail or reason})",
            "delete, or correct the address if you know the real one",
        )

    if _truthy(row.get("ev_disposable")):
        return (
            REMOVE,
            "disposable / throwaway mailbox provider",
            "delete - no marketing value even though it accepts mail",
        )

    if verdict == "undeliverable":
        if reason == "no_mail_server":
            return (
                REMOVE,
                f"{domain or 'domain'} does not accept mail "
                f"({(row.get('ev_domain_status') or '').strip() or 'no MX'})",
                "delete - mail to this domain cannot be delivered",
            )
        return (
            REMOVE,
            f"mailbox rejected by the mail server ({reason or 'undeliverable'})",
            "delete - the provider confirmed this mailbox does not accept mail",
        )

    # --- fixable ------------------------------------------------------------
    if _truthy(row.get("ev_typo_suspect")) and did_you_mean:
        return (
            FIX,
            f"likely typo in the domain; probably meant {did_you_mean}",
            f"correct the domain to {did_you_mean}, then re-verify",
        )

    # --- needs a human ------------------------------------------------------
    if verdict == "risky":
        if _truthy(row.get("ev_catch_all")):
            return (
                REVIEW,
                f"{domain or 'domain'} is catch-all: it accepts every address, "
                "so the mailbox itself is unproven",
                "keep only if you have other evidence this person is real",
            )
        if reason == "mailbox_full":
            return (REVIEW, "mailbox is over quota", "retry later; drop if it stays full")
        return (REVIEW, f"risky ({reason or 'unspecified'})", "review before bulk sending")

    if _truthy(row.get("ev_relay_provider")):
        return (
            REVIEW,
            "alias/forwarding relay - always accepts mail, tells you nothing "
            "about whether a human reads it",
            "keep if the relationship is real, drop if it was a one-off signup",
        )

    if _truthy(row.get("ev_role_account")):
        return (
            REVIEW,
            "role mailbox (shared inbox, not a person)",
            "keep for support/billing contact, drop for 1:1 outreach",
        )

    # --- keep ---------------------------------------------------------------
    if verdict == "deliverable":
        return (KEEP, "mailbox confirmed by the mail server", "safe to send")

    if level == LEVEL_API:
        # The API ran but could not settle it (greylisted, timeout, tarpit).
        return (
            KEEP,
            f"domain accepts mail; mailbox unconfirmed ({reason or 'unknown'})",
            "safe to send, but expect some bounces - re-verify later",
        )

    if level == LEVEL_DOMAIN:
        return (
            KEEP,
            "domain accepts mail; mailbox never individually verified",
            "verify with the API before a large send",
        )

    return (
        KEEP,
        "passed syntax rules only; domain not checked",
        "run the domain and API stages before sending",
    )


def mark_duplicates(records: list[MergedRecord]) -> int:
    """Flag CRM records that reach a mailbox another record already covers.

    Grouped by canonical mailbox, so `a.b+tag@gmail.com` and `ab@gmail.com`
    land in the same group. Within a group the strongest-evidence record is
    kept and the rest become REMOVE_DUPLICATE; ties break on the oldest
    Record ID, which is almost always the original signup.
    """
    groups: dict[str, list[MergedRecord]] = defaultdict(list)
    for rec in records:
        canonical = (rec.row.get("ev_canonical_email") or "").strip().lower()
        if canonical:
            groups[canonical].append(rec)

    flagged = 0
    for canonical, group in groups.items():
        if len(group) < 2:
            continue
        ordered = sorted(
            group,
            key=lambda r: (
                -LEVEL_RANK[r.level],
                _record_id_sort_key(r),
            ),
        )
        keeper = ordered[0]
        keeper_id = (keeper.row.get("Record ID") or "").strip()
        for rec in ordered[1:]:
            # Do not overwrite a removal that stands on its own merits -- a
            # dead-domain duplicate is still a dead domain, and saying
            # "duplicate" would hide the stronger reason.
            if rec.row.get("ev_decision") == REMOVE:
                rec.row["ev_duplicate_of_record"] = keeper_id
                continue
            rec.row["ev_decision"] = REMOVE_DUPLICATE
            rec.row["ev_priority"] = str(DECISION_PRIORITY[REMOVE_DUPLICATE])
            rec.row["ev_decision_reason"] = (
                f"same mailbox as record {keeper_id or '(no id)'} ({canonical})"
            )
            rec.row["ev_action"] = f"merge into record {keeper_id or '(no id)'} and delete"
            rec.row["ev_duplicate_of_record"] = keeper_id
            flagged += 1
    return flagged


def _record_id_sort_key(rec: MergedRecord) -> tuple[int, str]:
    rid = (rec.row.get("Record ID") or "").strip()
    # Numeric IDs sort numerically; anything else falls to the back.
    return (0, rid.zfill(24)) if rid.isdigit() else (1, rid)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


@dataclass
class ConsolidateResult:
    records: list[MergedRecord] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    out_path: Path | None = None
    duplicates_flagged: int = 0
    runs: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    level_counts: dict[str, int] = field(default_factory=dict)


def consolidate(
    targets: list[str | Path],
    out_path: str | Path,
    lean: bool = False,
    find_duplicates: bool = True,
) -> ConsolidateResult:
    if not targets:
        raise ConsolidateError("No inputs given")

    runs = [read_run(t) for t in targets]
    # Disambiguate runs that share a parent directory name.
    seen: dict[str, int] = {}
    for run in runs:
        seen[run.name] = seen.get(run.name, 0) + 1
        if seen[run.name] > 1:
            run.name = f"{run.name}#{seen[run.name]}"

    merged = merge_runs(runs)
    records = list(merged.values())

    for rec in records:
        decision, reason, action = decide(rec.row, rec.level)
        rec.row["ev_decision"] = decision
        rec.row["ev_priority"] = str(DECISION_PRIORITY[decision])
        rec.row["ev_decision_reason"] = reason
        rec.row["ev_action"] = action
        rec.row["ev_verification_level"] = rec.level
        rec.row["ev_source_run"] = rec.source_run
        rec.row["ev_runs_seen"] = str(rec.runs_seen)
        rec.row.setdefault("ev_duplicate_of_record", "")

    duplicates = mark_duplicates(records) if find_duplicates else 0

    # Sort: action-first, then worst risk, then by record id for stability.
    records.sort(
        key=lambda r: (
            int(r.row.get("ev_priority") or 9),
            -int(r.row.get("ev_risk_score") or 0),
            _record_id_sort_key(r),
        )
    )

    columns = _output_columns(runs, records, lean=lean)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            writer.writerow(rec.row)

    counts: dict[str, int] = {}
    levels: dict[str, int] = {}
    for rec in records:
        d = rec.row["ev_decision"]
        counts[d] = counts.get(d, 0) + 1
        levels[rec.level] = levels.get(rec.level, 0) + 1

    return ConsolidateResult(
        records=records,
        columns=columns,
        out_path=out,
        duplicates_flagged=duplicates,
        runs=[r.name for r in runs],
        counts=dict(sorted(counts.items(), key=lambda kv: DECISION_PRIORITY.get(kv[0], 9))),
        level_counts=dict(sorted(levels.items(), key=lambda kv: -LEVEL_RANK[kv[0]])),
    )


def _output_columns(
    runs: list[RunFile], records: list[MergedRecord], lean: bool
) -> list[str]:
    if lean:
        present = {k for rec in records for k in rec.row}
        cols = list(DECISION_COLUMNS)
        cols += [c for c in LEAN_IDENTITY if c in present]
        cols += [c for c in LEAN_EVIDENCE if c in present]
        return _dedupe(cols)

    # Full passthrough: every original column from every run, in first-seen
    # order, with the decision columns promoted to the front.
    ordered: list[str] = list(DECISION_COLUMNS)
    for run in runs:
        for col in run.columns:
            ordered.append(col)
    for rec in records:
        for col in rec.row:
            ordered.append(col)
    return _dedupe(ordered)


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def format_report(result: ConsolidateResult) -> str:
    total = len(result.records)
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append(f"  Consolidated {total} CRM records from {len(result.runs)} run(s)")
    lines.append(f"  {', '.join(result.runs)}")
    lines.append("=" * 72)

    def bar(n: int, width: int = 22) -> str:
        if not total:
            return ""
        filled = int(round(width * n / total))
        return "#" * filled + "." * (width - filled)

    explain = {
        REMOVE: "delete: malformed, dead domain, or rejected",
        REMOVE_DUPLICATE: "delete: another record has the same mailbox",
        FIX: "correct the typo, then re-verify",
        REVIEW: "needs a human call",
        KEEP: "keep",
    }
    lines.append("")
    lines.append("Decision")
    for decision, n in result.counts.items():
        pct = 100.0 * n / total if total else 0.0
        lines.append(
            f"  {decision:<18} {n:>6}  {pct:>5.1f}%  {bar(n)}  {explain.get(decision, '')}"
        )

    lines.append("")
    lines.append("Evidence behind those decisions")
    level_explain = {
        LEVEL_API: "SMTP-verified by Verimail",
        LEVEL_DOMAIN: "domain resolved, mailbox unproven",
        LEVEL_RULES: "syntax only",
        LEVEL_NONE: "not checked",
    }
    for level, n in result.level_counts.items():
        pct = 100.0 * n / total if total else 0.0
        lines.append(
            f"  {level:<18} {n:>6}  {pct:>5.1f}%  {bar(n)}  {level_explain.get(level, '')}"
        )

    removable = result.counts.get(REMOVE, 0) + result.counts.get(REMOVE_DUPLICATE, 0)
    lines.append("")
    lines.append(f"Safe to delete now:        {removable}")
    lines.append(f"  of which duplicates:     {result.duplicates_flagged}")
    lines.append(f"Fixable typos:             {result.counts.get(FIX, 0)}")
    lines.append(f"Needs review:              {result.counts.get(REVIEW, 0)}")
    lines.append(f"Keep:                      {result.counts.get(KEEP, 0)}")
    if result.out_path is not None:
        lines.append("")
        lines.append(f"Written to: {result.out_path}")
        lines.append("Sorted so everything to delete is at the top. "
                     "Filter on ev_decision.")
    lines.append("=" * 72)
    return "\n".join(lines)
