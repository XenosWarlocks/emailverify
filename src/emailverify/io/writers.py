"""Output: enriched CSV, JSONL detail, segment files, summary.

The enriched CSV keeps every original column untouched and appends `ev_*`
columns, so the file can go straight back into HubSpot as an import without
remapping anything. Columns are prefixed to guarantee they never collide with
a HubSpot property name.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable, Sequence

from emailverify.models import Action, InitialStatus, Verdict, Verification

# Appended columns, in order. Keep this list and `_row_for` in sync.
EV_COLUMNS = [
    "ev_email_normalized",
    "ev_canonical_email",
    "ev_initial_status",
    "ev_final_verdict",
    "ev_final_reason",
    "ev_final_code",
    "ev_recommended_action",
    "ev_mailable",
    "ev_risk_score",
    "ev_confidence",
    "ev_rule_ok",
    "ev_rule_reason",
    "ev_rule_detail",
    "ev_domain",
    "ev_domain_status",
    "ev_domain_provider",
    "ev_domain_mx",
    "ev_domain_null_mx",
    "ev_domain_implicit_mx",
    "ev_has_spf",
    "ev_has_dmarc",
    "ev_smtp_reachable",
    "ev_disposable",
    "ev_role_account",
    "ev_free_provider",
    "ev_relay_provider",
    "ev_catch_all",
    "ev_plus_tagged",
    "ev_typo_suspect",
    "ev_did_you_mean",
    "ev_api_called",
    "ev_api_verdict",
    "ev_api_reason",
    "ev_api_code",
    "ev_api_action",
    "ev_api_billed",
    "ev_api_provider",
    "ev_api_latency_ms",
    "ev_api_error",
    "ev_verified_as",
    "ev_notes",
    "ev_checked_at",
]


def _b(value: bool | None) -> str:
    """Booleans as HubSpot expects them in an import: TRUE/FALSE, blank if unknown."""
    if value is None:
        return ""
    return "TRUE" if value else "FALSE"


def _row_for(v: Verification) -> dict[str, str]:
    from emailverify.scoring import mailable

    api = v.api
    flags = v.rule.flags
    return {
        "ev_email_normalized": v.rule.normalized,
        "ev_canonical_email": v.rule.canonical,
        "ev_initial_status": v.initial_status.value,
        "ev_final_verdict": v.final_verdict.value,
        "ev_final_reason": v.final_reason,
        "ev_final_code": str(v.final_code) if v.final_code is not None else "",
        "ev_recommended_action": v.action.value,
        "ev_mailable": _b(mailable(v)),
        "ev_risk_score": str(v.risk_score),
        "ev_confidence": v.confidence,
        "ev_rule_ok": _b(v.rule.ok),
        "ev_rule_reason": v.rule.reason if not v.rule.ok else "",
        "ev_rule_detail": v.rule.detail,
        "ev_domain": v.rule.ascii_domain or v.domain.domain,
        "ev_domain_status": v.domain.status.value,
        "ev_domain_provider": v.domain.provider,
        "ev_domain_mx": ";".join(v.domain.mx_hosts),
        "ev_domain_null_mx": _b(v.domain.null_mx),
        "ev_domain_implicit_mx": _b(v.domain.implicit_mx),
        "ev_has_spf": _b(v.domain.has_spf) if v.domain.spf_checked else "",
        "ev_has_dmarc": _b(v.domain.has_dmarc) if v.domain.dmarc_checked else "",
        "ev_smtp_reachable": _b(v.domain.smtp_reachable),
        "ev_disposable": _b(flags.disposable),
        "ev_role_account": _b(flags.role_account),
        "ev_free_provider": _b(flags.free_provider),
        "ev_relay_provider": _b(flags.relay_provider),
        "ev_catch_all": _b(flags.catch_all),
        "ev_plus_tagged": _b(flags.plus_tagged),
        "ev_typo_suspect": _b(flags.typo_suspect),
        "ev_did_you_mean": v.rule.did_you_mean,
        "ev_api_called": _b(api is not None),
        "ev_api_verdict": api.verdict.value if api and api.ok else "",
        "ev_api_reason": api.reason if api and api.ok else "",
        "ev_api_code": str(api.code) if api and api.ok and api.code is not None else "",
        "ev_api_action": api.suggested_action.value if api and api.ok else "",
        "ev_api_billed": _b(api.billed) if api and api.ok else "",
        "ev_api_provider": api.provider if api and api.ok else "",
        "ev_api_latency_ms": str(api.latency_ms) if api and api.ok else "",
        "ev_api_error": api.error if api else "",
        "ev_verified_as": v.verified_as,
        "ev_notes": " | ".join(v.notes),
        "ev_checked_at": v.checked_at,
    }


def write_enriched_csv(
    path: Path,
    original_columns: Sequence[str],
    rows: Iterable[tuple[dict[str, str], Verification]],
) -> int:
    """Original row + ev_* columns. Returns the row count written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = list(original_columns) + EV_COLUMNS
    count = 0
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for original, verification in rows:
            out = dict(original)
            out.update(_row_for(verification))
            writer.writerow(out)
            count += 1
    return count


def write_segment_csv(
    path: Path,
    original_columns: Sequence[str],
    rows: Iterable[tuple[dict[str, str], Verification]],
) -> int:
    return write_enriched_csv(path, original_columns, rows)


def verification_to_dict(v: Verification) -> dict[str, Any]:
    payload = asdict(v)
    payload["initial_status"] = v.initial_status.value
    payload["final_verdict"] = v.final_verdict.value
    payload["final_reason"] = v.final_reason
    payload["action"] = v.action.value
    payload["rule"]["reason"] = v.rule.reason
    payload["domain"]["status"] = v.domain.status.value
    if v.api is not None:
        payload["api"]["verdict"] = v.api.verdict.value
        payload["api"]["suggested_action"] = v.api.suggested_action.value
    return payload


def write_jsonl(path: Path, verifications: Iterable[Verification]) -> int:
    """Full detail, one JSON object per line -- including API evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as fh:
        for v in verifications:
            fh.write(json.dumps(verification_to_dict(v), default=str, ensure_ascii=False))
            fh.write("\n")
            count += 1
    return count


def build_summary(verifications: Sequence[Verification], extra: dict[str, Any]) -> dict[str, Any]:
    from emailverify.scoring import mailable

    def tally(key) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in verifications:
            counts[key(v)] = counts.get(key(v), 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    flag_counts: dict[str, int] = {}
    for v in verifications:
        for name in v.rule.flags.as_list():
            flag_counts[name] = flag_counts.get(name, 0) + 1

    total = len(verifications)
    mailable_count = sum(1 for v in verifications if mailable(v))
    return {
        "total_rows": total,
        "mailable": mailable_count,
        "not_mailable": total - mailable_count,
        "mailable_pct": round(100.0 * mailable_count / total, 1) if total else 0.0,
        "initial_status": tally(lambda v: v.initial_status.value),
        "final_verdict": tally(lambda v: v.final_verdict.value),
        "recommended_action": tally(lambda v: v.action.value),
        "final_reason": tally(lambda v: v.final_reason or "none"),
        "confidence": tally(lambda v: v.confidence),
        "flags": dict(sorted(flag_counts.items(), key=lambda kv: -kv[1])),
        "domain_status": tally(lambda v: v.domain.status.value),
        **extra,
    }


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")


def format_summary(summary: dict[str, Any]) -> str:
    """Human-readable summary for the terminal."""
    lines: list[str] = []
    total = summary.get("total_rows", 0)

    def bar(n: int, width: int = 24) -> str:
        if not total:
            return ""
        filled = int(round(width * n / total))
        return "#" * filled + "." * (width - filled)

    def block(title: str, counts: dict[str, int]) -> None:
        if not counts:
            return
        lines.append("")
        lines.append(title)
        for label, n in counts.items():
            pct = 100.0 * n / total if total else 0.0
            lines.append(f"  {label:<24} {n:>6}  {pct:>5.1f}%  {bar(n)}")

    lines.append("=" * 68)
    lines.append(f"  {total} rows verified")
    lines.append("=" * 68)

    block("Initial status (stage 1 + 2)", summary.get("initial_status", {}))
    block("Final verdict", summary.get("final_verdict", {}))
    block("Recommended action", summary.get("recommended_action", {}))
    block("Top reasons", dict(list(summary.get("final_reason", {}).items())[:10]))
    block("Flags", summary.get("flags", {}))

    lines.append("")
    lines.append(
        f"Mailable: {summary.get('mailable', 0)}/{total} "
        f"({summary.get('mailable_pct', 0)}%)"
    )
    for key, label in (
        ("api_calls_sent", "API addresses sent"),
        ("api_credits_billed", "API credits billed"),
        ("api_cache_hits", "API cache hits"),
        ("domains_resolved", "Unique domains resolved"),
        ("duplicates_collapsed", "Duplicate mailboxes collapsed"),
        ("elapsed_seconds", "Elapsed (s)"),
    ):
        if key in summary:
            lines.append(f"{label}: {summary[key]}")
    lines.append("=" * 68)
    return "\n".join(lines)


def segment_of(v: Verification) -> str:
    """Which segment file a row belongs in."""
    if v.initial_status is InitialStatus.INVALID_SYNTAX:
        return "invalid_syntax"
    if v.final_verdict is Verdict.UNDELIVERABLE:
        return "undeliverable"
    if v.action is Action.REJECT:
        return "rejected"
    if v.final_verdict is Verdict.RISKY:
        return "risky"
    if v.final_verdict is Verdict.UNKNOWN:
        return "unknown"
    return "deliverable"
