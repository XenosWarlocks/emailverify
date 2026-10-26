"""Command line interface.

    emailverify run data/raw/export.csv
    emailverify check someone@example.com --json
    emailverify preflight
    emailverify cache --stats | --purge all

Exit codes: 0 ok, 1 configuration/input error, 2 the run completed but the API
stage aborted part-way (so the output is incomplete, not wrong).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from emailverify import __version__
from emailverify.cache import NullCache, ResultCache
from emailverify.config import Config, ConfigError
from emailverify.consolidate import ConsolidateError, consolidate, format_report
from emailverify.io import writers
from emailverify.io.hubspot import CsvFormatError
from emailverify.models import DomainResult, Verification
from emailverify.pipeline import Pipeline
from emailverify.rules import RuleEngine
from emailverify.scoring import reconcile
from emailverify.stages.domain_check import DomainChecker
from emailverify.stages.verimail import VerimailClient, VerimailError


# --------------------------------------------------------------------------- #
# argument parsing
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="emailverify",
        description="Verify emails from a HubSpot export: rules -> domain liveness -> Verimail.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"emailverify {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # -- run ---------------------------------------------------------------- #
    run = sub.add_parser(
        "run", help="verify a CSV export", formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    run.add_argument("input", nargs="?", default="data/raw/sample_hubspot_export.csv",
                     help="HubSpot CSV export")
    run.add_argument("-o", "--outdir", default="data/out", help="where to write reports")
    run.add_argument("--email-column", default=None,
                     help="email column name (auto-detected if omitted)")
    run.add_argument("--id-column", default=None,
                     help="record id column name (auto-detected if omitted)")
    run.add_argument("--limit", type=int, default=0, help="only process the first N rows")

    stages = run.add_argument_group("stages")
    stages.add_argument("--skip-domain", action="store_true",
                        help="skip stage 2 (no DNS lookups)")
    stages.add_argument("--skip-api", action="store_true",
                        help="skip stage 3 (no Verimail calls, no credits spent)")
    stages.add_argument("--api-gate", choices=["rules", "rules+domain", "unresolved"],
                        default="rules+domain",
                        help="which rows reach the paid API")
    stages.add_argument("--no-dedupe", dest="dedupe", action="store_false",
                        help="verify every address, even ones reaching the same mailbox")

    rules = run.add_argument_group("stage 1: rules")
    rules.add_argument("--disposable-list", default=None,
                       help="extra disposable-domain file, merged with the built-in list")
    rules.add_argument("--free-list", default=None, help="extra free-provider file")
    rules.add_argument("--relay-list", default=None, help="extra alias-relay file")
    rules.add_argument("--role-list", default=None, help="extra role-account file")
    rules.add_argument("--no-typo-detection", dest="detect_typos", action="store_false",
                       help="disable did-you-mean suggestions")
    rules.add_argument("--allow-disposable", dest="reject_disposable", action="store_false",
                       help="flag disposable addresses as risky instead of rejecting them")

    dns_g = run.add_argument_group("stage 2: domain")
    dns_g.add_argument("--dns-workers", type=int, default=16, help="concurrent DNS lookups")
    dns_g.add_argument("--dns-timeout", type=float, default=5.0, help="per-query timeout (s)")
    dns_g.add_argument("--nameserver", action="append", default=[], dest="nameservers",
                       help="override resolver (repeatable), e.g. --nameserver 1.1.1.1")
    dns_g.add_argument("--check-spf", action="store_true", help="also look up SPF")
    dns_g.add_argument("--check-dmarc", action="store_true", help="also look up DMARC")
    dns_g.add_argument("--smtp-probe", action="store_true",
                       help="TCP-connect to port 25 on the primary MX (often blocked locally)")

    api_g = run.add_argument_group("stage 3: Verimail")
    api_g.add_argument("--api-key", default=None, help="overrides VERIMAIL_KEY")
    api_g.add_argument("--api-base-url", default=None, help="overrides VERIMAIL_BASE_URL")
    api_g.add_argument("--rps", type=float, default=None, help="client-side requests/second cap")
    api_g.add_argument("--api-timeout-ms", type=int, default=None,
                       help="per-verification SMTP budget sent to Verimail (1000-45000)")
    api_g.add_argument("--max-api-calls", type=int, default=0,
                       help="stop after this many billable credits (0 = unlimited)")
    api_g.add_argument("--evidence", action="store_true",
                       help="ask Verimail for the SMTP dialogue (written to results.jsonl)")

    cache_g = run.add_argument_group("cache")
    cache_g.add_argument("--no-cache", dest="use_cache", action="store_false",
                         help="do not read or write the result cache")
    cache_g.add_argument("--cache-path", default=None, help="cache database location")

    out_g = run.add_argument_group("output")
    out_g.add_argument("--no-split", dest="split_outputs", action="store_false",
                       help="do not write per-segment CSVs")
    out_g.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    out_g.add_argument("--json", dest="json_out", action="store_true",
                       help="print the summary as JSON instead of a table")

    # -- check -------------------------------------------------------------- #
    chk = sub.add_parser("check", help="verify one or more addresses from the command line")
    chk.add_argument("emails", nargs="+")
    chk.add_argument("--skip-domain", action="store_true")
    chk.add_argument("--skip-api", action="store_true")
    chk.add_argument("--api-key", default=None)
    chk.add_argument("--api-base-url", default=None)
    chk.add_argument("--nameserver", action="append", default=[], dest="nameservers")
    chk.add_argument("--check-spf", action="store_true")
    chk.add_argument("--check-dmarc", action="store_true")
    chk.add_argument("--evidence", action="store_true")
    chk.add_argument("--no-cache", dest="use_cache", action="store_false")
    chk.add_argument("--json", dest="json_out", action="store_true")

    # -- preflight ---------------------------------------------------------- #
    pre = sub.add_parser(
        "preflight",
        help="validate the Verimail key without spending a credit, and test DNS",
    )
    pre.add_argument("--api-key", default=None)
    pre.add_argument("--api-base-url", default=None)
    pre.add_argument("--nameserver", action="append", default=[], dest="nameservers")

    # -- consolidate -------------------------------------------------------- #
    con = sub.add_parser(
        "consolidate",
        help="merge several runs into one decision file you can act on",
        description=(
            "Merge the verified.csv from two or more runs into a single file, "
            "one row per CRM record, keeping the strongest evidence seen for "
            "each. Adds an ev_decision column (REMOVE / REMOVE_DUPLICATE / "
            "FIX / REVIEW / KEEP) and sorts removals to the top."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    con.add_argument(
        "inputs", nargs="+",
        help="verified.csv paths, or the output directories containing them. "
             "Later inputs win ties, so list newer runs last.",
    )
    con.add_argument("-o", "--out", default="data/out/master.csv",
                     help="the single consolidated file to write")
    con.add_argument("--lean", action="store_true",
                     help="write only identity + decision columns instead of "
                          "passing through every original CRM column")
    con.add_argument("--no-duplicates", dest="find_duplicates", action="store_false",
                     help="skip cross-record duplicate-mailbox detection")
    con.add_argument("--json", dest="json_out", action="store_true",
                     help="print the counts as JSON")

    # -- cache -------------------------------------------------------------- #
    cc = sub.add_parser("cache", help="inspect or clear the result cache")
    cc.add_argument("--cache-path", default=None)
    cc.add_argument("--stats", action="store_true", help="show cache contents")
    cc.add_argument("--purge", choices=["all", "domains", "api"], default=None,
                    help="delete cached rows")
    return p


def _config_from_run_args(args: argparse.Namespace) -> Config:
    cfg = Config.from_env()
    cfg.input_path = Path(args.input)
    cfg.outdir = Path(args.outdir)
    if args.email_column:
        cfg.email_column = args.email_column
    if args.id_column:
        cfg.id_column = args.id_column
    cfg.limit = args.limit
    cfg.skip_domain = args.skip_domain
    cfg.skip_api = args.skip_api
    cfg.api_gate = args.api_gate
    cfg.dedupe = args.dedupe
    cfg.split_outputs = args.split_outputs
    cfg.use_cache = args.use_cache
    if args.cache_path:
        cfg.cache_path = Path(args.cache_path)

    cfg.rules.disposable_list = Path(args.disposable_list) if args.disposable_list else None
    cfg.rules.free_list = Path(args.free_list) if args.free_list else None
    cfg.rules.relay_list = Path(args.relay_list) if args.relay_list else None
    cfg.rules.role_list = Path(args.role_list) if args.role_list else None
    cfg.rules.detect_typos = args.detect_typos
    cfg.rules.reject_disposable = args.reject_disposable

    cfg.dns.workers = args.dns_workers
    cfg.dns.timeout = args.dns_timeout
    cfg.dns.lifetime = max(args.dns_timeout * 2, args.dns_timeout + 2.0)
    cfg.dns.nameservers = list(args.nameservers or [])
    cfg.dns.check_spf = args.check_spf
    cfg.dns.check_dmarc = args.check_dmarc
    cfg.dns.smtp_probe = args.smtp_probe

    if args.api_key:
        cfg.api.api_key = args.api_key
    if args.api_base_url:
        cfg.api.base_url = args.api_base_url.rstrip("/")
    if args.rps is not None:
        cfg.api.requests_per_second = args.rps
    if args.api_timeout_ms is not None:
        cfg.api.verify_timeout_ms = args.api_timeout_ms
    cfg.api.max_calls = args.max_api_calls
    cfg.api.evidence = args.evidence
    return cfg


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #


def _progress_printer(quiet: bool):
    state = {"last": ""}

    def report(stage: str, done: int, total: int, detail: str) -> None:
        if quiet:
            return
        pct = f"{100.0 * done / total:5.1f}%" if total else "     "
        line = f"[{stage:<6}] {done:>6}/{total:<6} {pct}  {detail}"
        # Overwrite in place so a long run does not flood the terminal.
        pad = max(0, len(state["last"]) - len(line))
        sys.stderr.write("\r" + line + " " * pad)
        sys.stderr.flush()
        state["last"] = line
        if total and done >= total:
            sys.stderr.write("\n")
            state["last"] = ""

    return report


def cmd_run(args: argparse.Namespace) -> int:
    cfg = _config_from_run_args(args)
    if not cfg.skip_api and not cfg.api.api_key:
        print(
            "No VERIMAIL_KEY found -- running stages 1 and 2 only.\n"
            "Set it in .env (see .env.example) or pass --api-key to enable stage 3.\n",
            file=sys.stderr,
        )
        cfg.skip_api = True

    cfg.validate()
    result = Pipeline(cfg, progress=_progress_printer(args.quiet)).run()

    if args.json_out:
        print(json.dumps(result.summary, indent=2, default=str))
    else:
        print(writers.format_summary(result.summary))
        print("\nOutputs:")
        for name, path in result.outputs.items():
            print(f"  {name:<22} {path}")
        if result.warnings:
            print("\nWarnings:")
            for w in result.warnings:
                print(f"  ! {w}")

    aborted = any("aborted" in w for w in result.warnings)
    return 2 if aborted else 0


def cmd_check(args: argparse.Namespace) -> int:
    cfg = Config.from_env()
    if args.api_key:
        cfg.api.api_key = args.api_key
    if args.api_base_url:
        cfg.api.base_url = args.api_base_url.rstrip("/")
    cfg.dns.nameservers = list(args.nameservers or [])
    cfg.dns.check_spf = args.check_spf
    cfg.dns.check_dmarc = args.check_dmarc
    cfg.api.evidence = args.evidence
    cfg.use_cache = args.use_cache

    engine = RuleEngine(cfg.rules)
    cache = ResultCache(cfg.cache_path) if cfg.use_cache else NullCache()
    payloads = []

    with cache:
        checker = DomainChecker(cfg.dns, cache)
        client = (
            VerimailClient(cfg.api, cache)
            if (cfg.api.api_key and not args.skip_api)
            else None
        )
        for email in args.emails:
            rule = engine.check(email)
            v = Verification(
                record_id="", email_raw=email, rule=rule,
                domain=DomainResult(domain=rule.ascii_domain),
            )
            if rule.ok and not args.skip_domain:
                v.domain = checker.check(rule.ascii_domain)
            if rule.ok and client is not None:
                v.api = client.verify(rule.normalized)
            reconcile(v, reject_disposable=cfg.rules.reject_disposable)
            payloads.append(v)

    if args.json_out:
        print(json.dumps([writers.verification_to_dict(v) for v in payloads],
                         indent=2, default=str))
        return 0

    for v in payloads:
        print(f"\n{v.email_raw}")
        print(f"  normalized      {v.rule.normalized or '-'}")
        print(f"  rules           {'pass' if v.rule.ok else 'FAIL: ' + v.rule.detail}")
        print(f"  initial status  {v.initial_status.value}")
        print(f"  domain          {v.domain.status.value}"
              + (f"  mx={','.join(v.domain.mx_hosts[:3])}" if v.domain.mx_hosts else ""))
        if v.api is not None:
            if v.api.ok:
                print(f"  verimail        {v.api.verdict.value} / {v.api.reason}"
                      f"  (billed={v.api.billed}, cached={v.api.from_cache})")
            else:
                print(f"  verimail        error: {v.api.error}")
        flags = v.rule.flags.as_list()
        if flags:
            print(f"  flags           {', '.join(flags)}")
        if v.rule.did_you_mean:
            print(f"  did you mean    {v.rule.did_you_mean}")
        print(f"  VERDICT         {v.final_verdict.value} / {v.final_reason}"
              f"  -> {v.action.value}  (risk {v.risk_score}, {v.confidence} confidence)")
    print()
    return 0


def cmd_preflight(args: argparse.Namespace) -> int:
    cfg = Config.from_env()
    if args.api_key:
        cfg.api.api_key = args.api_key
    if args.api_base_url:
        cfg.api.base_url = args.api_base_url.rstrip("/")
    cfg.dns.nameservers = list(args.nameservers or [])
    ok = True

    print("DNS resolver")
    try:
        checker = DomainChecker(cfg.dns, cache=None)
        probe = checker.check("gmail.com")
        if probe.is_active:
            print(f"  ok          gmail.com -> {len(probe.mx_hosts)} MX "
                  f"({probe.provider}) in {probe.elapsed_ms} ms")
        else:
            ok = False
            print(f"  FAILED      gmail.com resolved as {probe.status.value}: {probe.error}")
    except Exception as exc:  # resolver construction can fail on odd setups
        ok = False
        print(f"  FAILED      {exc.__class__.__name__}: {exc}")

    print("Verimail API")
    if not cfg.api.api_key:
        print("  skipped     no VERIMAIL_KEY set (stages 1-2 will still work)")
    else:
        try:
            print(f"  ok          {VerimailClient(cfg.api).preflight()}")
        except VerimailError as exc:
            ok = False
            print(f"  FAILED      {exc}")
        except ConfigError as exc:
            ok = False
            print(f"  FAILED      {exc}")

    print("\nReady." if ok else "\nPreflight found problems (see above).")
    return 0 if ok else 1


def cmd_consolidate(args: argparse.Namespace) -> int:
    result = consolidate(args.inputs, args.out, lean=args.lean,
                         find_duplicates=args.find_duplicates)
    if args.json_out:
        print(json.dumps(
            {
                "out": str(result.out_path),
                "records": len(result.records),
                "runs": result.runs,
                "decisions": result.counts,
                "evidence_levels": result.level_counts,
                "duplicates_flagged": result.duplicates_flagged,
            },
            indent=2,
        ))
    else:
        print(format_report(result))
    return 0


def cmd_cache(args: argparse.Namespace) -> int:
    cfg = Config.from_env()
    path = Path(args.cache_path) if args.cache_path else cfg.cache_path
    with ResultCache(path) as cache:
        if args.purge:
            removed = cache.purge(args.purge)
            print(f"Purged {removed} rows from {args.purge} cache ({path})")
        stats = cache.stats()
        print(f"Cache: {path}")
        print(f"  cached domains  {stats['domains']}")
        print(f"  cached mailboxes {stats['emails']}")
    return 0


# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "run": cmd_run,
        "check": cmd_check,
        "preflight": cmd_preflight,
        "consolidate": cmd_consolidate,
        "cache": cmd_cache,
    }
    try:
        return handlers[args.command](args)
    except (ConfigError, CsvFormatError, ConsolidateError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
