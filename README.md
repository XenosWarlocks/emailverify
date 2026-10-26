# emailverify - three-stage email verification for HubSpot exports

Takes a HubSpot contact export, verifies every address through three
increasingly expensive stages, and writes back a CSV you can re-import.

```
all rows
  |
  +-- stage 1  rules      free, offline, instant
  |            syntax (RFC 5321/5322 subset), disposable / role / free-provider
  |            / alias-relay classification, "did you mean gmail.com?"
  |
  +-- stage 2  domain     one DNS query per *domain*, cached
  |            MX -> A/AAAA fallback -> null-MX. Does this domain accept mail?
  |            => this sets the initial status: syntax ok + domain live = "ok"
  |
  +-- stage 3  verimail   one paid credit per *mailbox*, cached
               SMTP-level mailbox verification via the Verimail v3 API, for the
               addresses that survived stages 1-2
```

Each stage narrows what the next one sees, because each one costs dramatically
more than the last. On the 10-row sample that means 10 rule checks, **4** DNS
lookups (six rows share `gmail.com`), and **9** API calls (the disposable
address is already decided and never sent).

## Install

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux

pip install -r requirements-dev.txt
pip install -e .                # optional: puts `emailverify` on PATH
```

Then set your API key:

```bash
cp .env.example .env
# edit .env and set VERIMAIL_KEY=...
```

Without a key the tool still runs stages 1 and 2 and tells you it skipped
stage 3 - useful for a first pass over a large list before spending anything.

## Use

```bash
# check the key (free - see "Credits" below) and the resolver
emailverify preflight

# full run
emailverify run data/raw/sample_hubspot_export.csv

# free dry run: rules + DNS only, no credits spent
emailverify run data/raw/export.csv --skip-api

# one-off addresses, with the reasoning shown
emailverify check kdanny@akrodlabs.com someone@gmial.com not-an-email

# cap spend while you are still calibrating
emailverify run data/raw/export.csv --max-api-calls 500
```

Without `pip install -e .`, run it as `python -m emailverify ...` with
`PYTHONPATH=src`.

### Output

Everything lands in `--outdir` (default `data/out/`):

| File | Contents |
|---|---|
| `verified.csv` | **every original column untouched**, plus `ev_*` columns. Re-importable into HubSpot as-is. |
| `results.jsonl` | one JSON object per row with full stage detail, including SMTP evidence when `--evidence` is set |
| `summary.json` | aggregate counts, credits spent, timings |
| `segments/*.csv` | the same rows split into `deliverable` / `risky` / `unknown` / `undeliverable` / `rejected` / `invalid_syntax` |

The columns you will actually filter on:

| Column | Meaning |
|---|---|
| `ev_initial_status` | `ok` / `invalid_syntax` / `dead_domain` / `unknown` - the stage 1+2 answer |
| `ev_final_verdict` | `deliverable` / `risky` / `unknown` / `undeliverable` |
| `ev_recommended_action` | `accept` / `accept_and_confirm` / `reject` |
| `ev_mailable` | `TRUE` if you would put it in a campaign |
| `ev_risk_score` | 0-100, advisory, for sorting |
| `ev_confidence` | how much to trust the verdict |
| `ev_canonical_email` | the mailbox this address actually reaches - group by it to find duplicates |
| `ev_verified_as` | which mailbox was sent to the API, when dedupe collapsed this row onto another |
| `ev_did_you_mean` | suggested correction for a likely typo |

Booleans are written `TRUE`/`FALSE` (what HubSpot imports expect), and **blank
means "not checked"** rather than false - `ev_has_spf` is empty unless you
passed `--check-spf`.

## How the verdict is decided

Precedence is strict:

1. **Stage 1 is absolute.** If syntax fails, nothing else is consulted. No DNS
   query and no credit spent to be told "not an email".
2. **Stage 3 beats stage 2**, because an SMTP-level answer strictly dominates a
   DNS-level guess. A `deliverable` from the API overrides a DNS timeout.
3. **Stage 2 is the fallback**, and is what produces the initial status.

Three deliberate choices worth knowing about:

**A live domain is not a valid mailbox.** If stage 2 says the domain accepts
mail but stage 3 never ran, the verdict is `unknown` / `not_checked`, not
`valid`. The domain answering proves nothing about this particular inbox. The
row is still mailable, just not confirmed.

**A DNS error is not a dead domain.** NXDOMAIN and null-MX (RFC 7505) are
definitive rejections. A timeout or SERVFAIL is `unknown`, and those rows still
go to the API. A resolver hiccup must never mark a real contact invalid.

**Disposable is a business rule, not a deliverability one.** Throwaway
mailboxes genuinely do accept mail, which is exactly why neither DNS nor SMTP
flags them - Verimail will happily report `deliverable`. So the disposable
check is applied *last* and overrides an `accept`. Use `--allow-disposable` to
downgrade them to risky instead of rejecting.

## Credits and cost control

Verimail bills per verification, but **not** for `unknown` verdicts or syntax
errors ([result codes](https://verimail.io/docs/results)). The pipeline is
built around that:

- **`preflight` is free.** It probes with an empty address, which returns
  `200 empty_address` unbilled, so the key is proven to work without spending
  anything. A bad key returns 401 and preflight fails loudly.
- **Dead domains are skipped by default.** Verimail bills for its own
  `no_mail_server` answer, so once DNS has said the domain does not exist there
  is nothing left to buy. Use `--api-gate rules` to send everything that passes
  stage 1 regardless.
- **Duplicates are collapsed.** `anupam936574+11@gmail.com` and
  `anupam936574@gmail.com` are one inbox; one credit answers for both. The
  collapsed rows record which mailbox was checked in `ev_verified_as`.
- **Everything is cached** in SQLite (`.cache/emailverify.sqlite3`), domains for
  7 days and mailboxes for 30. A re-run after a crash, or over an export that
  overlaps last week's, costs **zero**. That also gives you resume-for-free: a
  killed run picks up where it stopped.
- **`--max-api-calls N` is a hard ceiling** on billable credits, enforced with
  an atomic reservation so concurrent workers cannot overshoot it.
- **401 / 402 / 403 abort the run immediately** rather than failing every
  remaining row one at a time. Partial output is still written, and the exit
  code is 2.

Inspect or clear the cache:

```bash
emailverify cache --stats
emailverify cache --purge api        # or: domains, all
```

## Keeping the disposable list current

The bundled list is a curated seed of ~500 common offenders. Real throwaway
domains number in the tens of thousands and rotate weekly, so for production
use pull the community list:

```bash
python scripts/update_disposable_list.py
emailverify run data/raw/export.csv --disposable-list data/disposable_domains.txt
```

The downloaded list is *merged* with the bundled seed, never substituted for
it. Verimail also flags disposables independently, so stage 3 acts as a second
opinion on anything the list misses - and when it does, the flag is promoted
back onto the row.

## Notable flags

| Flag | Why |
|---|---|
| `--skip-api` | stages 1-2 only; spend nothing |
| `--api-gate rules \| rules+domain \| unresolved` | which rows reach the paid API (default `rules+domain`) |
| `--check-spf` / `--check-dmarc` | extra domain-health signals; a live domain with no SPF rarely sends real mail |
| `--smtp-probe` | TCP-connect to port 25 on the primary MX. **Off by default** - most consumer and cloud networks block outbound 25, which makes a failure meaningless. A failed probe never downgrades a verdict. |
| `--nameserver 1.1.1.1` | override the resolver (repeatable) |
| `--evidence` | ask Verimail for the SMTP dialogue; lands in `results.jsonl` |
| `--no-cache` | bypass the cache entirely |
| `--limit N` | first N rows, for a quick look |
| `--email-column` | if the export's email header is non-standard (auto-detected otherwise) |

## Layout

```
src/emailverify/
  config.py            defaults -> .env -> CLI flag precedence
  models.py            verdicts, flags, stage results, shared reason codes
  datasets.py          loads the bundled + user domain lists
  cache.py             SQLite result cache (thread-safe, TTL'd)
  ratelimit.py         token bucket
  scoring.py           three stage results -> one decision
  pipeline.py          orchestration
  cli.py               run / check / preflight / cache
  rules/               stage 1: syntax.py, classify.py, engine.py
  stages/              stage 2: domain_check.py   stage 3: verimail.py
  io/                  hubspot.py (reader), writers.py (reports)
  resources/           disposable, free, relay, role, popular, typo lists
tests/                 217 tests, no network required
scripts/               disposable-list updater
```

Local rule codes deliberately reuse Verimail's numbering (100-105 for syntax,
400 for no mail server, and so on), so one table explains a rejection no matter
which stage produced it.

## Tests

```bash
python -m pytest
```

217 tests, none of which touch the network: DNS is a scripted resolver and the
API is a fake HTTP session. They cover the full cost path too - that a re-run
bills nothing, that dead domains never reach the API, and that the credit
budget holds under concurrency.

## Known limits

- **No catch-all handling beyond what Verimail reports.** A catch-all domain
  accepts every address, so `risky` is the honest ceiling there; `ev_catch_all`
  marks them.
- **Alias relays** (`wearehackerone.com`, SimpleLogin, Apple Private Relay)
  always verify as deliverable, because the relay accepts the mail and forwards
  it. That tells you nothing about whether a human reads it, so they are
  flagged `relay_provider` and scored accordingly.
- **Typo suggestions are distance-1 only.** Distance 2 produces too many
  confident-looking wrong answers on legitimate small domains.
- `registrable_provider` uses a short two-part-suffix table rather than the full
  Public Suffix List, so exotic suffixes may group imprecisely. It is a
  reporting field only and never affects a verdict.
- **Bulk/file verification is not wired up.** Verimail's bulk path is a
  dashboard CSV upload rather than a documented API endpoint, so this calls
  `/v3/verify` per address with client-side pacing and caching instead.
- **The Verimail stage has not been exercised against the live API** - no key
  was available here. It was verified against a local mock implementing the
  documented v3 contract (request shape, all four verdicts, the legacy response
  shape, 400/401/402/403/429/500 handling, Retry-After). Run
  `emailverify preflight` first; it validates the key for free.
