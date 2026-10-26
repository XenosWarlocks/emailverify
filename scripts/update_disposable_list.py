#!/usr/bin/env python
"""Download a community disposable-domain blocklist.

The bundled seed list covers the common offenders, but throwaway domains rotate
weekly and no static list stays current. This fetches a large maintained list
and writes it to data/disposable_domains.txt, which you then pass to the
pipeline:

    python scripts/update_disposable_list.py
    emailverify run data/raw/export.csv --disposable-list data/disposable_domains.txt

The downloaded list is *merged* with the bundled seed at load time, so this
never loses the curated entries.

Run it on a schedule (weekly is plenty) if you verify continuously.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

# Several mirrors, tried in order. All are plain newline-delimited domain lists.
SOURCES = (
    "https://raw.githubusercontent.com/disposable-email-domains/"
    "disposable-email-domains/main/disposable_email_blocklist.conf",
    "https://raw.githubusercontent.com/7c/fakefilter/main/txt/data.txt",
    "https://raw.githubusercontent.com/martenson/disposable-email-domains/"
    "master/disposable_email_blocklist.conf",
)

DEFAULT_OUT = Path("data/disposable_domains.txt")


def fetch(url: str, timeout: float = 30.0) -> str:
    req = Request(url, headers={"User-Agent": "emailverify/0.1 list-updater"})
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URLs
        if resp.status != 200:
            raise URLError(f"HTTP {resp.status}")
        return resp.read().decode("utf-8", "replace")


def parse(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith(("#", "//")):
            continue
        # Some mirrors ship "domain,extra,fields" rows.
        domain = line.split(",")[0].split()[0].strip().strip(".")
        if "." in domain and " " not in domain:
            out.add(domain)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-o", "--out", default=str(DEFAULT_OUT), help="output file")
    ap.add_argument("--url", action="append", default=[], dest="urls",
                    help="source URL (repeatable); defaults to the built-in mirrors")
    ap.add_argument("--merge", action="store_true",
                    help="union with the existing output file instead of replacing it")
    args = ap.parse_args(argv)

    out = Path(args.out)
    domains: set[str] = set()
    if args.merge and out.exists():
        domains |= parse(out.read_text(encoding="utf-8"))
        print(f"starting from {len(domains)} existing entries")

    sources = args.urls or list(SOURCES)
    fetched_any = False
    for url in sources:
        try:
            found = parse(fetch(url))
        except (URLError, OSError, TimeoutError) as exc:
            print(f"  skip  {url}\n        {exc.__class__.__name__}: {exc}", file=sys.stderr)
            continue
        print(f"  ok    {len(found):>7} domains from {url}")
        domains |= found
        fetched_any = True
        if not args.urls:
            # The built-in mirrors largely overlap; one good fetch is enough.
            break

    if not fetched_any:
        print("error: every source failed. Check connectivity or pass --url.", file=sys.stderr)
        return 1

    out.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# Disposable-domain blocklist fetched by scripts/update_disposable_list.py\n"
        f"# sources: {', '.join(sources)}\n"
        f"# entries: {len(domains)}\n"
    )
    out.write_text(header + "\n".join(sorted(domains)) + "\n", encoding="utf-8")
    print(f"\nwrote {len(domains)} domains -> {out}")
    print(f"use it with:  emailverify run <csv> --disposable-list {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
