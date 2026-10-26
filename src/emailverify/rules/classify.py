"""Classification of a syntactically-valid address.

Everything here is a *signal*, not a verdict: disposable, role, free provider,
alias relay, plus-tag, likely typo. The pipeline decides what to do with them.
"""

from __future__ import annotations

from emailverify import datasets

# Providers that ignore dots in the local part. Used only for canonicalization
# (duplicate detection) -- we never rewrite the address we report.
_DOT_INSENSITIVE = {"gmail.com", "googlemail.com"}

# Separator each provider uses for sub-addressing.
_TAG_SEPARATORS = {
    "gmail.com": "+",
    "googlemail.com": "+",
    "outlook.com": "+",
    "hotmail.com": "+",
    "live.com": "+",
    "icloud.com": "+",
    "me.com": "+",
    "proton.me": "+",
    "protonmail.com": "+",
    "fastmail.com": "+",
    "yahoo.com": "-",   # Yahoo uses base-keyword with '-'
    "zoho.com": "+",
}
_DEFAULT_TAG_SEP = "+"


def damerau_levenshtein(a: str, b: str, cutoff: int = 2) -> int:
    """Edit distance with transpositions, bailing out past `cutoff`.

    The early exit matters: this runs against the popular-domain list for every
    row, and we only ever care about distance 1.
    """
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cutoff:
        return cutoff + 1

    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0] * len(b)
        best = cur[0]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            cur[j] = min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
            best = min(best, cur[j])
        if best > cutoff:
            return cutoff + 1
        prev2, prev = prev, cur
    return prev[len(b)]


def split_tag(local: str, domain: str) -> tuple[str, str]:
    """Split a sub-addressed local part into (base, tag).

    'anupam936574+11' -> ('anupam936574', '11')
    """
    sep = _TAG_SEPARATORS.get(domain, _DEFAULT_TAG_SEP)
    if sep in local:
        base, _, tag = local.partition(sep)
        # A leading separator means the whole thing is the local part, not a tag.
        if base:
            return base, tag
    return local, ""


def canonicalize(local: str, domain: str) -> str:
    """Collapse an address to the mailbox it actually reaches.

    Used for duplicate detection only. `a.b+tag@gmail.com` and `ab@gmail.com`
    are the same inbox, and a CRM that mails both has paid twice to annoy one
    person once.
    """
    base, _ = split_tag(local, domain)
    if domain in _DOT_INSENSITIVE:
        base = base.replace(".", "")
    return f"{base.lower()}@{domain}"


def suggest_correction(domain: str, popular: frozenset[str] | None = None) -> str:
    """Return the domain the user probably meant, or "" if this one looks fine."""
    typos = datasets.domain_typos()
    if domain in typos:
        return typos[domain]

    pool = popular if popular is not None else datasets.popular_domains()
    if domain in pool:
        return ""

    # Only distance-1 suggestions. Distance 2 produces too many confident-looking
    # wrong answers on legitimate small domains (e.g. "gmail.com" for "gmx.com").
    for candidate in pool:
        if damerau_levenshtein(domain, candidate, cutoff=1) == 1:
            return candidate
    return ""


def registrable_provider(mx_hosts: list[str]) -> str:
    """Best-effort 'who runs this mailbox' from the MX hostnames.

    Deliberately simple -- no Public Suffix List dependency. Takes the last two
    labels, with a carve-out for the common two-part suffixes that would
    otherwise collapse to something useless like 'co.uk'.
    """
    if not mx_hosts:
        return ""
    host = mx_hosts[0].lower().rstrip(".")
    parts = host.split(".")
    if len(parts) < 2:
        return host
    two_part_suffixes = {
        "co.uk", "co.jp", "co.in", "co.nz", "co.za", "com.au", "com.br",
        "com.cn", "com.mx", "com.sg", "com.tr", "net.au", "org.uk", "ac.uk",
    }
    tail2 = ".".join(parts[-2:])
    if tail2 in two_part_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])
    return tail2
