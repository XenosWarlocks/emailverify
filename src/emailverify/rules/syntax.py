"""Syntax validation.

Scope: a pragmatic subset of RFC 5321/5322 -- what mail servers in the real
world actually accept, which is narrower than the RFCs permit. Specifically we
reject some technically-legal-but-never-seen forms (comments, folding
whitespace, most quoted-string exotica) because in a CRM export they are
always data corruption rather than a real mailbox.

Reason codes match Verimail's 100-105 range so stage 1 and stage 3 speak the
same language.
"""

from __future__ import annotations

import re

# RFC 5322 atext, the characters legal in an unquoted local part.
ATEXT = r"a-zA-Z0-9!#$%&'*+/=?^_`{|}~-"

# Practical limits. 254 is the longest address that can traverse SMTP
# (RFC 5321 4.5.3.1.3 gives 256 for the reverse-path *including* the <>).
MAX_ADDRESS_LEN = 254
MAX_LOCAL_LEN = 64
MAX_DOMAIN_LEN = 253
MAX_LABEL_LEN = 63

_DOT_ATOM = re.compile(rf"^[{ATEXT}]+(?:\.[{ATEXT}]+)*$")
# Note the leading dot: ATEXT ends in '-', so appending anything after it
# would be parsed as a character range ('~-.') instead of a literal.
_ATEXT_OR_DOT = re.compile(rf"[.{ATEXT}]")
_QUOTED = re.compile(r'^"(?:[^"\\]|\\.)*"$')
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_TLD = re.compile(r"^[a-z]{2,63}$", re.IGNORECASE)
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# "Full Name <addr@example.com>" and stray wrapping that CRM exports pick up.
_ANGLE = re.compile(r"^[^<>]*<\s*([^<>]+?)\s*>[^<>]*$")

# Unicode lookalikes and invisible characters that get pasted in from
# documents. Stripping these is safe; leaving them in produces a domain that
# looks identical to a valid one but resolves to nothing.
_INVISIBLE = dict.fromkeys(
    map(ord, "​‌‍⁠﻿­"), None
)
_TRANSLATE = {
    ord(" "): " ",   # non-breaking space
    ord("＠"): "@",   # fullwidth @
    ord("．"): ".",   # fullwidth .
    ord("。"): ".",   # ideographic full stop
    ord("․"): ".",   # one dot leader
    **_INVISIBLE,
}


class SyntaxError_(Exception):
    """Internal control flow for check_syntax; carries a reason code."""

    def __init__(self, code: int, detail: str = "") -> None:
        super().__init__(detail or str(code))
        self.code = code
        self.detail = detail


def normalize(raw: str | None) -> str:
    """Clean an address up to the point where it can be parsed.

    Does NOT validate. Lowercases the domain only -- the local part is
    case-sensitive per RFC 5321 2.4, and while essentially every real provider
    treats it case-insensitively, rewriting it would silently change the
    identity of the address we report back to the CRM.
    """
    if raw is None:
        return ""
    s = str(raw).translate(_TRANSLATE).strip()
    # Unwrap "Name <addr>" and mailto:
    m = _ANGLE.match(s)
    if m:
        s = m.group(1).strip()
    if s.lower().startswith("mailto:"):
        s = s[7:].strip()
    s = s.strip().strip(",;")
    # Lowercase the domain half only.
    if "@" in s:
        local, _, domain = s.rpartition("@")
        s = f"{local}@{domain.lower().strip('.')}"
    return s


def _check_local(local: str) -> None:
    if not local:
        raise SyntaxError_(102, "empty local part")
    if len(local) > MAX_LOCAL_LEN:
        raise SyntaxError_(103, f"local part is {len(local)} chars (max {MAX_LOCAL_LEN})")
    if local.startswith('"') and local.endswith('"') and len(local) > 1:
        if not _QUOTED.match(local):
            raise SyntaxError_(105, "malformed quoted local part")
        return
    if local.startswith(".") or local.endswith("."):
        raise SyntaxError_(105, "local part starts or ends with a dot")
    if ".." in local:
        raise SyntaxError_(105, "local part contains consecutive dots")
    if not _DOT_ATOM.match(local):
        bad = sorted({c for c in local if not _ATEXT_OR_DOT.match(c)})
        raise SyntaxError_(105, f"illegal character(s) in local part: {''.join(bad) or '?'}")


def _check_domain(domain: str) -> str:
    """Validate the domain and return its ASCII (punycode) form."""
    if not domain:
        raise SyntaxError_(104, "empty domain")
    if domain.startswith("[") and domain.endswith("]"):
        # Address literal: user@[192.0.2.1]. Legal SMTP, but in a CRM export it
        # is never a mailbox we want to contact.
        raise SyntaxError_(104, "address literal (IP) domain")
    if len(domain) > MAX_DOMAIN_LEN:
        raise SyntaxError_(104, f"domain is {len(domain)} chars (max {MAX_DOMAIN_LEN})")
    if "." not in domain:
        raise SyntaxError_(104, "domain has no dot (not a public FQDN)")
    if ".." in domain:
        raise SyntaxError_(104, "domain contains consecutive dots")
    if _IPV4.match(domain):
        raise SyntaxError_(104, "bare IPv4 address as domain")

    try:
        ascii_domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise SyntaxError_(104, f"domain is not encodable as IDNA: {exc}") from exc

    labels = ascii_domain.split(".")
    for label in labels:
        if not label:
            raise SyntaxError_(104, "empty domain label")
        if len(label) > MAX_LABEL_LEN:
            raise SyntaxError_(104, f"domain label '{label[:16]}...' exceeds {MAX_LABEL_LEN} chars")
        if not _LABEL.match(label):
            raise SyntaxError_(104, f"illegal domain label '{label}'")

    tld = labels[-1]
    # Punycode TLDs (xn--) are legal; otherwise a TLD must be alphabetic.
    if not (tld.startswith("xn--") or _TLD.match(tld)):
        raise SyntaxError_(104, f"implausible TLD '{tld}'")
    return ascii_domain


def check_syntax(raw: str | None) -> tuple[bool, int, str, str, str, str]:
    """Validate `raw`.

    Returns (ok, code, detail, normalized, local_part, ascii_domain).
    `code` is 0 on success, otherwise one of 100-105.
    """
    normalized = normalize(raw)
    if not normalized:
        return False, 100, "address is empty", "", "", ""
    if len(normalized) > MAX_ADDRESS_LEN:
        return (
            False, 101,
            f"address is {len(normalized)} chars (max {MAX_ADDRESS_LEN})",
            normalized, "", "",
        )
    if "@" not in normalized:
        return False, 102, "no @ sign", normalized, "", ""
    if normalized.count("@") > 1 and not normalized.startswith('"'):
        return False, 102, "more than one @ sign", normalized, "", ""
    if any(c.isspace() for c in normalized):
        return False, 105, "address contains whitespace", normalized, "", ""

    local, _, domain = normalized.rpartition("@")
    try:
        _check_local(local)
        ascii_domain = _check_domain(domain)
    except SyntaxError_ as exc:
        return False, exc.code, exc.detail, normalized, local, ""
    return True, 0, "", normalized, local, ascii_domain
