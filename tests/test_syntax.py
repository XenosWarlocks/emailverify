"""Stage 1 syntax rules."""

from __future__ import annotations

import pytest

from emailverify.rules.syntax import check_syntax, normalize


@pytest.mark.parametrize(
    "address",
    [
        "simple@example.com",
        "very.common@example.com",
        "disposable.style.email.with+symbol@example.com",
        "other.email-with-hyphen@example.com",
        "fully-qualified-domain@example.com",
        "user.name+tag+sorting@example.com",
        "x@example.com",
        "example-indeed@strange-example.com",
        "test/test@test.com",
        "mailhost!username@example.org",
        "user%example.com@example.org",
        "a_b-c@sub.domain.co.uk",
        "h1_analyst_jack@wearehackerone.com",
        "anupam936574+11@gmail.com",
        "fakeha3890@ofags.com",
        "name@xn--80ak6aa92e.com",       # punycode domain
        "0123456789@numeric-local.com",
    ],
)
def test_accepts_valid(address: str) -> None:
    ok, code, detail, *_ = check_syntax(address)
    assert ok, f"{address} rejected as {code}: {detail}"


@pytest.mark.parametrize(
    "address,expected_code",
    [
        ("", 100),
        (None, 100),
        ("   ", 100),
        ("plainaddress", 102),
        ("@no-local.com", 102),
        ("two@at@signs.com", 102),
        ("a" * 65 + "@example.com", 103),
        ("user@", 104),
        ("user@nodot", 104),
        ("user@-leadinghyphen.com", 104),
        ("user@trailinghyphen-.com", 104),
        ("user@double..dot.com", 104),
        ("user@192.168.1.1", 104),
        ("user@[192.168.1.1]", 104),
        ("user@domain.123", 104),
        (".leadingdot@example.com", 105),
        ("trailingdot.@example.com", 105),
        ("double..dot@example.com", 105),
        ("has space@example.com", 105),
        ("has(paren)@example.com", 105),
        ("has,comma@example.com", 105),
        ("has:colon@example.com", 105),
    ],
)
def test_rejects_invalid(address, expected_code: int) -> None:
    ok, code, _detail, *_ = check_syntax(address)
    assert not ok
    assert code == expected_code


def test_address_length_cap() -> None:
    # A 64-char local part is legal on its own; pad the domain until the whole
    # address passes 254 so the total-length rule is what fires (code 101),
    # ahead of the per-part checks.
    local = "a" * 64
    domain = ".".join(["b" * 60] * 4) + ".com"   # 64 + 1 + 247 = 312 chars
    ok, code, *_ = check_syntax(f"{local}@{domain}")
    assert not ok
    assert code == 101


class TestNormalize:
    def test_lowercases_domain_only(self) -> None:
        # The local part is case-sensitive per RFC 5321 2.4 -- rewriting it
        # would change the identity of the address we report back.
        assert normalize("John.Doe@EXAMPLE.COM") == "John.Doe@example.com"

    def test_unwraps_display_name(self) -> None:
        assert normalize("Jane Roe <jane@example.com>") == "jane@example.com"

    def test_strips_mailto(self) -> None:
        assert normalize("mailto:bob@example.com") == "bob@example.com"

    def test_strips_whitespace_and_trailing_punctuation(self) -> None:
        assert normalize("  bob@example.com,  ") == "bob@example.com"

    def test_strips_zero_width_characters(self) -> None:
        # A zero-width space pasted from a document makes a valid-looking
        # address resolve to nothing; it must be removed, not preserved.
        assert normalize("bob​@exam​ple.com") == "bob@example.com"

    def test_normalizes_fullwidth_at(self) -> None:
        assert normalize("bob＠example.com") == "bob@example.com"

    def test_strips_trailing_dot_on_domain(self) -> None:
        assert normalize("bob@example.com.") == "bob@example.com"

    def test_handles_none(self) -> None:
        assert normalize(None) == ""


def test_returns_ascii_domain_for_unicode() -> None:
    ok, _code, _detail, _norm, _local, ascii_domain = check_syntax("user@bücher.example")
    assert ok
    assert ascii_domain == "xn--bcher-kva.example"
