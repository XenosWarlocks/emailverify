"""Classification: disposable / role / free / relay / typo / canonicalization."""

from __future__ import annotations

import pytest

from emailverify.rules import RuleEngine
from emailverify.rules.classify import (
    canonicalize,
    damerau_levenshtein,
    registrable_provider,
    split_tag,
    suggest_correction,
)


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    return RuleEngine()


class TestFlags:
    def test_disposable_from_sample_data(self, engine: RuleEngine) -> None:
        r = engine.check("fakeha3890@ofags.com")
        assert r.ok
        assert r.flags.disposable

    def test_free_provider(self, engine: RuleEngine) -> None:
        r = engine.check("mufij7114@gmail.com")
        assert r.flags.free_provider
        assert not r.flags.disposable

    def test_relay_provider(self, engine: RuleEngine) -> None:
        # HackerOne forwards these to a hidden real mailbox, so SMTP always
        # says deliverable and tells you nothing useful.
        r = engine.check("h1_analyst_jack@wearehackerone.com")
        assert r.flags.relay_provider

    def test_role_account(self, engine: RuleEngine) -> None:
        assert engine.check("support@akrodlabs.com").flags.role_account
        assert not engine.check("kdanny@akrodlabs.com").flags.role_account

    def test_role_detection_sees_through_plus_tag(self, engine: RuleEngine) -> None:
        r = engine.check("sales+q4@example.com")
        assert r.flags.role_account
        assert r.flags.plus_tagged

    def test_plus_tagged(self, engine: RuleEngine) -> None:
        r = engine.check("anupam936574+11@gmail.com")
        assert r.flags.plus_tagged

    def test_corporate_domain_has_no_flags(self, engine: RuleEngine) -> None:
        r = engine.check("kdanny@akrodlabs.com")
        assert r.flags.as_list() == []


class TestCanonicalize:
    def test_strips_gmail_tag_and_dots(self) -> None:
        assert canonicalize("anupam.936574+11", "gmail.com") == "anupam936574@gmail.com"

    def test_keeps_dots_on_other_providers(self) -> None:
        # Only Gmail ignores dots; stripping them elsewhere would merge two
        # genuinely different mailboxes.
        assert canonicalize("first.last+x", "outlook.com") == "first.last@outlook.com"

    def test_yahoo_uses_hyphen_separator(self) -> None:
        assert canonicalize("base-keyword", "yahoo.com") == "base@yahoo.com"

    def test_leading_separator_is_not_a_tag(self) -> None:
        assert canonicalize("+weird", "gmail.com") == "+weird@gmail.com"

    def test_duplicate_detection(self, engine: RuleEngine) -> None:
        a = engine.check("anupam936574+11@gmail.com")
        b = engine.check("anupam.936574@gmail.com")
        assert a.canonical == b.canonical
        assert a.normalized != b.normalized


def test_split_tag() -> None:
    assert split_tag("user+tag", "gmail.com") == ("user", "tag")
    assert split_tag("user", "gmail.com") == ("user", "")
    assert split_tag("user-tag", "yahoo.com") == ("user", "tag")


class TestTypoDetection:
    @pytest.mark.parametrize(
        "typo,expected",
        [
            ("gmial.com", "gmail.com"),
            ("gmai.com", "gmail.com"),
            ("gmaill.com", "gmail.com"),
            ("hotmial.com", "hotmail.com"),
            ("yaho.com", "yahoo.com"),
            ("outlok.com", "outlook.com"),
        ],
    )
    def test_known_typos(self, typo: str, expected: str) -> None:
        assert suggest_correction(typo) == expected

    def test_edit_distance_one_catches_unlisted_typos(self) -> None:
        assert suggest_correction("gmail.cok") == "gmail.com"

    @pytest.mark.parametrize("good", ["gmail.com", "akrodlabs.com", "wearehackerone.com"])
    def test_no_suggestion_for_fine_domains(self, good: str) -> None:
        assert suggest_correction(good) == ""

    @pytest.mark.parametrize(
        "real_provider",
        [
            "my.com",        # Mail.ru's service, one edit from me.com
            "op.pl",         # real Polish provider, one edit from o2.pl
            "hotmail.ca",
            "outlook.nl",
            "gmx.fr",
        ],
    )
    def test_real_providers_near_popular_domains_are_not_flagged(
        self, engine: RuleEngine, real_provider: str
    ) -> None:
        # These sit one edit from a popular domain and would otherwise get a
        # confident, wrong suggestion. Being listed as free providers is what
        # suppresses it.
        r = engine.check(f"someone@{real_provider}")
        assert r.flags.free_provider
        assert not r.flags.typo_suspect
        assert r.did_you_mean == ""

    def test_engine_sets_flag_and_suggestion(self) -> None:
        r = RuleEngine().check("someone@gmial.com")
        assert r.flags.typo_suspect
        assert r.did_you_mean == "gmail.com"

    def test_distance_two_is_not_suggested(self) -> None:
        # Two edits from a popular domain produces confident-looking wrong
        # answers on legitimate small domains, so it stays out.
        assert suggest_correction("gmwil.cop") == ""


def test_damerau_levenshtein() -> None:
    assert damerau_levenshtein("abc", "abc") == 0
    assert damerau_levenshtein("abc", "abd") == 1
    assert damerau_levenshtein("abc", "acb") == 1       # transposition
    assert damerau_levenshtein("gmail.com", "gmial.com") == 1
    assert damerau_levenshtein("abc", "xyz", cutoff=2) > 2


def test_registrable_provider() -> None:
    assert registrable_provider(["aspmx.l.google.com"]) == "google.com"
    assert registrable_provider(["mx.zoho.eu"]) == "zoho.eu"
    assert registrable_provider(["mail.company.co.uk"]) == "company.co.uk"
    assert registrable_provider([]) == ""


def test_disposable_list_override_is_merged(tmp_path, monkeypatch) -> None:
    from emailverify import datasets
    from emailverify.config import RuleConfig

    datasets.clear_caches()
    extra = tmp_path / "extra.txt"
    extra.write_text("# custom\nmycompetitor-temp.test\n", encoding="utf-8")

    eng = RuleEngine(RuleConfig(disposable_list=extra))
    assert eng.check("a@mycompetitor-temp.test").flags.disposable
    # The bundled seed must survive the merge, not be replaced by it.
    assert eng.check("a@mailinator.com").flags.disposable
    datasets.clear_caches()
