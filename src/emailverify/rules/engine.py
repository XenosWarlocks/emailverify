"""Stage 1 entry point: syntax check + classification in one call."""

from __future__ import annotations

from emailverify import datasets
from emailverify.config import RuleConfig
from emailverify.models import Flags, RuleResult
from emailverify.rules import classify, syntax


class RuleEngine:
    """Rule-based verifier. Stateless per call; loads its lists once."""

    def __init__(self, cfg: RuleConfig | None = None) -> None:
        self.cfg = cfg or RuleConfig()
        self.disposable = datasets.disposable_domains(self.cfg.disposable_list)
        self.free = datasets.free_providers(self.cfg.free_list)
        self.relay = datasets.relay_providers(self.cfg.relay_list)
        self.roles = datasets.role_accounts(self.cfg.role_list)
        self.popular = datasets.popular_domains()

    def check(self, raw: str | None) -> RuleResult:
        ok, code, detail, normalized, local, ascii_domain = syntax.check_syntax(raw)
        if not ok:
            return RuleResult(
                raw=str(raw or ""),
                ok=False,
                code=code,
                normalized=normalized,
                local_part=local,
                detail=detail,
            )

        # The display domain keeps any unicode the user typed; ascii_domain is
        # what we hand to the resolver and to the API.
        display_domain = normalized.rpartition("@")[2]
        base, tag = classify.split_tag(local, ascii_domain)

        flags = Flags(
            disposable=ascii_domain in self.disposable,
            role_account=base.lower() in self.roles,
            free_provider=ascii_domain in self.free,
            relay_provider=ascii_domain in self.relay,
            plus_tagged=bool(tag),
            non_ascii=display_domain != ascii_domain or not local.isascii(),
        )

        did_you_mean = ""
        if self.cfg.detect_typos and not flags.free_provider:
            # Skip the suggestion for addresses already on a known-good free
            # provider -- gmail.com is in the popular list, so a hit there is
            # noise by definition.
            suggestion = classify.suggest_correction(ascii_domain, self.popular)
            if suggestion and suggestion != ascii_domain:
                did_you_mean = suggestion
                flags.typo_suspect = True

        return RuleResult(
            raw=str(raw or ""),
            ok=True,
            code=0,
            normalized=normalized,
            local_part=local,
            domain=display_domain,
            ascii_domain=ascii_domain,
            canonical=classify.canonicalize(local, ascii_domain),
            did_you_mean=did_you_mean,
            flags=flags,
        )
