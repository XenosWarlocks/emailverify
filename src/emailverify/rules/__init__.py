"""Stage 1: rule-based verification. Pure functions, no network, no I/O."""

from emailverify.rules.engine import RuleEngine
from emailverify.rules.syntax import check_syntax, normalize
from emailverify.rules.classify import canonicalize, suggest_correction

__all__ = ["RuleEngine", "check_syntax", "normalize", "canonicalize", "suggest_correction"]
