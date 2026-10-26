"""Loading of the bundled (and user-supplied) reference lists.

Every list is cached after first read, so loading is cheap to call per-row.
All lookups are lowercase; blank lines and `#` comments are ignored.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from pathlib import Path

_PKG = "emailverify.resources"


def _parse_lines(text: str) -> list[str]:
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line.lower())
    return out


def _read_bundled(name: str) -> str:
    return resources.files(_PKG).joinpath(name).read_text(encoding="utf-8")


@lru_cache(maxsize=None)
def _bundled_set(name: str) -> frozenset[str]:
    return frozenset(_parse_lines(_read_bundled(name)))


@lru_cache(maxsize=None)
def _file_set(path: str) -> frozenset[str]:
    return frozenset(_parse_lines(Path(path).read_text(encoding="utf-8")))


def load_set(name: str, override: str | Path | None = None) -> frozenset[str]:
    """Load a bundled domain list, optionally merging a user-supplied file.

    The override is *merged*, not substituted: a 100k-entry community list and
    the curated seed both contribute, so updating one never silently loses the
    other's coverage.
    """
    base = _bundled_set(name)
    if override is None:
        return base
    return base | _file_set(str(Path(override).expanduser().resolve()))


def disposable_domains(override: str | Path | None = None) -> frozenset[str]:
    return load_set("disposable_domains.txt", override)


def free_providers(override: str | Path | None = None) -> frozenset[str]:
    return load_set("free_providers.txt", override)


def relay_providers(override: str | Path | None = None) -> frozenset[str]:
    return load_set("relay_providers.txt", override)


def role_accounts(override: str | Path | None = None) -> frozenset[str]:
    return load_set("role_accounts.txt", override)


def popular_domains(override: str | Path | None = None) -> frozenset[str]:
    return load_set("popular_domains.txt", override)


@lru_cache(maxsize=None)
def domain_typos() -> dict[str, str]:
    """Explicit typo -> correction map."""
    table: dict[str, str] = {}
    for line in _read_bundled("domain_typos.txt").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            table[parts[0].lower()] = parts[1].lower()
    return table


def clear_caches() -> None:
    """Drop cached lists. Used by tests that swap in fixture files."""
    _bundled_set.cache_clear()
    _file_set.cache_clear()
    domain_typos.cache_clear()
