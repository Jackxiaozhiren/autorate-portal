"""Section 11's Localization row: one message catalog, two languages.

A6 (PRD section 12.3) fixes the second language as Simplified Chinese
(``zh-Hans``). Three rules here are not cosmetic:

* **No string concatenation for numbers.** Every number reaches the page
  through a catalog template (``fmt.number_with_unit``), so a locale can move
  the unit without the value being reformatted or a digit being glued to a
  word. The digits themselves are the artefact's own text, never recomputed.
* **Unit words are translated.** ``case`` and ``record`` are different
  denominators; a mistranslated unit is a wrong claim (section 11). An unknown
  unit is returned unchanged and marked untranslated rather than guessed.
* **Closed vocabularies stay closed.** F4's three verdicts and F8's four badge
  states are machine values fixed by the PRD; the catalog carries them
  identically in both languages so a translated screen cannot invent a fifth.

A missing key or locale raises. Falling back to English would hide an
incomplete catalog, which the completeness test exists to catch.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CATALOG_PATH = Path(__file__).with_name("catalog.json")
LANGUAGES = ("en", "zh-Hans")
DEFAULT_LOCALE = "en"
UNIT_KEYS = ("case", "record")


class CatalogError(KeyError):
    """The catalog is incomplete, or a caller asked for a key it does not have."""


def _load() -> dict[str, dict[str, str]]:
    with CATALOG_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


CATALOG = _load()


def locale_or_raise(locale: str) -> str:
    if locale not in LANGUAGES:
        raise CatalogError("unknown locale: %r (languages: %s)" % (locale, ", ".join(LANGUAGES)))
    return locale


def t(locale: str, key: str, **kwargs: Any) -> str:
    """One message, formatted from a template. No numeric concatenation."""
    table = CATALOG[locale_or_raise(locale)]
    if key not in table:
        raise CatalogError("catalog key %r is missing in locale %r" % (key, locale))
    template = table[key]
    if not kwargs:
        return template
    return template.format(**kwargs)


def keys(locale: str) -> frozenset[str]:
    return frozenset(CATALOG[locale_or_raise(locale)])


def assert_complete() -> None:
    """Section 11 acceptance: the two key sets are equal, and both are loaded."""
    missing_languages = [language for language in LANGUAGES if language not in CATALOG]
    if missing_languages:
        raise CatalogError("catalog is missing languages: %s" % ", ".join(missing_languages))
    baseline = keys(DEFAULT_LOCALE)
    for language in LANGUAGES:
        if keys(language) != baseline:
            only_here = sorted(keys(language) - baseline)
            only_there = sorted(baseline - keys(language))
            raise CatalogError("catalog mismatch in %r: extra=%s missing=%s"
                               % (language, only_here, only_there))
    for unit in UNIT_KEYS:
        for language in LANGUAGES:
            if "unit.%s" % unit not in CATALOG[language]:
                raise CatalogError("unit %r has no translation in %r" % (unit, language))


def unit_word(locale: str, unit: str) -> tuple[str, bool]:
    """(display word, translated?). An unlisted unit is never guessed at."""
    key = "unit.%s" % str(unit)
    table = CATALOG[locale_or_raise(locale)]
    if key in table:
        return table[key], True
    return str(unit), False


def number_with_unit(locale: str, value: Any, unit: Any) -> str:
    """A published value plus a translated unit, through one catalog template."""
    word, _translated = unit_word(locale, unit)
    return t(locale, "fmt.number_with_unit", value=value, unit=word)


def state_word(locale: str, state: str) -> str:
    """F2/I3 render states; the artefact's refusal *reason* is not translated."""
    mapping = {"certified": "state.certified", "refusal": "state.refusal",
               "unavailable": "state.unavailable"}
    if state not in mapping:
        raise CatalogError("unknown render state: %r" % state)
    return t(locale, mapping[state])
