"""Solidity version-pragma handling.

Understands the npm-semver-like syntax used by ``pragma solidity``:
``^0.8.0``, ``>=0.6.0 <0.9.0``, ``~0.5.2``, ``0.8.19``, ``>=0.4.22 || ^0.8``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")
_CONSTRAINT_RE = re.compile(r"(\^|~|>=|<=|>|<|=)?\s*v?(\d+(?:\.\d+){0,2})")


@total_ordering
@dataclass(frozen=True, slots=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, text: str) -> Version:
        match = _VERSION_RE.search(text)
        if not match:
            raise ValueError(f"invalid version: {text!r}")
        major, minor, patch = (int(g) if g is not None else 0 for g in match.groups())
        return cls(major, minor, patch)

    def _key(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() < other._key()

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


V0_4_22 = Version(0, 4, 22)
V0_5_0 = Version(0, 5, 0)
V0_6_0 = Version(0, 6, 0)
V0_7_0 = Version(0, 7, 0)
V0_8_0 = Version(0, 8, 0)

# Releases considered current enough at the time of writing. Anything older
# than ``RECOMMENDED_MIN`` is reported as outdated.
RECOMMENDED_MIN = Version(0, 8, 20)
LATEST_KNOWN = Version(0, 8, 30)


@dataclass(frozen=True, slots=True)
class VersionRange:
    """A (possibly unbounded) half-open interval [low, high)."""

    low: Version
    high: Version | None
    raw: str

    @property
    def is_floating(self) -> bool:
        return self.high is None or self.high != _bump_patch(self.low)

    @property
    def min_version(self) -> Version:
        return self.low

    def allows(self, version: Version) -> bool:
        if version < self.low:
            return False
        return self.high is None or version < self.high

    def allows_below(self, version: Version) -> bool:
        """True if *some* version strictly lower than ``version`` is allowed."""
        return self.low < version


def _bump_patch(v: Version) -> Version:
    return Version(v.major, v.minor, v.patch + 1)


def _caret_upper(v: Version, parts: int) -> Version:
    if v.major > 0:
        return Version(v.major + 1, 0, 0)
    if v.minor > 0 or parts < 3:
        return Version(0, v.minor + 1, 0)
    return Version(0, 0, v.patch + 1)


def parse_pragma(text: str) -> VersionRange | None:
    """Parse a ``pragma solidity`` value into the *widest* allowed range.

    For disjunctions (``a || b``) the union's lowest bound and highest upper
    bound are kept - good enough for "could this compile with an old solc?".
    """
    alternatives = [alt.strip() for alt in text.split("||") if alt.strip()]
    ranges = [r for r in (_parse_conjunction(alt, text) for alt in alternatives) if r]
    if not ranges:
        return None
    low = min(r.low for r in ranges)
    highs = [r.high for r in ranges]
    high = None if any(h is None for h in highs) else max(h for h in highs if h)
    return VersionRange(low, high, text)


def _parse_conjunction(text: str, raw: str) -> VersionRange | None:
    low: Version | None = None
    high: Version | None = None
    # Hyphen ranges: "0.5.0 - 0.6.0"
    hyphen = re.match(r"^\s*(\S+)\s+-\s+(\S+)\s*$", text)
    if hyphen:
        return VersionRange(Version.parse(hyphen.group(1)), _bump_patch(Version.parse(hyphen.group(2))), raw)

    for op, ver_text in _CONSTRAINT_RE.findall(text):
        parts = ver_text.count(".") + 1
        v = Version.parse(ver_text)
        if op == "^":
            lo, hi = v, _caret_upper(v, parts)
        elif op == "~":
            lo, hi = v, Version(v.major, v.minor + 1, 0) if parts >= 2 else Version(v.major + 1, 0, 0)
        elif op == ">=":
            lo, hi = v, None
        elif op == ">":
            lo, hi = _bump_patch(v), None
        elif op == "<":
            lo, hi = Version(0, 0, 0), v
        elif op == "<=":
            lo, hi = Version(0, 0, 0), _bump_patch(v)
        else:  # exact
            lo, hi = v, _bump_patch(v)
        low = lo if low is None else max(low, lo)
        if hi is not None:
            high = hi if high is None else min(high, hi)
    if low is None:
        return None
    return VersionRange(low, high, raw)
