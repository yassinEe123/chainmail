"""Finding model shared by detectors, the engine and reporters."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    GAS = "gas"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank >= other.rank

    __hash__ = str.__hash__

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.lower())
        except ValueError as exc:
            raise ValueError(f"unknown severity {value!r} (choose from {', '.join(s.value for s in cls)})") from exc


# Higher rank == more severe.
_SEVERITY_RANK = {
    Severity.GAS: 0,
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank >= other.rank

    __hash__ = str.__hash__


@dataclass(slots=True)
class Location:
    file: str
    line: int
    column: int = 1
    end_line: int | None = None
    contract: str | None = None
    function: str | None = None

    def __str__(self) -> str:
        return f"{self.file}:{self.line}:{self.column}"


@dataclass
class Finding:
    detector: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    location: Location
    recommendation: str = ""
    swc: str | None = None
    cwe: str | None = None
    snippet: str = ""
    related: list[Location] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable ID that survives unrelated edits (used for baselines).

        Built from the detector, file, contract, function and the normalised
        snippet rather than line numbers, so findings keep the same ID when
        code above them moves.
        """
        normalised = " ".join(self.snippet.split())
        material = "|".join(
            [
                self.detector,
                self.location.file.replace("\\", "/"),
                self.location.contract or "",
                self.location.function or "",
                normalised,
            ]
        )
        return hashlib.sha256(material.encode()).hexdigest()[:16]

    @property
    def sort_key(self) -> tuple:
        return (-self.severity.rank, -self.confidence.rank, self.location.file, self.location.line, self.detector)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["confidence"] = self.confidence.value
        data["fingerprint"] = self.fingerprint
        return data
