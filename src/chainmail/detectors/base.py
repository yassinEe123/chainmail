"""Detector base class and registry."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import ClassVar

from ..core import ast as A
from ..core.analysis import AnalysisCache, FunctionAnalysis
from ..core.project import ContractInfo, Project, SourceFile
from ..findings import Confidence, Finding, Location, Severity


@dataclass
class DetectorContext:
    project: Project
    cache: AnalysisCache

    def analyze(self, fn: A.FunctionDef, info: ContractInfo) -> FunctionAnalysis:
        return self.cache.get(fn, info)


class Detector:
    """Base class for every Chainmail detector.

    Subclasses declare metadata as class attributes and implement either
    :meth:`check_contract` (called once per contract), :meth:`check_file`
    (called once per source file) or override :meth:`run` entirely.
    """

    id: ClassVar[str] = ""
    title: ClassVar[str] = ""
    description: ClassVar[str] = ""
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    swc: ClassVar[str | None] = None
    cwe: ClassVar[str | None] = None
    recommendation: ClassVar[str] = ""
    references: ClassVar[tuple[str, ...]] = ()
    category: ClassVar[str] = "security"
    # Detectors with a non-empty example are self-documented by `chainmail explain`.
    example: ClassVar[str] = ""

    def __init__(self, ctx: DetectorContext) -> None:
        self.ctx = ctx
        self._findings: list[Finding] = []

    # Hooks ----------------------------------------------------------------
    def run(self) -> list[Finding]:
        for sf in self.ctx.project.files:
            self.check_file(sf)
        for info in self.ctx.project.iter_contracts():
            if info.kind == "interface":
                continue
            self.check_contract(info)
        return self._findings

    def check_file(self, sf: SourceFile) -> None:  # pragma: no cover - default no-op
        pass

    def check_contract(self, info: ContractInfo) -> None:  # pragma: no cover - default no-op
        pass

    # Helpers --------------------------------------------------------------
    def analyze(self, fn: A.FunctionDef, info: ContractInfo) -> FunctionAnalysis:
        return self.ctx.analyze(fn, info)

    @staticmethod
    def own_functions(info: ContractInfo, include_modifiers: bool = False) -> Iterator[A.FunctionDef]:
        """Functions *declared* in this contract that have a body."""
        items: Iterable[A.FunctionDef] = info.contract.functions
        if include_modifiers:
            items = list(items) + list(info.contract.modifiers)
        for fn in items:
            if fn.body is not None:
                yield fn

    def report(
        self,
        sf: SourceFile,
        node: A.Node | A.Loc | int,
        message: str,
        *,
        contract: str | None = None,
        function: A.FunctionDef | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        title: str | None = None,
        recommendation: str | None = None,
        related: list[A.Node] | None = None,
        metadata: dict | None = None,
    ) -> Finding:
        if isinstance(node, int):
            line, col, end = node, 1, node
        else:
            loc = node if isinstance(node, A.Loc) else node.loc
            line, col, end = loc.line, loc.col, max(loc.end_line, loc.line)
        fn_name = None
        if function is not None:
            fn_name = function.name or function.kind
        location = Location(sf.path, line, col, end, contract, fn_name)
        snippet = _snippet(sf, line)
        rel = []
        for r in related or []:
            rel.append(Location(sf.path, r.loc.line, r.loc.col, r.loc.end_line or r.loc.line, contract, fn_name))
        finding = Finding(
            detector=self.id,
            title=title or self.title,
            severity=severity or self.severity,
            confidence=confidence or self.confidence,
            description=message,
            location=location,
            recommendation=recommendation or self.recommendation,
            swc=self.swc,
            cwe=self.cwe,
            snippet=snippet,
            related=rel,
            references=list(self.references),
            metadata=metadata or {},
        )
        self._findings.append(finding)
        return finding

    @classmethod
    def info(cls) -> dict:
        return {
            "id": cls.id,
            "title": cls.title,
            "severity": cls.severity.value,
            "confidence": cls.confidence.value,
            "swc": cls.swc,
            "cwe": cls.cwe,
            "category": cls.category,
            "description": cls.description,
            "recommendation": cls.recommendation,
            "references": list(cls.references),
        }


def _snippet(sf: SourceFile, line: int) -> str:
    lines = sf.lines
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()
    return ""


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, type[Detector]] = {}


def register(cls: type[Detector]) -> type[Detector]:
    if not cls.id:
        raise ValueError(f"{cls.__name__} has no id")
    if cls.id in _REGISTRY and _REGISTRY[cls.id] is not cls:
        raise ValueError(f"duplicate detector id {cls.id!r}")
    _REGISTRY[cls.id] = cls
    return cls


def all_detectors() -> dict[str, type[Detector]]:
    from . import load_builtin_detectors

    load_builtin_detectors()
    return dict(sorted(_REGISTRY.items()))


def get_detector(detector_id: str) -> type[Detector]:
    detectors = all_detectors()
    if detector_id not in detectors:
        raise KeyError(detector_id)
    return detectors[detector_id]
