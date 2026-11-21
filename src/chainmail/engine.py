"""Scan orchestration: file discovery, detector execution, filtering."""

from __future__ import annotations

import json
import re
import time
import traceback
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .config import Config
from .core.analysis import AnalysisCache
from .core.project import Project, SourceFile
from .detectors import DetectorContext, all_detectors
from .findings import Finding, Severity

SUPPRESS_RE = re.compile(
    r"(?:chainmail|slither)-(disable-next-line|disable-line|disable|enable)\b\s*:?\s*([\w\-*, ]*)",
)


@dataclass
class DetectorError:
    detector: str
    message: str
    trace: str


@dataclass
class ScanResult:
    findings: list[Finding]
    files: list[str]
    contracts: int
    functions: int
    lines_of_code: int
    parse_errors: list[tuple[str, str]]
    detector_errors: list[DetectorError]
    detectors_run: list[str]
    suppressed: int = 0
    baselined: int = 0
    filtered: int = 0
    duration: float = 0.0
    tool_version: str = __version__
    targets: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        counter = Counter(f.severity.value for f in self.findings)
        return {sev.value: counter.get(sev.value, 0) for sev in sorted(Severity, reverse=True)}

    def highest_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def should_fail(self, threshold: Severity | None) -> bool:
        if threshold is None:
            return False
        return any(f.severity >= threshold for f in self.findings)

    @property
    def risk_score(self) -> int:
        """0 (clean) .. 100 (critical issues) - a coarse summary for dashboards."""
        weights = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 7, Severity.LOW: 2, Severity.INFO: 0, Severity.GAS: 0}
        conf = {"high": 1.0, "medium": 0.7, "low": 0.4}
        score = sum(weights[f.severity] * conf[f.confidence.value] for f in self.findings)
        return min(100, round(score))


# ---------------------------------------------------------------------------
# Suppressions
# ---------------------------------------------------------------------------


@dataclass
class _Suppressions:
    lines: dict[int, set[str]] = field(default_factory=dict)  # line -> ids ("*" = all)
    ranges: list[tuple[int, int, set[str]]] = field(default_factory=list)

    def matches(self, finding: Finding) -> bool:
        line = finding.location.line
        ids = self.lines.get(line)
        if ids and ("*" in ids or finding.detector in ids):
            return True
        return any(start <= line <= end and ("*" in ids or finding.detector in ids) for start, end, ids in self.ranges)


def parse_suppressions(sf: SourceFile) -> _Suppressions:
    sup = _Suppressions()
    open_ranges: dict[str, int] = {}
    total_lines = len(sf.lines) + 1
    for comment in sf.comments:
        for match in SUPPRESS_RE.finditer(comment.text):
            action, raw_ids = match.groups()
            ids = {i.strip() for i in raw_ids.replace(",", " ").split() if i.strip()} or {"*"}
            if action == "disable-next-line":
                sup.lines.setdefault(comment.end_line + 1, set()).update(ids)
            elif action == "disable-line":
                sup.lines.setdefault(comment.line, set()).update(ids)
            elif action == "disable":
                for i in ids:
                    open_ranges.setdefault(i, comment.line)
            elif action == "enable":
                for i in ids if ids != {"*"} else set(open_ranges):
                    start = open_ranges.pop(i, None)
                    if start is not None:
                        sup.ranges.append((start, comment.line, {i}))
    for i, start in open_ranges.items():
        sup.ranges.append((start, total_lines, {i}))
    return sup


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


def load_baseline(path: Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("fingerprints", [])
    return {str(x) for x in data}


def write_baseline(result: ScanResult, path: Path) -> int:
    fingerprints = sorted({f.fingerprint for f in result.findings})
    payload = {
        "tool": "chainmail",
        "version": result.tool_version,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "fingerprints": fingerprints,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return len(fingerprints)


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def collect_files(targets: Sequence[Path | str], config: Config) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()
    for target in targets:
        path = Path(target)
        if path.is_file():
            candidates: Iterable[Path] = [path]
        elif path.is_dir():
            candidates = sorted(p for p in path.rglob("*.sol") if p.is_file())
        else:
            raise FileNotFoundError(f"no such file or directory: {target}")
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            rel = _relative(candidate)
            if not path.is_file() and config.path_excluded(rel):
                continue
            seen.add(resolved)
            files.append(candidate)
    return files


def _relative(path: Path) -> Path:
    try:
        return path.resolve().relative_to(Path.cwd())
    except ValueError:
        return path


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class Scanner:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()

    def enabled_detectors(self):
        return {k: v for k, v in all_detectors().items() if self.config.detector_enabled(k)}

    def scan_paths(self, targets: Sequence[Path | str], baseline: Path | None = None) -> ScanResult:
        files = collect_files(targets, self.config)
        project = Project()
        for f in files:
            project.add_file(f)
        project.link()
        result = self.scan_project(project, baseline=baseline)
        result.targets = [str(t) for t in targets]
        return result

    def scan_source(self, source: str, path: str = "contract.sol") -> ScanResult:
        project = Project.from_sources([(path, source)])
        return self.scan_project(project)

    def scan_project(self, project: Project, baseline: Path | None = None) -> ScanResult:
        started = time.perf_counter()
        ctx = DetectorContext(project, AnalysisCache(project))
        detectors = self.enabled_detectors()
        raw: list[Finding] = []
        errors: list[DetectorError] = []
        for det_id, cls in detectors.items():
            try:
                raw.extend(cls(ctx).run())
            except Exception as exc:  # a buggy detector must not kill the scan
                errors.append(DetectorError(det_id, f"{type(exc).__name__}: {exc}", traceback.format_exc()))

        # Severity overrides
        for f in raw:
            override = self.config.severity_overrides.get(f.detector)
            if override is not None:
                f.severity = override

        # Deduplicate (same detector + location + message)
        unique: dict[tuple, Finding] = {}
        for f in raw:
            key = (f.detector, f.location.file, f.location.line, f.location.column, f.description)
            unique.setdefault(key, f)
        findings = list(unique.values())

        # Inline suppressions
        suppressions = {sf.path: parse_suppressions(sf) for sf in project.files}
        kept: list[Finding] = []
        suppressed = 0
        for f in findings:
            sup = suppressions.get(f.location.file)
            if sup is not None and sup.matches(f):
                suppressed += 1
            else:
                kept.append(f)

        # Baseline
        baselined = 0
        baseline_path = baseline or (Path(self.config.baseline) if self.config.baseline else None)
        if baseline_path is not None and baseline_path.exists():
            known = load_baseline(baseline_path)
            before = len(kept)
            kept = [f for f in kept if f.fingerprint not in known]
            baselined = before - len(kept)

        # Severity / confidence thresholds
        before = len(kept)
        kept = [f for f in kept if f.severity >= self.config.min_severity and f.confidence >= self.config.min_confidence]
        filtered = before - len(kept)

        kept.sort(key=lambda f: f.sort_key)
        contracts = sum(len(sf.unit.contracts) for sf in project.files)
        functions = sum(len(c.functions) + len(c.modifiers) for sf in project.files for c in sf.unit.contracts)
        loc = sum(_count_loc(sf.source) for sf in project.files)
        return ScanResult(
            findings=kept,
            files=[sf.path for sf in project.files],
            contracts=contracts,
            functions=functions,
            lines_of_code=loc,
            parse_errors=[(path, str(err)) for path, err in project.parse_errors],
            detector_errors=errors,
            detectors_run=list(detectors),
            suppressed=suppressed,
            baselined=baselined,
            filtered=filtered,
            duration=time.perf_counter() - started,
        )


def _count_loc(source: str) -> int:
    """Count non-blank, non-comment lines."""
    no_block = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), source, flags=re.S)
    count = 0
    for line in no_block.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("//"):
            count += 1
    return count
