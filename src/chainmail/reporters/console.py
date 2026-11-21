"""Human-friendly terminal output (ANSI colours, no third-party dependency)."""

from __future__ import annotations

import os
import sys
import textwrap
from typing import TextIO

from ..engine import ScanResult
from ..findings import Finding, Severity

COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m",
    Severity.INFO: "\033[1;34m",
    Severity.GAS: "\033[1;35m",
}
RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
GREEN = "\033[1;32m"


def supports_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.enabled else text


def render_console(result: ScanResult, color: bool | None = None, verbose: bool = False, stream: TextIO = sys.stdout) -> str:
    style = _Style(supports_color(stream) if color is None else color)
    out: list[str] = []
    width = 88

    out.append(style(BOLD, "Chainmail") + style(DIM, f" v{result.tool_version} - smart contract audit"))
    out.append(style(DIM, "─" * width))

    for finding in result.findings:
        out.extend(_render_finding(finding, style, verbose, width))

    if result.parse_errors:
        out.append(style(BOLD, f"Parser warnings ({len(result.parse_errors)})"))
        for path, err in result.parse_errors[:20]:
            out.append(style(DIM, f"  {path}:{err}"))
        if len(result.parse_errors) > 20:
            out.append(style(DIM, f"  ... {len(result.parse_errors) - 20} more"))
        out.append("")
    for derr in result.detector_errors:
        out.append(style(COLORS[Severity.HIGH], f"Detector '{derr.detector}' crashed: {derr.message}"))

    out.append(style(DIM, "─" * width))
    counts = result.counts
    summary = "  ".join(style(COLORS[Severity(sev)], f"{sev.upper()} {n}") if n else style(DIM, f"{sev} 0") for sev, n in counts.items())
    out.append(f"{style(BOLD, 'Summary')}  {summary}")
    details = (
        f"{len(result.files)} file(s), {result.contracts} contract(s), {result.functions} function(s), "
        f"{result.lines_of_code} LoC · {len(result.detectors_run)} detectors · {result.duration:.2f}s"
    )
    out.append(style(DIM, details))
    hidden = []
    if result.suppressed:
        hidden.append(f"{result.suppressed} suppressed inline")
    if result.baselined:
        hidden.append(f"{result.baselined} in baseline")
    if result.filtered:
        hidden.append(f"{result.filtered} below thresholds")
    if hidden:
        out.append(style(DIM, "Hidden: " + ", ".join(hidden)))
    if not result.findings:
        out.append(style(GREEN, "✓ No issues found."))
    else:
        out.append(style(DIM, f"Risk score: {result.risk_score}/100"))
    return "\n".join(out) + "\n"


def _render_finding(f: Finding, style: _Style, verbose: bool, width: int) -> list[str]:
    badge = style(COLORS[f.severity], f" {f.severity.value.upper()} ")
    tags = [f.detector]
    if f.swc:
        tags.append(f.swc)
    tags.append(f"confidence: {f.confidence.value}")
    lines = [f"{badge} {style(BOLD, f.title)}  {style(DIM, '[' + ' · '.join(tags) + ']')}"]
    where = str(f.location)
    if f.location.contract:
        where += f"  ({f.location.contract}" + (f".{f.location.function}" if f.location.function else "") + ")"
    lines.append(f"  {style(DIM, '→')} {where}")
    if f.snippet:
        lines.append(f"  {style(DIM, f'{f.location.line:>4} │')} {f.snippet[: width - 10]}")
    for chunk in textwrap.wrap(f.description, width - 4):
        lines.append(f"    {chunk}")
    if verbose and f.recommendation:
        lines.append(style(DIM, "    Fix:"))
        for chunk in textwrap.wrap(f.recommendation, width - 6):
            lines.append(f"      {chunk}")
    lines.append("")
    return lines
