"""Self-contained HTML report (single file, no external assets)."""

from __future__ import annotations

import re
import time
from importlib import resources

from jinja2 import Environment, select_autoescape
from markupsafe import Markup, escape

from ..engine import ScanResult
from .markdown import finding_ids

_CODE_RE = re.compile(r"`([^`]+)`")


def _inline_code(text: str) -> Markup:
    """Escape text, then turn `backticks` into <code> spans."""
    return Markup(_CODE_RE.sub(lambda m: f"<code>{m.group(1)}</code>", str(escape(text))))


def _template_source() -> str:
    return resources.files("chainmail").joinpath("templates/report.html.j2").read_text(encoding="utf-8")


def render_html(result: ScanResult) -> str:
    env = Environment(autoescape=select_autoescape(default=True, default_for_string=True), trim_blocks=True, lstrip_blocks=True)
    env.filters["code"] = _inline_code
    template = env.from_string(_template_source())
    ids = finding_ids(result.findings)
    findings = [dict(f.to_dict(), id=ids[id(f)]) for f in result.findings]
    by_detector: dict[str, int] = {}
    for f in result.findings:
        by_detector[f.detector] = by_detector.get(f.detector, 0) + 1
    return template.render(
        result=result,
        findings=findings,
        counts=result.counts,
        top_detectors=sorted(by_detector.items(), key=lambda kv: -kv[1])[:8],
        generated=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
    )
