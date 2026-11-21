"""Report renderers."""

from __future__ import annotations

from collections.abc import Callable

from ..engine import ScanResult
from .console import render_console
from .html import render_html
from .json_report import render_json
from .markdown import render_markdown
from .sarif import render_sarif

Renderer = Callable[[ScanResult], str]

RENDERERS: dict[str, Renderer] = {
    "json": render_json,
    "markdown": render_markdown,
    "md": render_markdown,
    "html": render_html,
    "sarif": render_sarif,
}

EXTENSIONS = {".json": "json", ".md": "markdown", ".markdown": "markdown", ".html": "html", ".htm": "html", ".sarif": "sarif"}

__all__ = ["RENDERERS", "EXTENSIONS", "render_console", "render_json", "render_markdown", "render_html", "render_sarif"]
