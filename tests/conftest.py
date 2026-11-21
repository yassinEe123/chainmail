from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from chainmail.config import Config
from chainmail.engine import Scanner
from chainmail.findings import Finding

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "contracts"


def scan(source: str, detector: str | None = None, path: str = "Test.sol", **config) -> list[Finding]:
    cfg = Config(**config)
    if detector:
        cfg.include_detectors = [detector]
    result = Scanner(cfg).scan_source(textwrap.dedent(source), path)
    assert not result.detector_errors, result.detector_errors
    return result.findings


def ids(findings: list[Finding]) -> list[str]:
    return [f.detector for f in findings]


@pytest.fixture
def examples() -> Path:
    return EXAMPLES
