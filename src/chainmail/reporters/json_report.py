"""Machine-readable JSON report."""

from __future__ import annotations

import json
import time

from ..engine import ScanResult


def build_json(result: ScanResult) -> dict:
    return {
        "tool": {"name": "chainmail", "version": result.tool_version},
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "targets": result.targets,
        "summary": {
            "files": len(result.files),
            "contracts": result.contracts,
            "functions": result.functions,
            "lines_of_code": result.lines_of_code,
            "duration_seconds": round(result.duration, 3),
            "detectors_run": len(result.detectors_run),
            "findings": len(result.findings),
            "by_severity": result.counts,
            "risk_score": result.risk_score,
            "suppressed": result.suppressed,
            "baselined": result.baselined,
            "filtered": result.filtered,
        },
        "findings": [f.to_dict() for f in result.findings],
        "parse_errors": [{"file": p, "message": m} for p, m in result.parse_errors],
        "detector_errors": [{"detector": e.detector, "message": e.message} for e in result.detector_errors],
        "files": result.files,
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(build_json(result), indent=2, ensure_ascii=False) + "\n"
