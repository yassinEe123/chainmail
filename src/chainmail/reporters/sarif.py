"""SARIF 2.1.0 output for GitHub Code Scanning and IDE integrations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..detectors import all_detectors
from ..engine import ScanResult
from ..findings import Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
    Severity.GAS: "note",
}
# GitHub uses `security-severity` (0.0-10.0) to bucket security alerts.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
    Severity.GAS: "0.5",
}


def _uri(path: str) -> str:
    p = Path(path)
    try:
        return p.resolve().relative_to(Path.cwd()).as_posix()
    except ValueError:
        return p.as_posix()


def render_sarif(result: ScanResult) -> str:
    detectors = all_detectors()
    used = sorted({f.detector for f in result.findings})
    rule_index = {rid: i for i, rid in enumerate(used)}
    rules: list[dict[str, Any]] = []
    for rid in used:
        cls = detectors.get(rid)
        if cls is None:
            rules.append({"id": rid})
            continue
        tags = ["security", cls.category]
        if cls.swc:
            tags.append(cls.swc)
        if cls.cwe:
            tags.append(f"external/cwe/{cls.cwe.lower()}")
        rules.append(
            {
                "id": rid,
                "name": "".join(part.capitalize() for part in rid.split("-")),
                "shortDescription": {"text": cls.title},
                "fullDescription": {"text": cls.description},
                "help": {"text": cls.recommendation, "markdown": cls.recommendation},
                "helpUri": cls.references[0] if cls.references else "https://github.com/yassinEe123/chainmail#detectors",
                "defaultConfiguration": {"level": LEVEL[cls.severity]},
                "properties": {
                    "tags": tags,
                    "precision": {"high": "high", "medium": "medium", "low": "low"}[cls.confidence.value],
                    "security-severity": SECURITY_SEVERITY[cls.severity],
                },
            }
        )

    results: list[dict[str, Any]] = []
    for f in result.findings:
        region: dict[str, Any] = {"startLine": f.location.line, "startColumn": max(1, f.location.column)}
        if f.location.end_line and f.location.end_line >= f.location.line:
            region["endLine"] = f.location.end_line
        if f.snippet:
            region["snippet"] = {"text": f.snippet}
        entry: dict[str, Any] = {
            "ruleId": f.detector,
            "ruleIndex": rule_index[f.detector],
            "level": LEVEL[f.severity],
            "message": {"text": f.description},
            "locations": [
                {
                    "physicalLocation": {"artifactLocation": {"uri": _uri(f.location.file)}, "region": region},
                    "logicalLocations": [
                        {
                            "name": f.location.function or f.location.contract or "",
                            "fullyQualifiedName": ".".join(filter(None, [f.location.contract, f.location.function])),
                            "kind": "function" if f.location.function else "type",
                        }
                    ]
                    if f.location.contract
                    else [],
                }
            ],
            "partialFingerprints": {"chainmail/v1": f.fingerprint},
            "properties": {
                "confidence": f.confidence.value,
                "severity": f.severity.value,
                "security-severity": SECURITY_SEVERITY[f.severity],
            },
        }
        if f.related:
            entry["relatedLocations"] = [
                {"id": i, "physicalLocation": {"artifactLocation": {"uri": _uri(r.file)}, "region": {"startLine": r.line}}}
                for i, r in enumerate(f.related)
            ]
        results.append(entry)

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Chainmail",
                        "version": result.tool_version,
                        "informationUri": "https://github.com/yassinEe123/chainmail",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not result.detector_errors,
                        "toolExecutionNotifications": [
                            {"level": "error", "message": {"text": f"{e.detector}: {e.message}"}} for e in result.detector_errors
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2) + "\n"
