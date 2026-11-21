import json

import pytest
from click.testing import CliRunner

from chainmail.cli import main
from chainmail.config import Config
from chainmail.engine import Scanner
from chainmail.reporters import render_console, render_html, render_json, render_markdown, render_sarif


@pytest.fixture(scope="module")
def result():
    from tests.conftest import EXAMPLES

    return Scanner(Config()).scan_paths([EXAMPLES])


def test_json_report(result):
    data = json.loads(render_json(result))
    assert data["tool"]["name"] == "chainmail"
    assert data["summary"]["findings"] == len(result.findings) > 20
    first = data["findings"][0]
    assert {"detector", "severity", "confidence", "location", "fingerprint", "description"} <= set(first)


def test_sarif_report_structure(result):
    sarif = json.loads(render_sarif(result))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert len(rule_ids) == len(set(rule_ids))
    for res in run["results"]:
        assert rule_ids[res["ruleIndex"]] == res["ruleId"]
        assert res["level"] in {"error", "warning", "note"}
        region = res["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        assert "chainmail/v1" in res["partialFingerprints"]
    assert all("security-severity" in r["properties"] for r in rules)


def test_markdown_and_html(result):
    md = render_markdown(result)
    assert md.startswith("# Smart Contract Audit Report")
    assert "## Findings overview" in md and "### C-01" in md
    html = render_html(result)
    assert html.lstrip().startswith("<!DOCTYPE html>")
    assert html.count('class="finding ') == len(result.findings)
    assert "<script>" in html and "Chainmail v" in html


def test_html_escapes_source(tmp_path):
    src = (
        'pragma solidity 0.8.24; contract C { function f() external { require(tx.origin == address(0x1), "<script>alert(1)</script>"); } }'
    )
    res = Scanner(Config()).scan_source(src, "C.sol")
    assert "<script>alert(1)</script>" not in render_html(res)


def test_console_report(result):
    out = render_console(result, color=False, verbose=True)
    assert "Summary" in out and "Fix:" in out and "\x1b[" not in out
    colored = render_console(result, color=True)
    assert "\x1b[" in colored


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def invoke(*args):
    return CliRunner().invoke(main, list(args), catch_exceptions=False)


def test_cli_scan_exit_codes(examples):
    r = invoke("scan", str(examples / "SafeVault.sol"), "--no-color")
    assert r.exit_code == 0, r.output
    assert "No issues found" in r.output or "Summary" in r.output
    r = invoke("scan", str(examples / "ReentrancyVault.sol"), "--no-color")
    assert r.exit_code == 1
    r = invoke("scan", str(examples / "ReentrancyVault.sol"), "--fail-on", "none", "-q")
    assert r.exit_code == 0 and r.output == ""


def test_cli_formats_and_outputs(examples, tmp_path):
    r = invoke("scan", str(examples), "-f", "json", "--fail-on", "none")
    data = json.loads(r.output)
    assert data["summary"]["files"] == 7
    outs = [tmp_path / n for n in ("r.json", "r.md", "r.html", "r.sarif")]
    args = ["scan", str(examples), "-q", "--fail-on", "none"]
    for o in outs:
        args += ["-o", str(o)]
    r = CliRunner().invoke(main, args)
    assert r.exit_code == 0
    assert all(o.exists() and o.stat().st_size > 1000 for o in outs)


def test_cli_detector_filters(examples):
    r = invoke("scan", str(examples), "-d", "weak-prng", "-f", "json", "--fail-on", "none")
    assert {f["detector"] for f in json.loads(r.output)["findings"]} == {"weak-prng"}
    r = CliRunner().invoke(main, ["scan", str(examples), "-d", "does-not-exist"])
    assert r.exit_code == 2 and "unknown detector" in r.output


def test_cli_baseline(examples, tmp_path):
    base = tmp_path / "b.json"
    r = CliRunner().invoke(main, ["scan", str(examples / "Lottery.sol"), "-q", "--write-baseline", str(base)])
    assert base.exists()
    r = invoke("scan", str(examples / "Lottery.sol"), "--baseline", str(base), "--no-color")
    assert r.exit_code == 0 and "in baseline" in r.output


def test_cli_detectors_explain_init(tmp_path, monkeypatch):
    r = invoke("detectors")
    assert "reentrancy-eth" in r.output and "detectors" in r.output
    r = invoke("detectors", "--json")
    assert len(json.loads(r.output)) >= 50
    r = invoke("detectors", "--markdown")
    assert r.output.startswith("| ID |")
    r = invoke("explain", "reentrancy-eth")
    assert "Checks-Effects-Interactions" in r.output and "Example:" in r.output
    assert CliRunner().invoke(main, ["explain", "nope"]).exit_code == 2
    monkeypatch.chdir(tmp_path)
    assert invoke("init").exit_code == 0 and (tmp_path / "chainmail.yml").exists()
    assert CliRunner().invoke(main, ["init"]).exit_code == 2
    assert Config.load(tmp_path / "chainmail.yml").exclude_detectors == ["assembly-usage"]


def test_cli_outline_and_callgraph(examples):
    r = invoke("outline", str(examples / "UpgradeableWallet.sol"))
    assert "contract UpgradeableWallet" in r.output and "guard: modifier onlyOwner" in r.output
    r = invoke("callgraph", str(examples / "ReentrancyVault.sol"))
    assert r.output.startswith("digraph chainmail {") and '"ReentrancyVault.withdrawAll" -> "ReentrancyVault._send"' in r.output


def test_cli_version():
    assert "chainmail" in invoke("--version").output
