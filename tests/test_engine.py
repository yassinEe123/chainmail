import json
import textwrap

import pytest

from chainmail.config import Config, ConfigError
from chainmail.engine import Scanner, collect_files, write_baseline
from chainmail.findings import Confidence, Severity

VULN = textwrap.dedent(
    """
    pragma solidity 0.8.24;
    contract C {
        address owner;
        function a() external { require(tx.origin == owner); }
        // chainmail-disable-next-line tx-origin-auth
        function b() external { require(tx.origin == owner); }
        function c() external { require(tx.origin == owner); } // chainmail-disable-line
        // chainmail-disable tx-origin-auth
        function d() external { require(tx.origin == owner); }
        // chainmail-enable tx-origin-auth
        function e() external { require(tx.origin == owner); } // slither-disable-line tx-origin-auth
        function f() external { require(tx.origin == owner); } // chainmail-disable-line other-detector
    }
    """
)


def run(src=VULN, **cfg):
    config = Config(include_detectors=["tx-origin-auth"], **cfg)
    return Scanner(config).scan_source(src, "C.sol")


def test_inline_suppressions():
    result = run()
    assert sorted(f.location.function for f in result.findings) == ["a", "f"]
    assert result.suppressed == 4


def test_baseline_roundtrip(tmp_path):
    first = run()
    path = tmp_path / "baseline.json"
    assert write_baseline(first, path) == 2
    data = json.loads(path.read_text())
    assert data["tool"] == "chainmail" and len(data["fingerprints"]) == 2

    # Shift every line down: fingerprints must survive the move.
    shifted = "\n\n\n" + VULN
    config = Config(include_detectors=["tx-origin-auth"], baseline=str(path))
    second = Scanner(config).scan_source(shifted, "C.sol")
    assert second.findings == [] and second.baselined == 2


def test_thresholds_and_overrides():
    result = run(min_severity=Severity.CRITICAL)
    assert result.findings == [] and result.filtered == 2
    config = Config(include_detectors=["tx-origin-auth"], severity_overrides={"tx-origin-auth": Severity.INFO})
    result = Scanner(config).scan_source(VULN, "C.sol")
    assert {f.severity for f in result.findings} == {Severity.INFO}
    assert not result.should_fail(Severity.HIGH)


def test_should_fail_and_risk_score():
    result = run()
    assert result.should_fail(Severity.HIGH)
    assert not result.should_fail(None)
    assert 0 < result.risk_score <= 100
    assert result.counts["high"] == 2


def test_detector_glob_selection():
    cfg = Config(include_detectors=["reentrancy-*"])
    enabled = Scanner(cfg).enabled_detectors()
    assert set(enabled) == {"reentrancy-eth", "reentrancy-no-eth"}
    cfg = Config(exclude_detectors=["*"])
    assert Scanner(cfg).enabled_detectors() == {}


def test_config_from_yaml(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "chainmail.yml").write_text(
        textwrap.dedent(
            """
            detectors:
              exclude: [assembly-usage]
              severity: {timestamp-dependence: info}
            min_severity: medium
            min_confidence: medium
            fail_on: none
            paths:
              exclude: ["**/vendor/**"]
            """
        )
    )
    sub = tmp_path / "src"
    sub.mkdir()
    cfg = Config.load(search_from=sub)
    assert cfg.exclude_detectors == ["assembly-usage"]
    assert cfg.severity_overrides == {"timestamp-dependence": Severity.INFO}
    assert cfg.min_severity is Severity.MEDIUM and cfg.min_confidence is Confidence.MEDIUM
    assert cfg.fail_on is None
    assert "**/vendor/**" in cfg.exclude_paths


def test_config_rejects_unknown_keys(tmp_path):
    p = tmp_path / "chainmail.yml"
    p.write_text("detectorz: {}\n")
    with pytest.raises(ConfigError):
        Config.load(p)


def test_pyproject_config(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "pyproject.toml").write_text('[tool.chainmail]\nmin_severity = "high"\n')
    assert Config.load(search_from=tmp_path).min_severity is Severity.HIGH


def test_collect_files_respects_excludes(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.sol").write_text("contract A {}")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "A.t.sol").write_text("contract T {}")
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "B.sol").write_text("contract B {}")
    (tmp_path / "weird.sol").mkdir()  # a directory with a .sol suffix
    files = collect_files([tmp_path], Config())
    assert [f.name for f in files] == ["A.sol"]
    with_tests = collect_files([tmp_path], Config(include_tests=True))
    assert sorted(f.name for f in with_tests) == ["A.sol", "A.t.sol"]


def test_crashing_detector_is_isolated(monkeypatch):
    from chainmail.detectors import calls

    def boom(self, info):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(calls.UncheckedSend, "check_contract", boom)
    result = Scanner(Config(include_detectors=["unchecked-send", "tx-origin-auth"])).scan_source(VULN, "C.sol")
    assert [e.detector for e in result.detector_errors] == ["unchecked-send"]
    assert result.findings  # other detectors still ran


def test_findings_are_sorted_by_severity():
    src = "pragma solidity ^0.8.0; contract C { address o; function k() external { selfdestruct(payable(msg.sender)); } }"
    result = Scanner(Config()).scan_source(src, "C.sol")
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)
