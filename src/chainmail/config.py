"""Configuration loading (``chainmail.yml`` / ``.chainmail.yml`` / ``pyproject.toml``)."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .findings import Confidence, Severity

CONFIG_FILENAMES = ("chainmail.yml", "chainmail.yaml", ".chainmail.yml", ".chainmail.yaml")
DEFAULT_EXCLUDE_PATHS = (
    "**/node_modules/**",
    "**/lib/forge-std/**",
    "**/lib/openzeppelin-contracts*/**",
    "**/.git/**",
    "**/cache/**",
    "**/out/**",
    "**/artifacts/**",
    "**/mocks/**",
    "**/mock/**",
    "**/testhelpers/**",
    "**/test-helpers/**",
)


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    include_detectors: list[str] = field(default_factory=list)  # empty = all
    exclude_detectors: list[str] = field(default_factory=list)
    min_severity: Severity = Severity.GAS
    min_confidence: Confidence = Confidence.LOW
    exclude_paths: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_PATHS))
    include_tests: bool = False
    fail_on: Severity | None = Severity.HIGH
    baseline: str | None = None
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    source: str | None = None

    # ------------------------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict[str, Any], source: str | None = None) -> Config:
        cfg = cls(source=source)
        detectors = data.get("detectors", {}) or {}
        if not isinstance(detectors, dict):
            raise ConfigError("'detectors' must be a mapping")
        cfg.include_detectors = list(detectors.get("include", []) or [])
        cfg.exclude_detectors = list(detectors.get("exclude", []) or [])
        for det_id, sev in (detectors.get("severity", {}) or {}).items():
            cfg.severity_overrides[det_id] = Severity.parse(str(sev))
        if "min_severity" in data:
            cfg.min_severity = Severity.parse(str(data["min_severity"]))
        if "min_confidence" in data:
            try:
                cfg.min_confidence = Confidence(str(data["min_confidence"]).lower())
            except ValueError as exc:
                raise ConfigError(f"invalid min_confidence: {data['min_confidence']!r}") from exc
        if "fail_on" in data:
            value = data["fail_on"]
            cfg.fail_on = None if value in (None, "none", "never", False) else Severity.parse(str(value))
        paths = data.get("paths", {}) or {}
        if "exclude" in paths:
            cfg.exclude_paths = list(DEFAULT_EXCLUDE_PATHS) + list(paths["exclude"] or [])
        cfg.include_tests = bool(paths.get("include_tests", False))
        cfg.baseline = data.get("baseline")
        unknown = set(data) - {"detectors", "min_severity", "min_confidence", "fail_on", "paths", "baseline"}
        if unknown:
            raise ConfigError(f"unknown configuration keys: {', '.join(sorted(unknown))}")
        return cfg

    @classmethod
    def load(cls, path: Path | None = None, search_from: Path | None = None) -> Config:
        if path is not None:
            return cls._load_file(Path(path))
        start = (search_from or Path.cwd()).resolve()
        if start.is_file():
            start = start.parent
        for directory in [start, *start.parents]:
            for name in CONFIG_FILENAMES:
                candidate = directory / name
                if candidate.is_file():
                    return cls._load_file(candidate)
            pyproject = directory / "pyproject.toml"
            if pyproject.is_file():
                cfg = cls._load_pyproject(pyproject)
                if cfg is not None:
                    return cfg
            if (directory / ".git").exists():
                break
        return cls()

    @classmethod
    def _load_file(cls, path: Path) -> Config:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"{path}: top level must be a mapping")
        return cls.from_dict(data, str(path))

    @classmethod
    def _load_pyproject(cls, path: Path) -> Config | None:
        try:
            import tomllib
        except ImportError:  # pragma: no cover - Python 3.10
            return None
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        section = data.get("tool", {}).get("chainmail")
        if section is None:
            return None
        return cls.from_dict(section, str(path))

    # ------------------------------------------------------------------
    def detector_enabled(self, detector_id: str) -> bool:
        if self.include_detectors and not any(fnmatch.fnmatch(detector_id, p) for p in self.include_detectors):
            return False
        return not any(fnmatch.fnmatch(detector_id, p) for p in self.exclude_detectors)

    def path_excluded(self, path: Path) -> bool:
        text = path.as_posix()
        if not self.include_tests:
            name = path.name
            if name.endswith((".t.sol", ".s.sol")) or "/test/" in f"/{text}" or "/script/" in f"/{text}":
                return True
        return any(fnmatch.fnmatch(text, pattern) or fnmatch.fnmatch("/" + text, pattern) for pattern in self.exclude_paths)


EXAMPLE_CONFIG = """\
# Chainmail configuration
# Detector ids accept shell-style wildcards (e.g. "reentrancy-*").
detectors:
  include: []            # empty = run every detector
  exclude:
    - assembly-usage
  severity:              # override the default severity of a detector
    timestamp-dependence: info

min_severity: low        # critical | high | medium | low | info | gas
min_confidence: low      # high | medium | low
fail_on: high            # exit code 1 if a finding at/above this severity remains ("none" to disable)

paths:
  include_tests: false   # *.t.sol, test/ and script/ are skipped by default
  exclude:
    - "**/mocks/**"

# baseline: chainmail-baseline.json   # ignore findings recorded in a baseline file
"""
