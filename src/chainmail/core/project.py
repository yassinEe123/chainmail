"""Project-wide model: files, contracts, inheritance and symbol lookup."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from . import ast as A
from .lexer import Comment, SuspiciousChar
from .parser import ParseDiagnostic, ParseResult, parse_source
from .version import V0_8_0, VersionRange, parse_pragma


@dataclass(eq=False)
class SourceFile:
    path: str
    unit: A.SourceUnit
    comments: list[Comment]
    suspicious_chars: list[SuspiciousChar]
    errors: list[ParseDiagnostic]
    version_range: VersionRange | None = None

    @property
    def source(self) -> str:
        return self.unit.source

    @property
    def lines(self) -> list[str]:
        return self.unit.source.splitlines()

    @property
    def checked_arithmetic(self) -> bool:
        """True if every compiler allowed by the pragma checks overflow."""
        if self.version_range is None:
            return True  # assume modern compiler when no pragma is present
        return not self.version_range.allows_below(V0_8_0)

    def allows_version_below(self, version) -> bool:
        if self.version_range is None:
            return False
        return self.version_range.allows_below(version)

    @classmethod
    def from_result(cls, path: str, result: ParseResult) -> SourceFile:
        pragma = result.unit.solidity_pragma
        vrange = parse_pragma(pragma.value) if pragma else None
        return cls(path, result.unit, result.comments, result.suspicious_chars, result.errors, vrange)


@dataclass(eq=False)
class ContractInfo:
    """A contract plus everything resolved from its inheritance chain."""

    contract: A.ContractDef
    file: SourceFile
    linearization: list[ContractInfo] = field(default_factory=list)
    unresolved_bases: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.contract.name

    @property
    def kind(self) -> str:
        return self.contract.kind

    # Inherited members -------------------------------------------------
    def all_state_vars(self) -> list[A.StateVariable]:
        seen: dict[str, A.StateVariable] = {}
        for info in reversed(self.linearization):
            for var in info.contract.state_vars:
                seen.setdefault(var.name, var)
        # Most-derived contract first keeps declaration-order stable.
        return list(seen.values())

    def state_var(self, name: str) -> A.StateVariable | None:
        for info in self.linearization:
            var = info.contract.get_state_var(name)
            if var is not None:
                return var
        return None

    def all_functions(self) -> list[A.FunctionDef]:
        """Functions visible in this contract (most-derived override wins)."""
        result: dict[str, A.FunctionDef] = {}
        for info in self.linearization:
            for fn in info.contract.functions:
                key = fn.signature if fn.kind == "function" else fn.kind
                result.setdefault(key, fn)
        return list(result.values())

    def functions_named(self, name: str) -> list[A.FunctionDef]:
        out: list[A.FunctionDef] = []
        for info in self.linearization:
            out.extend(fn for fn in info.contract.functions if fn.name == name)
        return out

    def modifier(self, name: str) -> A.FunctionDef | None:
        for info in self.linearization:
            for mod in info.contract.modifiers:
                if mod.name == name:
                    return mod
        return None

    def inherits_from(self, name: str) -> bool:
        return any(info.name == name for info in self.linearization[1:]) or name in self.unresolved_bases

    def all_base_names(self) -> set[str]:
        return {info.name for info in self.linearization[1:]} | set(self.unresolved_bases)


class Project:
    """A set of parsed Solidity files analysed together."""

    def __init__(self) -> None:
        self.files: list[SourceFile] = []
        self.contracts: dict[str, list[ContractInfo]] = {}
        self._linearized = False

    # Loading -----------------------------------------------------------
    def add_source(self, source: str, path: str = "<memory>") -> SourceFile:
        result = parse_source(source, path)
        sf = SourceFile.from_result(path, result)
        self.files.append(sf)
        for contract in sf.unit.contracts:
            self.contracts.setdefault(contract.name, []).append(ContractInfo(contract, sf))
        self._linearized = False
        return sf

    def add_file(self, path: Path | str) -> SourceFile:
        p = Path(path)
        text = p.read_text(encoding="utf-8", errors="replace")
        return self.add_source(text, str(p))

    @classmethod
    def from_sources(cls, sources: Iterable[tuple[str, str]]) -> Project:
        project = cls()
        for path, text in sources:
            project.add_source(text, path)
        project.link()
        return project

    # Linking -----------------------------------------------------------
    def lookup(self, name: str, prefer: SourceFile | None = None) -> ContractInfo | None:
        short = name.split(".")[-1]
        candidates = self.contracts.get(short, [])
        if not candidates:
            return None
        if prefer is not None:
            for c in candidates:
                if c.file is prefer:
                    return c
        return candidates[0]

    def link(self) -> None:
        cache: dict[int, list[ContractInfo]] = {}
        for infos in self.contracts.values():
            for info in infos:
                info.linearization = self._c3(info, cache, set())
                info.unresolved_bases = [b for b in info.contract.bases if self.lookup(b, info.file) is None]
        self._linearized = True

    def _c3(self, info: ContractInfo, cache: dict[int, list[ContractInfo]], visiting: set[int]) -> list[ContractInfo]:
        key = id(info)
        if key in cache:
            return cache[key]
        if key in visiting:  # cyclic inheritance - bail out gracefully
            return [info]
        visiting.add(key)
        bases = [b for b in (self.lookup(name, info.file) for name in info.contract.bases) if b and b is not info]
        # Solidity lists bases from "most base-like" to "most derived", which is
        # the reverse of Python's convention.
        bases = list(reversed(bases))
        sequences = [list(self._c3(b, cache, visiting)) for b in bases] + [list(bases)]
        result = [info]
        while True:
            sequences = [s for s in sequences if s]
            if not sequences:
                break
            for seq in sequences:
                head = seq[0]
                if not any(head in s[1:] for s in sequences):
                    break
            else:
                # Inconsistent hierarchy: fall back to DFS order.
                for seq in sequences:
                    for item in seq:
                        if item not in result:
                            result.append(item)
                break
            result.append(head)
            for s in sequences:
                if s and s[0] is head:
                    s.pop(0)
        visiting.discard(key)
        cache[key] = result
        return result

    # Iteration ---------------------------------------------------------
    def iter_contracts(self) -> Iterator[ContractInfo]:
        if not self._linearized:
            self.link()
        for sf in self.files:
            for contract in sf.unit.contracts:
                for info in self.contracts.get(contract.name, []):
                    if info.contract is contract:
                        yield info

    def is_library(self, name: str) -> bool:
        info = self.lookup(name)
        return info is not None and info.kind == "library"

    def is_contract_type(self, name: str) -> bool:
        info = self.lookup(name)
        return info is not None and info.kind in ("contract", "interface", "abstract")

    @property
    def parse_errors(self) -> list[tuple[str, ParseDiagnostic]]:
        return [(sf.path, err) for sf in self.files for err in sf.errors]
