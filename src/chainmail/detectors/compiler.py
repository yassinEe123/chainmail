"""Compiler-version and language-level detectors."""

from __future__ import annotations

from ..core import ast as A
from ..core.analysis import is_builtin_call, is_member
from ..core.project import ContractInfo, SourceFile
from ..core.version import RECOMMENDED_MIN, V0_4_22, V0_5_0, V0_8_0
from ..findings import Confidence, Severity
from .base import Detector, register


@register
class FloatingPragma(Detector):
    id = "floating-pragma"
    title = "Floating compiler version"
    severity = Severity.LOW
    confidence = Confidence.HIGH
    swc = "SWC-103"
    cwe = "CWE-1103"
    category = "best-practice"
    description = (
        "The pragma accepts a range of compiler versions. Deployed bytecode may "
        "be produced by a different, untested (or buggy) compiler than the one "
        "used in testing and audits."
    )
    recommendation = "Lock the pragma for deployable contracts, e.g. `pragma solidity 0.8.24;`."
    references = ("https://swcregistry.io/docs/SWC-103",)

    def check_file(self, sf: SourceFile) -> None:
        pragma = sf.unit.solidity_pragma
        if pragma is None or sf.version_range is None or not sf.version_range.is_floating:
            return
        only_abstract = sf.unit.contracts and all(c.kind in ("interface", "library", "abstract") for c in sf.unit.contracts)
        self.report(
            sf,
            pragma,
            f"`pragma solidity {pragma.value};` is not locked to a specific version.",
            severity=Severity.INFO if only_abstract else Severity.LOW,
        )


@register
class OutdatedCompiler(Detector):
    id = "outdated-compiler"
    title = "Outdated compiler version"
    severity = Severity.INFO
    confidence = Confidence.HIGH
    swc = "SWC-102"
    cwe = "CWE-937"
    category = "best-practice"
    description = (
        "The pragma allows compiler versions with known bugs or missing safety features (checked arithmetic, custom errors, `push0`)."
    )
    recommendation = f"Use a recent compiler (≥ {RECOMMENDED_MIN})."
    references = ("https://docs.soliditylang.org/en/latest/bugs.html", "https://swcregistry.io/docs/SWC-102")

    def check_file(self, sf: SourceFile) -> None:
        pragma = sf.unit.solidity_pragma
        if pragma is None or sf.version_range is None:
            return
        low = sf.version_range.min_version
        if low >= RECOMMENDED_MIN:
            return
        sev = Severity.LOW if low < V0_8_0 else Severity.INFO
        self.report(
            sf,
            pragma,
            f"`pragma solidity {pragma.value};` allows compiler {low}, older than the recommended {RECOMMENDED_MIN}.",
            severity=sev,
        )


@register
class MissingPragma(Detector):
    id = "missing-pragma"
    title = "Missing version pragma"
    severity = Severity.INFO
    confidence = Confidence.HIGH
    category = "best-practice"
    description = "The file has no `pragma solidity` directive, so any compiler version may be used."
    recommendation = "Add an explicit, locked `pragma solidity` directive."

    def check_file(self, sf: SourceFile) -> None:
        if sf.unit.solidity_pragma is None and sf.unit.contracts:
            self.report(sf, 1, "No `pragma solidity` directive found.")


DEPRECATED_CALLS = {
    "suicide": ("suicide()", "selfdestruct()"),
    "sha3": ("sha3()", "keccak256()"),
}
DEPRECATED_MEMBERS = {
    ("block", "blockhash"): ("block.blockhash()", "blockhash()"),
    ("msg", "gas"): ("msg.gas", "gasleft()"),
    ("block", "difficulty"): ("block.difficulty", "block.prevrandao"),
}


@register
class DeprecatedConstructs(Detector):
    id = "deprecated-constructs"
    title = "Use of deprecated Solidity constructs"
    severity = Severity.INFO
    confidence = Confidence.HIGH
    swc = "SWC-111"
    cwe = "CWE-477"
    category = "best-practice"
    description = "The code uses constructs that are deprecated or removed in recent Solidity versions."
    recommendation = "Replace each deprecated construct with its modern equivalent."
    references = ("https://swcregistry.io/docs/SWC-111",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info, include_modifiers=True):
            if fn.mutability == "constant":
                self.report(
                    info.file, fn, f"`{fn.signature}` uses the `constant` function modifier; use `view`.", contract=info.name, function=fn
                )
            if fn.body is None:
                continue
            for node in fn.body.walk():
                msg = None
                if isinstance(node, A.Identifier) and node.name == "now":
                    msg = ("now", "block.timestamp")
                elif isinstance(node, A.ThrowStatement):
                    msg = ("throw", "revert()")
                elif isinstance(node, A.FunctionCall) and isinstance(node.target, A.Identifier) and node.target.name in DEPRECATED_CALLS:
                    msg = DEPRECATED_CALLS[node.target.name]
                elif isinstance(node, A.MemberAccess) and isinstance(node.expr, A.Identifier):
                    key = (node.expr.name, node.member)
                    if key in DEPRECATED_MEMBERS:
                        msg = DEPRECATED_MEMBERS[key]
                    elif node.member == "callcode":
                        msg = ("callcode", "delegatecall")
                elif isinstance(node, A.VariableDeclarationStatement):
                    if any(d and d.type_name == "var" for d in node.declarations):
                        msg = ("var", "an explicit type")
                elif isinstance(node, A.Literal) and node.unit == "years":
                    msg = ("years", "365 days")
                elif isinstance(node, A.FunctionCall) and isinstance(node.target, A.Identifier) and node.target.name == "selfdestruct":
                    self.report(
                        info.file,
                        node,
                        "`selfdestruct` is deprecated (EIP-6049) and no longer deletes code after Cancun (EIP-6780).",
                        contract=info.name,
                        function=fn,
                        severity=Severity.LOW,
                    )
                    continue
                if msg:
                    self.report(info.file, node, f"`{msg[0]}` is deprecated; use `{msg[1]}`.", contract=info.name, function=fn)


@register
class ConstructorName(Detector):
    id = "constructor-name"
    title = "Function named like its contract"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    swc = "SWC-118"
    cwe = "CWE-665"
    description = (
        "Before Solidity 0.4.22 the constructor was the function bearing the "
        "contract's name. A typo or a rename turns it into a public function "
        "anyone can call to re-initialize the contract (Rubixi)."
    )
    recommendation = "Use the `constructor` keyword."
    references = ("https://swcregistry.io/docs/SWC-118",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in info.contract.functions:
            if fn.kind == "function" and fn.name == info.name:
                old = info.file.allows_version_below(V0_4_22)
                self.report(
                    info.file,
                    fn,
                    f"`{fn.name}()` has the same name as contract `{info.name}`"
                    + (" and is a legacy constructor." if old else "; it is a regular public function, not a constructor."),
                    contract=info.name,
                    function=fn,
                    severity=Severity.MEDIUM if old else Severity.HIGH,
                )
            elif fn.kind == "function" and info.file.allows_version_below(V0_5_0) and _looks_like_typo(fn.name, info.name):
                has_ctor = any(f.kind == "constructor" for f in info.contract.functions)
                if has_ctor:
                    continue
                self.report(
                    info.file,
                    fn,
                    f"`{fn.name}()` is almost the contract name `{info.name}` - a misspelled legacy constructor "
                    "becomes a public function anyone can call.",
                    contract=info.name,
                    function=fn,
                )


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _looks_like_typo(name: str, contract: str) -> bool:
    if name == contract or len(contract) < 5:
        return False
    if not name[:1].isupper():
        return False  # legacy constructors were always written like the contract name
    if name.lower() == contract.lower():
        return True
    return _levenshtein(name.lower(), contract.lower()) <= 2 and name[0].isupper()


@register
class DefaultVisibility(Detector):
    id = "default-visibility"
    title = "Missing visibility specifier"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    swc = "SWC-100"
    cwe = "CWE-710"
    description = (
        "Functions without an explicit visibility default to `public` in Solidity < 0.5.0, exposing helpers intended to be internal."
    )
    recommendation = "Always declare visibility explicitly (`external`, `public`, `internal`, `private`)."
    references = ("https://swcregistry.io/docs/SWC-100", "https://swcregistry.io/docs/SWC-108")

    def check_contract(self, info: ContractInfo) -> None:
        if info.kind == "interface":
            return
        for fn in info.contract.functions:
            if fn.kind == "function" and fn.visibility is None:
                self.report(
                    info.file,
                    fn,
                    f"`{fn.signature}` has no visibility specifier and is implicitly public.",
                    contract=info.name,
                    function=fn,
                )
        for var in info.contract.state_vars:
            if var.visibility is None and not var.is_constant:
                self.report(
                    info.file,
                    var,
                    f"State variable `{var.name}` has no explicit visibility (defaults to internal).",
                    contract=info.name,
                    severity=Severity.INFO,
                    title="State variable default visibility",
                )


@register
class UninitializedStoragePointer(Detector):
    id = "uninitialized-storage-pointer"
    title = "Uninitialized storage pointer"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    swc = "SWC-109"
    cwe = "CWE-824"
    description = (
        "In Solidity < 0.5.0 a local struct/array declared without a data "
        "location defaults to `storage` and, if uninitialized, points at slot 0 - "
        "writes through it overwrite unrelated state (e.g. the owner)."
    )
    recommendation = "Declare the location explicitly (`memory`), or initialize the storage pointer."
    references = ("https://swcregistry.io/docs/SWC-109",)

    def check_contract(self, info: ContractInfo) -> None:
        if not info.file.allows_version_below(V0_5_0):
            return
        struct_names = {s.name for c in info.linearization for s in c.contract.structs}
        for fn in self.own_functions(info):
            for node in fn.body.walk() if fn.body else []:
                if not isinstance(node, A.VariableDeclarationStatement) or node.value is not None:
                    continue
                for d in node.declarations:
                    if d is None or d.storage == "memory":
                        continue
                    is_ref = d.type_name in struct_names or d.type_name.endswith("]")
                    if is_ref and d.storage in (None, "storage"):
                        self.report(
                            info.file,
                            node,
                            f"Local `{d.type_name} {d.name}` is an uninitialized storage pointer.",
                            contract=info.name,
                            function=fn,
                        )


@register
class RightToLeftOverride(Detector):
    id = "rtlo-character"
    title = "Right-to-left override / bidirectional character"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    swc = "SWC-130"
    cwe = "CWE-451"
    description = (
        "Unicode bidirectional control characters (e.g. U+202E) make the source "
        "render differently from how the compiler reads it, hiding malicious "
        'logic from reviewers ("Trojan Source").'
    )
    recommendation = "Remove all bidirectional control characters from the source."
    references = ("https://swcregistry.io/docs/SWC-130", "https://trojansource.codes/")

    def check_file(self, sf: SourceFile) -> None:
        for ch in sf.suspicious_chars:
            self.report(sf, A.Loc(ch.line, ch.col, ch.line), f"Bidirectional control character U+{ord(ch.char):04X} found.")


@register
class TypographicalError(Detector):
    id = "assignment-typo"
    title = "Suspicious `=+` / `=-` assignment"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    swc = "SWC-129"
    cwe = "CWE-480"
    description = "`x =+ 1` assigns `+1` instead of incrementing. This is almost always a typo for `+=`/`-=`."
    recommendation = "Use the compound operator (`+=`, `-=`) or add a space to make the intent explicit."
    references = ("https://swcregistry.io/docs/SWC-129",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            for node in fn.body.walk() if fn.body else []:
                if isinstance(node, A.Assignment) and node.op == "=" and isinstance(node.value, A.UnaryOp):
                    u = node.value
                    if u.prefix and u.op in ("+", "-", "!") and u.loc.line == node.loc.line and u.loc.col == node.loc.col + 1:
                        self.report(info.file, node, f"`={u.op}` found; did you mean `{u.op}=`?", contract=info.name, function=fn)


@register
class AssertStateChange(Detector):
    id = "assert-misuse"
    title = "assert() used for input validation or with side effects"
    severity = Severity.LOW
    confidence = Confidence.MEDIUM
    swc = "SWC-110"
    cwe = "CWE-670"
    category = "best-practice"
    description = (
        "`assert` should only check invariants that can never be false. Failing "
        "asserts on user input signals a bug to tooling, and before 0.8.0 "
        "consumed all remaining gas."
    )
    recommendation = "Use `require`/custom errors for input validation; keep `assert` for invariants."
    references = ("https://swcregistry.io/docs/SWC-110",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            fa = self.analyze(fn, info)
            for call in fa.calls:
                if not is_builtin_call(call.node, "assert") or not call.node.args:
                    continue
                arg = call.node.args[0]
                side_effect = any(isinstance(n, (A.Assignment,)) or (isinstance(n, A.UnaryOp) and n.op in ("++", "--")) for n in arg.walk())
                if side_effect:
                    self.report(
                        info.file,
                        call.node,
                        "`assert` condition has side effects.",
                        contract=info.name,
                        function=fn,
                        severity=Severity.MEDIUM,
                    )
                elif fn.is_public_entry and (
                    fa.expr_tainted(arg) or any(is_member(n, "msg", "sender") or is_member(n, "msg", "value") for n in arg.walk())
                ):
                    self.report(
                        info.file, call.node, "`assert` validates caller-controlled input; use `require`.", contract=info.name, function=fn
                    )
