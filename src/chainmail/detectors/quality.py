"""Code-quality, best-practice and gas detectors."""

from __future__ import annotations

import re

from ..core import ast as A
from ..core.analysis import CallKind, identifiers, render
from ..core.project import ContractInfo
from ..core.version import V0_6_0
from ..findings import Confidence, Severity
from .base import Detector, register

BUILTIN_SYMBOLS = {
    "now",
    "msg",
    "block",
    "tx",
    "abi",
    "this",
    "super",
    "selfdestruct",
    "suicide",
    "keccak256",
    "sha256",
    "sha3",
    "ecrecover",
    "require",
    "assert",
    "revert",
    "gasleft",
    "blockhash",
    "addmod",
    "mulmod",
    "type",
}


@register
class StateShadowing(Detector):
    id = "shadowing-state"
    title = "State variable shadowing"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    swc = "SWC-119"
    cwe = "CWE-710"
    description = (
        "A state variable re-declares a variable of a base contract (two storage "
        "slots, base functions keep using the old one), or a local/parameter "
        "hides a state variable."
    )
    recommendation = "Rename the variable, or remove the duplicate declaration and reuse the inherited one."
    references = ("https://swcregistry.io/docs/SWC-119",)

    def check_contract(self, info: ContractInfo) -> None:
        own = {v.name: v for v in info.contract.state_vars}
        for base in info.linearization[1:]:
            for var in base.contract.state_vars:
                if var.visibility == "private" and not info.file.allows_version_below(V0_6_0):
                    continue  # each contract keeps its own private slot; no confusion possible
                if var.name in own and own[var.name] is not var and base.kind != "interface":
                    self.report(
                        info.file,
                        own[var.name],
                        f"`{info.name}.{var.name}` shadows state variable `{base.name}.{var.name}`.",
                        contract=info.name,
                    )
        state = {v.name for v in info.all_state_vars()}
        for fn in self.own_functions(info, include_modifiers=True):
            for p in fn.params + fn.returns:
                if p.name and p.name in state:
                    self.report(
                        info.file,
                        p,
                        f"Parameter `{p.name}` of `{fn.signature}` shadows a state variable.",
                        contract=info.name,
                        function=fn,
                        severity=Severity.LOW,
                        title="Local variable shadows state",
                    )
            for node in fn.body.walk() if fn.body else []:
                if isinstance(node, A.VariableDeclarationStatement):
                    for d in node.declarations:
                        if d and d.name and d.name in state:
                            self.report(
                                info.file,
                                node,
                                f"Local variable `{d.name}` in `{fn.signature}` shadows a state variable.",
                                contract=info.name,
                                function=fn,
                                severity=Severity.LOW,
                                title="Local variable shadows state",
                            )


@register
class BuiltinShadowing(Detector):
    id = "shadowing-builtin"
    title = "Shadowing of a builtin symbol"
    severity = Severity.LOW
    confidence = Confidence.HIGH
    swc = "SWC-119"
    category = "code-quality"
    description = "A variable, function or parameter is named like a Solidity builtin (`now`, `msg`, `assert`, ...)."
    recommendation = "Rename the declaration."

    def check_contract(self, info: ContractInfo) -> None:
        for var in info.contract.state_vars:
            if var.name in BUILTIN_SYMBOLS:
                self.report(info.file, var, f"State variable `{var.name}` shadows a builtin.", contract=info.name)
        for fn in info.contract.functions + info.contract.modifiers:
            if fn.name in BUILTIN_SYMBOLS:
                self.report(info.file, fn, f"`{fn.name}` shadows a builtin symbol.", contract=info.name, function=fn)
            for p in fn.params:
                if p.name in BUILTIN_SYMBOLS:
                    self.report(info.file, p, f"Parameter `{p.name}` shadows a builtin.", contract=info.name, function=fn)


@register
class AssemblyUsage(Detector):
    id = "assembly-usage"
    title = "Inline assembly"
    severity = Severity.INFO
    confidence = Confidence.HIGH
    category = "best-practice"
    description = "Inline assembly bypasses Solidity's type and memory safety checks and deserves careful manual review."
    recommendation = "Keep assembly minimal, documented and covered by tests; prefer `memory-safe` blocks."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info, include_modifiers=True):
            fa = self.analyze(fn, info)
            for asm in fa.assembly:
                dangerous = [
                    op
                    for op in ("delegatecall", "selfdestruct", "sstore", "call", "create2", "callcode")
                    if re.search(rf"\b{op}\s*\(", asm.code)
                ]
                detail = f" (uses {', '.join(dangerous)})" if dangerous else ""
                self.report(
                    info.file,
                    asm,
                    f"`{fn.signature}` contains inline assembly{detail}.",
                    contract=info.name,
                    function=fn,
                    severity=Severity.LOW if any(d in ("delegatecall", "selfdestruct", "callcode") for d in dangerous) else Severity.INFO,
                    metadata={"opcodes": dangerous},
                )


@register
class MissingZeroAddressCheck(Detector):
    id = "missing-zero-check"
    title = "Missing zero-address validation"
    severity = Severity.LOW
    confidence = Confidence.MEDIUM
    cwe = "CWE-20"
    description = (
        "An address parameter is stored in state without checking for "
        "`address(0)`. A mistaken call can brick privileged roles or burn funds."
    )
    recommendation = "Add `require(addr != address(0))` (or a custom error) before storing the address."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if not (fn.is_public_entry or fn.is_constructor) or fn.body is None:
                continue
            fa = self.analyze(fn, info)
            address_params = {p.name for p in fn.params if p.name and p.type_name.startswith("address")}
            if not address_params:
                continue
            checked: set[str] = set()
            for cond in fa.conditions:
                checked |= set(identifiers(cond))
            for call in fa.calls:
                if call.node.args and (call.name in ("require", "assert") or call.kind is CallKind.INTERNAL):
                    for a in call.node.args:
                        checked |= set(identifiers(a))
            for w in fa.state_writes:
                node = w.node
                if not isinstance(node, A.Assignment) or not w.var.type_name.startswith("address"):
                    continue
                value_names = set(identifiers(node.value))
                hit = (value_names & address_params) - checked
                if hit and not isinstance(node.target, A.IndexAccess):
                    name = sorted(hit)[0]
                    self.report(
                        info.file,
                        node,
                        f"`{name}` is written to `{w.var.name}` without a zero-address check.",
                        contract=info.name,
                        function=fn,
                    )


@register
class MissingEvents(Detector):
    id = "missing-events"
    title = "Privileged state change without event"
    severity = Severity.INFO
    confidence = Confidence.MEDIUM
    category = "best-practice"
    cwe = "CWE-778"
    description = "An access-controlled function changes configuration without emitting an event, hindering off-chain monitoring."
    recommendation = "Emit an event describing the old and new values."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if not fn.is_public_entry or fn.is_view or fn.kind != "function":
                continue
            fa = self.analyze(fn, info)
            if not fa.is_protected or fa.emits or not fa.state_writes:
                continue
            if any(c.kind is CallKind.INTERNAL and c.resolved is not None and self.analyze(c.resolved, info).emits for c in fa.calls):
                continue
            names = sorted({w.var.name for w in fa.state_writes})
            self.report(
                info.file,
                fn,
                f"`{fn.signature}` updates {', '.join(f'`{n}`' for n in names[:4])} without emitting an event.",
                contract=info.name,
                function=fn,
            )


@register
class BooleanEquality(Detector):
    id = "boolean-equality"
    title = "Comparison to boolean constant"
    severity = Severity.INFO
    confidence = Confidence.HIGH
    category = "code-quality"
    description = "Comparing a boolean to `true`/`false` is redundant."
    recommendation = "Use the boolean directly (`if (x)` / `if (!x)`)."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info, include_modifiers=True):
            for node in fn.body.walk() if fn.body else []:
                if isinstance(node, A.BinaryOp) and node.op in ("==", "!="):
                    for side in (node.left, node.right):
                        if isinstance(side, A.Literal) and side.kind == "bool":
                            self.report(
                                info.file, node, f"`{render(node)}` compares with a boolean constant.", contract=info.name, function=fn
                            )
                            break


# ---------------------------------------------------------------------------
# Gas
# ---------------------------------------------------------------------------


def _project_internal_calls(det: Detector) -> set[str]:
    names: set[str] = set()
    for info in det.ctx.project.iter_contracts():
        for fn in info.contract.functions + info.contract.modifiers:
            if fn.body is None:
                continue
            for node in fn.body.walk():
                if isinstance(node, A.FunctionCall):
                    t = node.target
                    if isinstance(t, A.Identifier):
                        names.add(t.name)
                    elif isinstance(t, A.MemberAccess) and isinstance(t.expr, A.Identifier) and t.expr.name == "super":
                        names.add(t.member)
    return names


@register
class PublicCouldBeExternal(Detector):
    id = "external-function"
    title = "Public function could be external"
    severity = Severity.GAS
    confidence = Confidence.MEDIUM
    category = "gas"
    description = "A `public` function is never called internally; declaring it `external` documents intent and, before 0.6, avoided copying calldata arrays to memory."
    recommendation = "Declare the function `external`."

    def run(self):
        self._called = _project_internal_calls(self)
        return super().run()

    def check_contract(self, info: ContractInfo) -> None:
        if info.kind in ("library", "interface"):
            return
        for fn in self.own_functions(info):
            if fn.kind != "function" or fn.visibility != "public" or fn.is_virtual or fn.is_override:
                continue
            if fn.name in self._called:
                continue
            if not any(p.storage == "memory" and (p.type_name.endswith("]") or p.type_name in ("string", "bytes")) for p in fn.params):
                continue
            self.report(info.file, fn, f"`{fn.signature}` is public but never called internally.", contract=info.name, function=fn)


@register
class StateCouldBeConstant(Detector):
    id = "constable-states"
    title = "State variable could be constant or immutable"
    severity = Severity.GAS
    confidence = Confidence.HIGH
    category = "gas"
    description = (
        "A state variable is never modified after deployment. Declaring it "
        "`constant` (literal initializer) or `immutable` (set in the constructor) "
        "saves an SLOAD (2100 gas) on every read."
    )
    recommendation = "Mark the variable `constant` or `immutable`."

    def run(self):
        self._written = self._written_vars()
        return super().run()

    def _written_vars(self) -> dict[str, set[str]]:
        written: dict[str, set[str]] = {}
        for info in self.ctx.project.iter_contracts():
            for c in [info]:
                for fn in c.contract.functions + c.contract.modifiers:
                    if fn.body is None:
                        continue
                    fa = self.analyze(fn, info)
                    for w in fa.state_writes:
                        written.setdefault(w.var.name, set()).add("constructor" if fn.is_constructor else "function")
                    if fa.assembly:
                        written.setdefault("*assembly*", set()).add(info.name)
        return written

    def check_contract(self, info: ContractInfo) -> None:
        if info.kind in ("library", "interface") or info.unresolved_bases:
            return
        if "*assembly*" in self._written:
            return  # assembly might write storage slots
        for var in info.contract.state_vars:
            if var.is_constant or var.is_immutable:
                continue
            if var.type_name.startswith("mapping") or var.type_name.endswith("]") or var.type_name in ("string", "bytes"):
                continue
            ctx = self._written.get(var.name, set())
            if "function" in ctx:
                continue
            if not ctx and var.value is not None:
                self.report(info.file, var, f"`{var.name}` is never modified and could be `constant`.", contract=info.name)
            elif ctx == {"constructor"}:
                self.report(info.file, var, f"`{var.name}` is only set in the constructor and could be `immutable`.", contract=info.name)


@register
class StorageWriteInLoop(Detector):
    id = "storage-write-in-loop"
    title = "Storage variable written inside a loop"
    severity = Severity.GAS
    confidence = Confidence.MEDIUM
    category = "gas"
    description = "Writing the same storage slot on every iteration costs an SSTORE each time."
    recommendation = "Accumulate in a local (memory) variable and write to storage once after the loop."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            fa = self.analyze(fn, info)
            seen: set[str] = set()
            for w in fa.state_writes:
                if w.in_loop and w.var.name not in seen and not w.var.type_name.startswith("mapping") and not w.var.type_name.endswith("]"):
                    seen.add(w.var.name)
                    self.report(
                        info.file,
                        w.node,
                        f"`{w.var.name}` is written on every iteration of a loop in `{fn.signature}`.",
                        contract=info.name,
                        function=fn,
                    )


@register
class UnusedStateVariable(Detector):
    id = "unused-state"
    title = "Unused state variable"
    severity = Severity.INFO
    confidence = Confidence.MEDIUM
    category = "code-quality"
    description = "A private/internal state variable is never used. It wastes a storage slot and may hint at missing logic."
    recommendation = "Remove the variable or implement the missing logic."

    def run(self):
        used: set[str] = set()
        for sf in self.ctx.project.files:
            for c in sf.unit.contracts:
                for fn in c.functions + c.modifiers:
                    if fn.body is not None:
                        used |= set(identifiers(fn.body))
                        used |= {n.member for n in fn.body.walk() if isinstance(n, A.MemberAccess)}
                        for inv in fn.modifiers:
                            for a in inv.args:
                                used |= set(identifiers(a))
                        for asm in fn.body.walk():
                            if isinstance(asm, A.AssemblyStatement):
                                used |= set(asm.code.replace(".", " ").replace("(", " ").replace(")", " ").split())
                for var in c.state_vars:
                    if var.value is not None:
                        used |= set(identifiers(var.value))
        self._used = used
        return super().run()

    def check_contract(self, info: ContractInfo) -> None:
        if info.kind in ("library", "interface"):
            return
        for var in info.contract.state_vars:
            if var.visibility == "public" or var.name in self._used:
                continue
            self.report(info.file, var, f"State variable `{var.name}` is never used.", contract=info.name)
