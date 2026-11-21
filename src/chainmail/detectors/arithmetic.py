"""Arithmetic detectors: overflow, unchecked blocks, precision loss, truncation."""

from __future__ import annotations

import re

from ..core import ast as A
from ..core.analysis import FunctionAnalysis, base_identifier, int_literal, render
from ..core.project import ContractInfo
from ..findings import Confidence, Severity
from .base import Detector, register

ARITH_OPS = {"+", "-", "*", "**"}
ARITH_ASSIGN = {"+=", "-=", "*="}
SMALL_INT_RE = re.compile(r"^(u?)int(\d+)$")


def _uses_safemath(info: ContractInfo) -> bool:
    for c in info.linearization:
        for uf in c.contract.using_for:
            if "SafeMath" in uf.library or "SignedSafeMath" in uf.library:
                return True
    return False


def _is_loop_counter(fa: FunctionAnalysis, expr: A.Expression) -> bool:
    root = base_identifier(expr)
    if root is None:
        return False
    if root.name not in fa.locals:
        return False
    for loop in fa.loops:
        if isinstance(loop, A.ForStatement) and loop.post is not None:
            if any(isinstance(n, A.Identifier) and n.name == root.name for n in loop.post.walk()):
                return True
    return False


@register
class IntegerOverflow(Detector):
    id = "integer-overflow"
    title = "Integer overflow / underflow"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    swc = "SWC-101"
    cwe = "CWE-190"
    description = (
        "The file may be compiled with Solidity < 0.8.0, where arithmetic wraps "
        "around silently, and the contract does not use SafeMath. Balances and "
        "counters can overflow (e.g. the BEC token `batchOverflow` bug)."
    )
    recommendation = "Compile with Solidity ≥ 0.8.0 (checked arithmetic by default) or use SafeMath."
    references = ("https://swcregistry.io/docs/SWC-101",)

    def check_contract(self, info: ContractInfo) -> None:
        if info.file.checked_arithmetic or _uses_safemath(info):
            return
        for fn in self.own_functions(info):
            if fn.is_view:
                continue
            fa = self.analyze(fn, info)
            hits = list(self._operations(fa))
            if not hits:
                continue
            first = hits[0]
            extra = f" ({len(hits) - 1} more in this function)" if len(hits) > 1 else ""
            self.report(
                info.file,
                first,
                f"Unchecked arithmetic `{render(first, 80)}` in `{fn.signature}`{extra}.",
                contract=info.name,
                function=fn,
                related=hits[1:6],
                metadata={"operations": len(hits)},
            )

    def _operations(self, fa: FunctionAnalysis):
        if fa.fn.body is None:
            return
        for node in fa.fn.body.walk():
            if isinstance(node, A.Assignment) and node.op in ARITH_ASSIGN:
                if not _is_loop_counter(fa, node.target):
                    yield node
            elif isinstance(node, A.UnaryOp) and node.op in ("++", "--"):
                root = base_identifier(node.operand)
                if root is not None and fa.state_var_for(root.name) is not None:
                    yield node
            elif isinstance(node, A.BinaryOp) and node.op in ARITH_OPS:
                if fa.expr_tainted(node) or any(fa.state_var_for(n.name) for n in node.walk() if isinstance(n, A.Identifier)):
                    if int_literal(node.left) is None or int_literal(node.right) is None:
                        if not fa.is_in_condition(node):
                            yield node


def _operands(op: A.Node) -> tuple[str, str]:
    if isinstance(op, A.Assignment):
        return render(op.target), render(op.value)
    assert isinstance(op, A.BinaryOp)
    return render(op.left), render(op.right)


def _comparison_guards(fn: A.FunctionDef, op: A.Node) -> bool:
    """Is there a comparison between the same two operands in the function?"""
    a, b = _operands(op)
    if fn.body is None:
        return False
    for node in fn.body.walk():
        if isinstance(node, A.BinaryOp) and node.op in ("<", ">", "<=", ">="):
            sides = {render(node.left), render(node.right)}
            if a in sides and b in sides:
                return True
            # `a - b` guarded by `b <= a` is covered above; also accept `a >= b + c`-style bounds.
            if a in sides and any(b in s_ for s_ in sides if s_ != a):
                return True
    return False


@register
class UncheckedBlockArithmetic(Detector):
    id = "unchecked-arithmetic"
    title = "Arithmetic in unchecked block"
    severity = Severity.LOW
    confidence = Confidence.LOW
    swc = "SWC-101"
    cwe = "CWE-190"
    description = (
        "Arithmetic inside an `unchecked { }` block wraps on overflow even with "
        "Solidity ≥ 0.8. This is a common gas optimisation, but it is only safe "
        "when the bounds are proven beforehand."
    )
    recommendation = "Document why the operation cannot overflow, or move it out of the `unchecked` block."

    def check_contract(self, info: ContractInfo) -> None:
        if not info.file.checked_arithmetic:
            return  # IntegerOverflow already covers old compilers
        for fn in self.own_functions(info):
            if fn.body is None:
                continue
            fa = self.analyze(fn, info)
            for node in fn.body.walk():
                if not (isinstance(node, A.Block) and node.unchecked):
                    continue
                for inner in node.walk():
                    op = None
                    if (
                        isinstance(inner, A.BinaryOp)
                        and inner.op in ARITH_OPS
                        or isinstance(inner, A.Assignment)
                        and inner.op in ARITH_ASSIGN
                    ):
                        op = inner
                    if op is None:
                        continue
                    target = op.target if isinstance(op, A.Assignment) else op.left
                    if _is_loop_counter(fa, target):
                        continue
                    if not fa.expr_tainted(op):
                        continue
                    sub = (isinstance(op, A.BinaryOp) and op.op == "-") or (isinstance(op, A.Assignment) and op.op == "-=")
                    if sub and _comparison_guards(fn, op):
                        continue  # e.g. `if (bal < amt) revert(); unchecked { bal - amt; }`
                    if not sub and isinstance(op, (A.BinaryOp, A.Assignment)) and _comparison_guards(fn, op):
                        continue
                    params = {p.name for p in fn.params if p.name}
                    direct = any(isinstance(n, A.Identifier) and n.name in params for n in op.walk())
                    risky = sub and fn.is_public_entry and direct
                    self.report(
                        info.file,
                        op,
                        f"Caller-influenced arithmetic `{render(op, 80)}` is not overflow-checked.",
                        contract=info.name,
                        function=fn,
                        severity=Severity.MEDIUM if risky else Severity.LOW,
                        confidence=Confidence.MEDIUM if risky else Confidence.LOW,
                    )


@register
class DivideBeforeMultiply(Detector):
    id = "divide-before-multiply"
    title = "Division before multiplication"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    cwe = "CWE-1339"
    description = (
        "Integer division truncates. Performing it before a multiplication "
        "amplifies the rounding error (`a / b * c` ≠ `a * c / b`), which can be "
        "exploited to skim fees or rewards."
    )
    recommendation = "Multiply first, then divide (`a * c / b`), or use `Math.mulDiv` for full precision."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if fn.body is None:
                continue
            divided_locals = self._division_locals(fn)
            for node in fn.body.walk():
                if not (isinstance(node, A.BinaryOp) and node.op == "*"):
                    continue
                for side, other in ((node.left, node.right), (node.right, node.left)):
                    direct = self._is_division(side)
                    via_local = isinstance(side, A.Identifier) and divided_locals.get(side.name, (10**9, 0)) < (node.loc.line, node.loc.col)
                    if not (direct or via_local):
                        continue
                    if isinstance(side, A.BinaryOp) and render(side.right) == render(other):
                        continue  # `x / step * step` rounds down to a multiple on purpose
                    self.report(
                        info.file,
                        node,
                        f"`{render(node, 80)}` multiplies the result of an integer division.",
                        contract=info.name,
                        function=fn,
                        confidence=Confidence.HIGH if direct else Confidence.MEDIUM,
                    )
                    break

    @staticmethod
    def _is_division(expr: A.Expression) -> bool:
        return isinstance(expr, A.BinaryOp) and expr.op == "/" and int_literal(expr.right) not in (1,)

    def _division_locals(self, fn: A.FunctionDef) -> dict[str, tuple[int, int]]:
        """Locals assigned from a division, mapped to the position of that assignment."""
        names: dict[str, tuple[int, int]] = {}
        assert fn.body is not None

        def note(name: str, node: A.Node) -> None:
            pos = (node.loc.line, node.loc.col)
            names[name] = min(names.get(name, pos), pos)

        for node in fn.body.walk():
            if isinstance(node, A.VariableDeclarationStatement) and len(node.declarations) == 1 and node.declarations[0]:
                if node.value is not None and self._is_division(node.value) and node.declarations[0].name:
                    note(node.declarations[0].name, node)
            elif isinstance(node, A.Assignment) and node.op == "=" and isinstance(node.target, A.Identifier):
                if self._is_division(node.value):
                    note(node.target.name, node)
            elif isinstance(node, A.Assignment) and node.op == "/=" and isinstance(node.target, A.Identifier):
                note(node.target.name, node)
        return names


@register
class UnsafeDowncast(Detector):
    id = "unsafe-downcast"
    title = "Unsafe integer downcast"
    severity = Severity.LOW
    confidence = Confidence.MEDIUM
    cwe = "CWE-681"
    description = (
        "Explicit conversions to a smaller integer type (e.g. `uint128(x)`) "
        "silently truncate the value - even in Solidity ≥ 0.8, which only checks "
        "arithmetic, not casts."
    )
    recommendation = "Use OpenZeppelin `SafeCast` (`x.toUint128()`) or validate the range before casting."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if fn.body is None:
                continue
            fa = self.analyze(fn, info)
            for call in fa.calls:
                target = call.node.target
                if not isinstance(target, A.ElementaryTypeExpr) or len(call.node.args) != 1:
                    continue
                m = SMALL_INT_RE.match(target.type_name)
                if not m or int(m.group(2)) >= 256:
                    continue
                arg = call.node.args[0]
                if int_literal(arg) is not None:
                    continue
                bits = int(m.group(2))
                src_bits = self._source_bits(fa, arg)
                if src_bits is not None and src_bits <= bits:
                    continue
                if src_bits is None and not (fa.expr_tainted(arg) or self._mentions_state(fa, arg)):
                    continue
                self.report(
                    info.file,
                    call.node,
                    f"`{render(call.node, 80)}` may silently truncate a " + (f"{src_bits}-bit" if src_bits else "wider") + " value.",
                    contract=info.name,
                    function=fn,
                    confidence=Confidence.MEDIUM if src_bits else Confidence.LOW,
                )

    @staticmethod
    def _mentions_state(fa: FunctionAnalysis, expr: A.Expression) -> bool:
        return any(isinstance(n, A.Identifier) and fa.state_var_for(n.name) for n in expr.walk())

    @staticmethod
    def _source_bits(fa: FunctionAnalysis, expr: A.Expression) -> int | None:
        t = fa.type_of(expr)
        if t is None:
            return None
        m = SMALL_INT_RE.match(t)
        if m:
            return int(m.group(2))
        if t in ("uint", "int"):
            return 256
        if t.startswith("bytes") or t == "address":
            return 0  # conversions between categories are not truncation here
        return None


@register
class TautologicalComparison(Detector):
    id = "tautology"
    title = "Tautological or contradictory comparison"
    severity = Severity.LOW
    confidence = Confidence.HIGH
    category = "code-quality"
    cwe = "CWE-571"
    description = "An unsigned value is compared against zero in a way that is always true (`>= 0`) or always false (`< 0`)."
    recommendation = "Remove the check or fix the intended condition (e.g. `> 0`)."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info, include_modifiers=True):
            if fn.body is None:
                continue
            fa = self.analyze(fn, info)
            for node in fn.body.walk():
                if not isinstance(node, A.BinaryOp) or node.op not in (">=", "<", "<=", ">"):
                    continue
                flipped = {">=": "<=", "<": ">", "<=": ">=", ">": "<"}[node.op]
                pairs = [(node.left, node.op, node.right), (node.right, flipped, node.left)]
                for value, op, zero in pairs:
                    if int_literal(zero) != 0 or op not in (">=", "<"):
                        continue
                    t = fa.type_of(value) or ""
                    if t.startswith("uint"):
                        verdict = "always true" if op == ">=" else "always false"
                        self.report(
                            info.file,
                            node,
                            f"`{render(node)}` is {verdict} for unsigned `{t}`.",
                            contract=info.name,
                            function=fn,
                        )
                        break
