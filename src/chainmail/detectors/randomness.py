"""Block-variable misuse: weak randomness (SWC-120) and timestamp dependence (SWC-116)."""

from __future__ import annotations

from ..core import ast as A
from ..core.analysis import FunctionAnalysis, int_literal, is_builtin_call, is_member, render
from ..core.project import ContractInfo
from ..findings import Confidence, Severity
from .base import Detector, register

ENTROPY_MEMBERS = {
    ("block", "timestamp"),
    ("block", "difficulty"),
    ("block", "prevrandao"),
    ("block", "number"),
    ("block", "coinbase"),
    ("block", "gaslimit"),
    ("block", "basefee"),
    ("block", "blockhash"),
    ("tx", "gasprice"),
}


def _is_entropy_source(node: A.Node) -> bool:
    if isinstance(node, A.MemberAccess) and isinstance(node.expr, A.Identifier):
        if (node.expr.name, node.member) in ENTROPY_MEMBERS:
            return True
    if isinstance(node, A.Identifier) and node.name == "now":
        return True
    return bool(is_builtin_call(node, "blockhash"))


def _entropy_in(expr: A.Node) -> list[A.Node]:
    return [n for n in expr.walk() if _is_entropy_source(n)]


def _hash_like(node: A.Node) -> bool:
    return is_builtin_call(node, "keccak256", "sha3", "sha256", "ripemd160")


def _is_power_of_two_literal(expr: A.Node) -> bool:
    if isinstance(expr, A.BinaryOp) and expr.op == "**":
        return int_literal(expr.left) == 2 and int_literal(expr.right) is not None
    value = int_literal(expr)
    return value is not None and value > 2 and value & (value - 1) == 0


def _tainted_locals(fa: FunctionAnalysis) -> set[str]:
    """Locals whose value is derived from block entropy."""
    names: set[str] = set()
    for stmt in fa.statements:
        if isinstance(stmt, A.VariableDeclarationStatement) and stmt.value is not None:
            if _entropy_in(stmt.value) or any(isinstance(n, A.Identifier) and n.name in names for n in stmt.value.walk()):
                for d in stmt.declarations:
                    if d and d.name:
                        names.add(d.name)
    return names


@register
class WeakRandomness(Detector):
    id = "weak-prng"
    title = "Weak source of randomness"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    swc = "SWC-120"
    cwe = "CWE-338"
    description = (
        "Randomness is derived from block attributes (`block.timestamp`, "
        "`block.prevrandao`, `blockhash`, ...). These values are public and can be "
        "predicted or influenced by validators and by contracts calling in the "
        "same block, so lotteries and mints become gameable."
    )
    recommendation = "Use a verifiable randomness source such as Chainlink VRF, or a commit-reveal scheme."
    references = ("https://swcregistry.io/docs/SWC-120",)
    example = "uint winner = uint(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % players.length;"

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if fn.body is None:
                continue
            fa = self.analyze(fn, info)
            derived = _tainted_locals(fa)
            reported_lines: set[int] = set()
            for node in fn.body.walk():
                hit = None
                if _hash_like(node) and _entropy_in(node):
                    hit = node
                elif isinstance(node, A.BinaryOp) and node.op == "%":
                    if _is_power_of_two_literal(node.right):
                        continue  # `block.timestamp % 2**32` is truncation, not randomness
                    if _entropy_in(node.left) or any(isinstance(n, A.Identifier) and n.name in derived for n in node.left.walk()):
                        hit = node
                if hit is None or hit.loc.line in reported_lines:
                    continue
                reported_lines.add(hit.loc.line)
                sources = sorted({render(n) for n in _entropy_in(hit)}) or sorted(derived)
                self.report(
                    info.file,
                    hit,
                    f"`{render(hit, 90)}` derives a pseudo-random value from {', '.join(f'`{s}`' for s in sources)}.",
                    contract=info.name,
                    function=fn,
                    confidence=Confidence.HIGH if isinstance(hit, A.BinaryOp) else Confidence.MEDIUM,
                )


@register
class TimestampDependence(Detector):
    id = "timestamp-dependence"
    title = "Block timestamp used in a condition"
    severity = Severity.LOW
    confidence = Confidence.MEDIUM
    swc = "SWC-116"
    cwe = "CWE-829"
    description = (
        "Validators have a few seconds of latitude on `block.timestamp`. Strict "
        "equality checks may never be satisfied, and short time windows can be "
        "manipulated."
    )
    recommendation = "Avoid strict equality on timestamps and tolerate drift of ~15 seconds in time windows."
    references = ("https://swcregistry.io/docs/SWC-116",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info, include_modifiers=True):
            if fn.body is None:
                continue
            fa = self.analyze(fn, info)
            for node in fn.body.walk():
                if not isinstance(node, A.BinaryOp) or node.op not in ("==", "!=", "<", ">", "<=", ">="):
                    continue
                if not any(is_member(n, "block", "timestamp") or (isinstance(n, A.Identifier) and n.name == "now") for n in node.walk()):
                    continue
                if any(_hash_like(n) for n in node.walk()):
                    continue  # reported as weak randomness
                strict = node.op in ("==", "!=")
                if not strict and not fa.is_in_condition(node):
                    continue
                self.report(
                    info.file,
                    node,
                    f"Condition `{render(node, 80)}` depends on `block.timestamp`" + (" with strict equality." if strict else "."),
                    contract=info.name,
                    function=fn,
                    severity=Severity.MEDIUM if strict else Severity.LOW,
                    confidence=Confidence.HIGH if strict else Confidence.MEDIUM,
                )
