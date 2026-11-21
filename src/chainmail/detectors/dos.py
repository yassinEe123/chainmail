"""Denial-of-service and ETH-accounting detectors."""

from __future__ import annotations

from ..core import ast as A
from ..core.analysis import CallKind, is_member, render
from ..core.project import ContractInfo
from ..findings import Confidence, Severity
from .base import Detector, register


@register
class UnboundedLoop(Detector):
    id = "unbounded-loop"
    title = "Loop over unbounded storage array"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    swc = "SWC-128"
    cwe = "CWE-400"
    description = (
        "A loop iterates over a dynamic storage array whose length can grow. "
        "Once the array is large enough the function exceeds the block gas "
        "limit and becomes permanently unusable (e.g. GovernMental)."
    )
    recommendation = "Paginate the loop (start/end indices), cap the array size, or use pull-based accounting."
    references = ("https://swcregistry.io/docs/SWC-128",)

    def check_contract(self, info: ContractInfo) -> None:
        dynamic_arrays = {v.name: v for v in info.all_state_vars() if v.type_name.endswith("[]") and not v.is_constant}
        if not dynamic_arrays:
            return
        growers = self._public_growers(info, set(dynamic_arrays))
        for fn in self.own_functions(info):
            if fn.is_view and not fn.is_public_entry:
                continue
            fa = self.analyze(fn, info)
            for loop in fa.loops:
                cond = getattr(loop, "cond", None)
                if cond is None:
                    continue
                for node in cond.walk():
                    if isinstance(node, A.MemberAccess) and node.member == "length" and isinstance(node.expr, A.Identifier):
                        name = node.expr.name
                        if name in dynamic_arrays and fa.state_var_for(name) is not None:
                            public_growth = name in growers
                            self.report(
                                info.file,
                                loop,
                                f"Loop in `{fn.signature}` iterates over `{name}`, which "
                                + ("anyone can grow" if public_growth else "can grow over time")
                                + "; gas usage is unbounded.",
                                contract=info.name,
                                function=fn,
                                severity=Severity.MEDIUM if (public_growth and not fn.is_view) else Severity.LOW,
                                confidence=Confidence.HIGH if public_growth else Confidence.MEDIUM,
                            )
                            break

    def _public_growers(self, info: ContractInfo, names: set[str]) -> set[str]:
        out: set[str] = set()
        for fn in info.all_functions():
            if not fn.is_public_entry or fn.body is None:
                continue
            fa = self.analyze(fn, info)
            if fa.is_protected:
                continue
            for call in fa.calls:
                t = call.node.target
                if isinstance(t, A.MemberAccess) and t.member == "push" and isinstance(t.expr, A.Identifier) and t.expr.name in names:
                    out.add(t.expr.name)
        return out


@register
class StrictBalanceEquality(Detector):
    id = "strict-balance-equality"
    title = "Strict equality on contract balance"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    swc = "SWC-132"
    cwe = "CWE-667"
    description = (
        "The contract's ETH or token balance is compared with `==`/`!=`. Anyone "
        "can change the balance without calling the contract (forced ETH via "
        "`selfdestruct`/coinbase, direct token transfers), breaking the check forever."
    )
    recommendation = "Track deposits in a state variable, or use `>=`/`<=` comparisons."
    references = ("https://swcregistry.io/docs/SWC-132",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info, include_modifiers=True):
            if fn.body is None:
                continue
            for node in fn.body.walk():
                if isinstance(node, A.BinaryOp) and node.op in ("==", "!="):
                    if self._is_balance(node.left) or self._is_balance(node.right):
                        self.report(
                            info.file, node, f"`{render(node, 90)}` uses strict equality on a balance.", contract=info.name, function=fn
                        )

    @staticmethod
    def _is_balance(expr: A.Expression) -> bool:
        if isinstance(expr, A.MemberAccess) and expr.member == "balance":
            inner = expr.expr
            if (
                isinstance(inner, A.FunctionCall)
                and inner.args
                and isinstance(inner.args[0], A.Identifier)
                and inner.args[0].name == "this"
            ):
                return True
            if isinstance(inner, A.Identifier) and inner.name == "this":
                return True
        if isinstance(expr, A.FunctionCall) and isinstance(expr.target, A.MemberAccess) and expr.target.member == "balanceOf":
            for arg in expr.args:
                if any(isinstance(n, A.Identifier) and n.name == "this" for n in arg.walk()):
                    return True
        return False


@register
class LockedEther(Detector):
    id = "locked-ether"
    title = "Contract locks ETH"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    cwe = "CWE-404"
    description = (
        "The contract can receive ETH (payable functions, `receive` or payable "
        "`fallback`) but has no code path that sends ETH out. Funds sent to it "
        "are locked forever."
    )
    recommendation = "Remove `payable` or add a (protected) withdrawal function."

    SENDING_KINDS = (
        CallKind.LOW_LEVEL_CALL,
        CallKind.SEND,
        CallKind.TRANSFER,
        CallKind.SEND_VALUE,
        CallKind.SELFDESTRUCT,
        CallKind.DELEGATECALL,
        CallKind.CALLCODE,
    )

    def check_contract(self, info: ContractInfo) -> None:
        if info.kind in ("library", "abstract"):
            return
        functions = info.all_functions()
        payable = [fn for fn in functions if fn.is_payable and fn.kind != "constructor" and fn.body is not None]
        if not payable:
            return
        if info.unresolved_bases:
            return  # a base we cannot see may implement withdrawals
        for fn in functions + [m for c in info.linearization for m in c.contract.modifiers]:
            if fn.body is None:
                continue
            fa = self.analyze(fn, info)
            for call in fa.calls:
                if call.kind in self.SENDING_KINDS:
                    return
                if call.kind is CallKind.EXTERNAL and call.value is not None:
                    return
                if call.kind is CallKind.CREATE and call.value is not None:
                    return
            if fa.assembly:
                return  # inline assembly may call/selfdestruct
        self.report(
            info.file,
            info.contract,
            f"`{info.name}` accepts ETH via {', '.join(f'`{f.signature}`' for f in payable[:3])} but never sends ETH.",
            contract=info.name,
        )


@register
class MsgValueWithoutPayable(Detector):
    id = "msg-value-non-payable"
    title = "msg.value read in non-payable function"
    severity = Severity.LOW
    confidence = Confidence.HIGH
    category = "code-quality"
    description = (
        "`msg.value` is always zero in a non-payable public function (the call "
        "reverts otherwise). Logic depending on it is dead or indicates a missing "
        "`payable` modifier."
    )
    recommendation = "Mark the function `payable` or remove the `msg.value` logic."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if fn.is_payable or fn.visibility not in ("public", "external") or fn.kind != "function" or fn.body is None:
                continue
            for node in fn.body.walk():
                if is_member(node, "msg", "value"):
                    self.report(info.file, node, f"`{fn.signature}` reads `msg.value` but is not payable.", contract=info.name, function=fn)
                    break
