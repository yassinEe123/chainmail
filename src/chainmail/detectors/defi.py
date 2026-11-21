"""DeFi-specific detectors: oracles, slippage, approvals."""

from __future__ import annotations

from ..core import ast as A
from ..core.analysis import CallKind, identifiers, int_literal, is_member, render
from ..core.project import ContractInfo
from ..findings import Confidence, Severity
from .base import Detector, register

# Router function name -> index of the `amountOutMin` argument.
SLIPPAGE_ARGS = {
    "swapExactTokensForTokens": 1,
    "swapExactTokensForETH": 1,
    "swapExactETHForTokens": 0,
    "swapExactTokensForTokensSupportingFeeOnTransferTokens": 1,
    "swapExactTokensForETHSupportingFeeOnTransferTokens": 1,
    "swapExactETHForTokensSupportingFeeOnTransferTokens": 0,
    "exchange": 3,  # Curve: exchange(i, j, dx, min_dy)
    "exchange_underlying": 3,
    "remove_liquidity_one_coin": 2,
}
SLIPPAGE_FIELDS = {"amountOutMinimum", "amountOutMin", "minAmountOut", "minReturn", "amount0Min", "amount1Min", "minDy"}
DEADLINE_ARGS = {
    "swapExactTokensForTokens": 4,
    "swapExactTokensForETH": 4,
    "swapExactETHForTokens": 3,
    "swapTokensForExactTokens": 4,
    "addLiquidity": 7,
    "addLiquidityETH": 5,
    "removeLiquidity": 6,
    "removeLiquidityETH": 5,
}


@register
class MissingSlippageProtection(Detector):
    id = "missing-slippage"
    title = "Swap without slippage protection"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = "CWE-682"
    description = (
        "A DEX swap is executed with a minimum output of `0`. MEV bots can sandwich the transaction and extract almost all of its value."
    )
    recommendation = "Pass a caller-provided `amountOutMin` computed off-chain from a quote with a tolerance."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if fn.body is None:
                continue
            fa = self.analyze(fn, info)
            for call in fa.calls:
                idx = SLIPPAGE_ARGS.get(call.name)
                if idx is not None and call.kind is CallKind.EXTERNAL and len(call.node.args) > idx:
                    if int_literal(call.node.args[idx]) == 0:
                        self.report(
                            info.file, call.node, f"`{call.name}` is called with a minimum output of 0.", contract=info.name, function=fn
                        )
                        continue
                if call.node.names:
                    for name, arg in zip(call.node.names, call.node.args):
                        if name in SLIPPAGE_FIELDS and int_literal(arg) == 0:
                            self.report(
                                info.file,
                                call.node,
                                f"`{name}: 0` disables slippage protection in `{render(call.node.target)}`.",
                                contract=info.name,
                                function=fn,
                            )


@register
class IneffectiveDeadline(Detector):
    id = "ineffective-deadline"
    title = "Swap deadline set to block.timestamp"
    severity = Severity.LOW
    confidence = Confidence.HIGH
    cwe = "CWE-682"
    description = (
        "Passing `block.timestamp` as the deadline always passes the check, so a "
        "pending transaction can be held by validators and executed later at a "
        "worse price."
    )
    recommendation = "Let the user provide the deadline as a function argument."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            fa = self.analyze(fn, info)
            for call in fa.calls:
                idx = DEADLINE_ARGS.get(call.name)
                if idx is None or call.kind is not CallKind.EXTERNAL or len(call.node.args) <= idx:
                    continue
                arg = call.node.args[idx]
                if is_member(arg, "block", "timestamp") or (isinstance(arg, A.BinaryOp) and is_member(arg.left, "block", "timestamp")):
                    self.report(info.file, call.node, f"`{call.name}` deadline is `{render(arg)}`.", contract=info.name, function=fn)
                elif (lit := int_literal(arg)) is not None and lit >= 2**255:
                    self.report(info.file, call.node, f"`{call.name}` deadline is effectively infinite.", contract=info.name, function=fn)


@register
class SpotPriceOracle(Detector):
    id = "spot-price-oracle"
    title = "Price derived from AMM spot reserves"
    severity = Severity.HIGH
    confidence = Confidence.LOW
    cwe = "CWE-1339"
    description = (
        "The price is computed from an AMM pair's instantaneous state "
        "(`getReserves`, `slot0`, or token balances of the pool). These values "
        "can be moved arbitrarily within one transaction using a flash loan, "
        "enabling price manipulation attacks (bZx, Harvest, Cream, ...)."
    )
    recommendation = "Use a manipulation-resistant oracle: Chainlink, or a Uniswap TWAP over a sufficient window."

    SPOT_CALLS = {"getReserves", "slot0", "get_dy", "getAmountsOut", "getAmountOut", "get_virtual_price"}

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if fn.body is None:
                continue
            fa = self.analyze(fn, info)
            spot = [c for c in fa.calls if c.name in self.SPOT_CALLS and c.kind in (CallKind.EXTERNAL, CallKind.LIBRARY)]
            if not spot:
                continue
            derived = self._derived_locals(fn, spot)
            used_in_math = any(
                isinstance(n, A.BinaryOp)
                and n.op in ("*", "/")
                and (set(identifiers(n)) & derived or any(n2 is s.node for s in spot for n2 in n.walk()))
                for n in fn.body.walk()
            )
            if not used_in_math:
                continue
            conf = Confidence.MEDIUM if not fn.is_view else Confidence.LOW
            self.report(
                info.file,
                spot[0].node,
                f"`{fn.signature}` computes a value from `{spot[0].name}()`, which reflects manipulable spot state.",
                contract=info.name,
                function=fn,
                confidence=conf,
                severity=Severity.HIGH if conf is Confidence.MEDIUM else Severity.MEDIUM,
            )

    @staticmethod
    def _derived_locals(fn: A.FunctionDef, spot) -> set[str]:
        nodes = {id(s.node) for s in spot}
        names: set[str] = set()
        assert fn.body is not None
        for node in fn.body.walk():
            if isinstance(node, A.VariableDeclarationStatement) and node.value is not None:
                if any(id(n) in nodes for n in node.value.walk()) or set(identifiers(node.value)) & names:
                    names.update(d.name for d in node.declarations if d and d.name)
        return names


@register
class ChainlinkStalePrice(Detector):
    id = "chainlink-stale-price"
    title = "Chainlink price used without freshness checks"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    cwe = "CWE-672"
    description = (
        "`latestRoundData()` is consumed without validating `updatedAt` "
        "(staleness) and/or that `answer > 0`. During outages or sequencer "
        "downtime the feed may return stale or zero prices."
    )
    recommendation = (
        "Check `answer > 0`, `updatedAt != 0` and `block.timestamp - updatedAt <= heartbeat`; on L2s also check the sequencer uptime feed."
    )
    references = ("https://docs.chain.link/data-feeds#check-the-timestamp-of-the-latest-answer",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if fn.body is None:
                continue
            fa = self.analyze(fn, info)
            for call in fa.calls:
                if call.name == "latestAnswer" and call.kind is CallKind.EXTERNAL:
                    self.report(
                        info.file,
                        call.node,
                        "`latestAnswer()` is deprecated and gives no freshness information.",
                        contract=info.name,
                        function=fn,
                        severity=Severity.LOW,
                    )
                if call.name != "latestRoundData" or call.kind is not CallKind.EXTERNAL:
                    continue
                stmt = fa.parent(call.node)
                if not isinstance(stmt, A.VariableDeclarationStatement) or len(stmt.declarations) < 4:
                    self.report(
                        info.file,
                        call.node,
                        "`latestRoundData()` result is not destructured; freshness cannot be checked.",
                        contract=info.name,
                        function=fn,
                    )
                    continue
                answer = stmt.declarations[1]
                updated = stmt.declarations[3]
                checked = set()
                for cond in fa.conditions + [c.node.args[0] for c in fa.calls if c.name in ("require", "assert") and c.node.args]:
                    checked |= set(identifiers(cond))
                problems = []
                if updated is None or not updated.name or updated.name not in checked:
                    problems.append("staleness (`updatedAt`)")
                if answer is None or not answer.name or answer.name not in checked:
                    problems.append("`answer > 0`")
                if problems:
                    self.report(
                        info.file,
                        call.node,
                        f"`latestRoundData()` result is used without checking {' and '.join(problems)}.",
                        contract=info.name,
                        function=fn,
                    )


@register
class ApproveRaceCondition(Detector):
    id = "erc20-approve-race"
    title = "ERC20 approve front-running"
    severity = Severity.LOW
    confidence = Confidence.MEDIUM
    swc = "SWC-114"
    cwe = "CWE-362"
    description = (
        "The token's `approve` overwrites the allowance directly. A spender who "
        "sees an allowance change in the mempool can spend the old allowance and "
        "then the new one."
    )
    recommendation = "Provide `increaseAllowance`/`decreaseAllowance`, or require the allowance to be 0 before changing it."
    references = ("https://swcregistry.io/docs/SWC-114",)

    def check_contract(self, info: ContractInfo) -> None:
        fn = next((f for f in info.contract.functions if f.name == "approve" and len(f.params) == 2 and f.body is not None), None)
        if fn is None:
            return
        names = {f.name for f in info.all_functions()}
        if {"increaseAllowance", "decreaseAllowance"} & names:
            return
        fa = self.analyze(fn, info)
        if fa.conditions or any(c.name == "require" for c in fa.calls):
            # e.g. require(value == 0 || allowance[msg.sender][spender] == 0)
            for c in fa.calls:
                if c.name == "require" and c.node.args and "0" in render(c.node.args[0]):
                    return
        writes = [w for w in fa.state_writes if "allow" in w.var.name.lower()]
        internal = [c for c in fa.calls if c.name in ("_approve",)]
        if writes or internal:
            self.report(
                info.file, fn, "`approve` sets the allowance without mitigating the known race condition.", contract=info.name, function=fn
            )
