"""Reentrancy detectors (SWC-107).

The analysis is an inter-procedural *Checks-Effects-Interactions* check: for
every externally reachable, state-changing function we build an ordered list of
effects (external calls and state writes), inlining internal callees up to a
fixed depth, and flag every state write that happens after an external call.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core import ast as A
from ..core.analysis import CallKind, CallSite, StateWrite, render
from ..core.project import ContractInfo
from ..findings import Confidence, Severity
from .base import Detector, register

REENTRANCY_GUARD_RE = re.compile(r"(nonReentrant|noReentran|reentrancyGuard|lock|mutex|nonReentrantView|guarded)", re.I)
CALLBACK_HOOKS = {"_safeMint", "_safeTransfer", "_checkOnERC721Received", "_doSafeTransferAcceptanceCheck"}
MAX_DEPTH = 3


@dataclass
class _Effect:
    order: tuple
    kind: str  # "call" | "write"
    call: CallSite | None = None
    write: StateWrite | None = None
    via: str | None = None  # internal function through which the effect happens
    anchor: A.Node | None = None  # node in the entry function to report at


class _ReentrancyBase(Detector):
    swc = "SWC-107"
    cwe = "CWE-841"
    references = (
        "https://swcregistry.io/docs/SWC-107",
        "https://docs.soliditylang.org/en/latest/security-considerations.html#reentrancy",
    )
    recommendation = (
        "Apply the Checks-Effects-Interactions pattern: update all state *before* "
        "making the external call, and/or protect the function with a reentrancy "
        "guard such as OpenZeppelin's `nonReentrant`."
    )
    sends_eth: bool = True

    def check_contract(self, info: ContractInfo) -> None:
        if info.kind == "library":
            return
        for fn in self.own_functions(info):
            if not fn.is_public_entry or fn.is_view or fn.is_constructor:
                continue
            if any(REENTRANCY_GUARD_RE.search(m) for m in fn.modifier_names):
                continue
            effects = self._effects(fn, info, depth=0, visited=set(), prefix=())
            self._analyse(fn, info, effects)

    def _effects(self, fn: A.FunctionDef, info: ContractInfo, depth: int, visited: set[int], prefix: tuple) -> list[_Effect]:
        fa = self.analyze(fn, info)
        out: list[_Effect] = []
        for c in fa.calls:
            pos = prefix + (c.loc.line, c.loc.col)
            if c.kind.is_external and c.kind not in (CallKind.STATICCALL, CallKind.TRANSFER, CallKind.SEND):
                if c.confidence == "low" or self._is_view_target(c, info) or self._declared_view(fa, c):
                    continue
                out.append(_Effect(pos, "call", call=c))
            elif c.kind is CallKind.INTERNAL and c.resolved is None and c.name in CALLBACK_HOOKS:
                out.append(_Effect(pos, "call", call=c))
            elif c.kind is CallKind.INTERNAL and c.resolved is not None and depth < MAX_DEPTH:
                callee = c.resolved
                if id(callee) in visited or callee.body is None:
                    continue
                inner = self._effects(callee, info, depth + 1, visited | {id(callee)}, pos)
                for eff in inner:
                    eff.via = eff.via or callee.name
                    if depth == 0:
                        eff.anchor = c.node  # report in the entry function's file
                out.extend(inner)
        for w in fa.state_writes:
            out.append(_Effect(prefix + (w.loc.line, w.loc.col), "write", write=w))
        # Modifiers run around the body: writes in a modifier *after* `_` are
        # rare, so modifiers are ignored on purpose.
        out.sort(key=lambda e: e.order)
        return out

    def _declared_view(self, fa, call: CallSite) -> bool:
        """Is the callee declared `view`/`pure` in an interface/contract we parsed?"""
        if call.receiver is None or call.kind is not CallKind.EXTERNAL:
            return False
        rtype = fa.type_of(call.receiver)
        if not rtype:
            return False
        target = self.ctx.project.lookup(rtype.split()[0])
        if target is None:
            return False
        fns = [fn for c in target.linearization for fn in c.contract.functions if fn.name == call.name]
        return bool(fns) and all(fn.is_view for fn in fns)

    def _is_view_target(self, call: CallSite, info: ContractInfo) -> bool:
        """Skip calls to well-known read-only functions."""
        return call.name in {
            "balanceOf",
            "allowance",
            "totalSupply",
            "decimals",
            "symbol",
            "name",
            "getReserves",
            "ownerOf",
            "getApproved",
            "isApprovedForAll",
            "token0",
            "token1",
            "latestRoundData",
            "latestAnswer",
            "getPrice",
            "price0CumulativeLast",
            "price1CumulativeLast",
            "supportsInterface",
            "nonces",
            "DOMAIN_SEPARATOR",
            "convertToAssets",
            "convertToShares",
            "previewDeposit",
            "previewRedeem",
            "asset",
        }

    def _analyse(self, fn: A.FunctionDef, info: ContractInfo, effects: list[_Effect]) -> None:
        fa = self.analyze(fn, info)
        first_call: _Effect | None = None
        stale: dict[str, _Effect] = {}
        for eff in effects:
            if eff.kind == "call":
                call = eff.call
                assert call is not None
                eth = call.sends_value or call.kind in (CallKind.LOW_LEVEL_CALL, CallKind.SEND_VALUE)
                if self.sends_eth == eth and first_call is None:
                    first_call = eff
                continue
            if first_call is None or eff.write is None:
                continue
            var = eff.write.var
            if var.is_constant or var.is_immutable:
                continue
            stale.setdefault(var.name, eff)
        if first_call is None or not stale:
            return
        call = first_call.call
        assert call is not None
        call_pos = (call.loc.line, call.loc.col)
        read_before = (
            any(v.name in stale and (node.loc.line, node.loc.col) < call_pos for node, v in fa.state_reads) or first_call.via is not None
        )
        via = f" (via internal call to `{first_call.via}()`)" if first_call.via else ""
        parts = []
        for name, eff in stale.items():
            assert eff.write is not None
            where = f" in `{eff.via}()`" if eff.via else ""
            parts.append(f"`{name}` (line {eff.write.loc.line}{where})")
        self.report(
            info.file,
            first_call.anchor or call.node,
            f"`{fn.signature}` in `{info.name}` makes an external call "
            f"`{render(call.node, 80)}`{via} and only then updates "
            f"{', '.join(parts)}. A malicious callee can re-enter while this state is stale.",
            contract=info.name,
            function=fn,
            confidence=(
                Confidence.LOW if fa.is_protected else Confidence.HIGH if read_before and call.confidence == "high" else Confidence.MEDIUM
            ),
            related=[e.anchor or e.write.node for e in stale.values() if e.write is not None],
            metadata={"variables": list(stale), "call_line": call.loc.line},
        )


@register
class ReentrancyEth(_ReentrancyBase):
    id = "reentrancy-eth"
    title = "Reentrancy with ETH transfer"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    sends_eth = True
    description = (
        "State is modified after an external call that forwards ETH (or all "
        "remaining gas). The callee can re-enter and drain funds before the "
        "balance bookkeeping is updated - the bug behind The DAO hack."
    )
    example = """
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok,) = msg.sender.call{value: amount}("");   // interaction
    require(ok);
    balances[msg.sender] -= amount;                    // effect AFTER interaction
}"""


@register
class ReentrancyNoEth(_ReentrancyBase):
    id = "reentrancy-no-eth"
    title = "Reentrancy without ETH transfer"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    sends_eth = False
    description = (
        "State is modified after a call to an external contract (e.g. a token "
        "with hooks, an oracle or an arbitrary user-supplied address). Even "
        "without ETH, re-entering can break invariants (ERC777/ERC721 hooks, "
        "cross-function reentrancy)."
    )
