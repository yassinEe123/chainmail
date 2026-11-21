"""Detectors about external calls: unchecked returns, controlled targets, loops."""

from __future__ import annotations

from ..core import ast as A
from ..core.analysis import CallKind, is_member, mentions_sender, render
from ..core.project import ContractInfo
from ..findings import Confidence, Severity
from .base import Detector, register

SIGNATURE_CHECKS = {"ecrecover", "recover", "tryRecover", "isValidSignatureNow", "isValidSignature", "verify", "_verify"}


@register
class UncheckedLowLevelCall(Detector):
    id = "unchecked-low-level-call"
    title = "Unchecked low-level call"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    swc = "SWC-104"
    cwe = "CWE-252"
    description = (
        "The boolean returned by `call`, `delegatecall`, `staticcall` or "
        "`callcode` is ignored. Low-level calls do not revert on failure, so "
        "execution silently continues as if the call succeeded."
    )
    recommendation = (
        "Capture the return value and handle failure: "
        '`(bool ok, ) = target.call(data); require(ok, "call failed");` or use '
        "OpenZeppelin's `Address.functionCall`."
    )
    references = ("https://swcregistry.io/docs/SWC-104",)
    example = 'payable(to).call{value: amount}("");  // result discarded'

    KINDS = (CallKind.LOW_LEVEL_CALL, CallKind.DELEGATECALL, CallKind.STATICCALL, CallKind.CALLCODE)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info, include_modifiers=True):
            fa = self.analyze(fn, info)
            for call in fa.calls:
                if call.kind in self.KINDS and not fa.result_is_used(call.node):
                    self.report(
                        info.file,
                        call.node,
                        f"Return value of low-level `{call.name}` is not checked: `{render(call.node, 90)}`.",
                        contract=info.name,
                        function=fn,
                        severity=Severity.HIGH if call.sends_value else Severity.MEDIUM,
                    )


@register
class UncheckedSend(Detector):
    id = "unchecked-send"
    title = "Unchecked send"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    swc = "SWC-104"
    cwe = "CWE-252"
    description = "`address.send()` returns `false` on failure instead of reverting, and the result is ignored."
    recommendation = 'Use `require(to.send(x))`, or better, a checked `call{value: x}("")`.'

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info, include_modifiers=True):
            fa = self.analyze(fn, info)
            for call in fa.calls:
                if call.kind is CallKind.SEND and not fa.result_is_used(call.node):
                    self.report(
                        info.file,
                        call.node,
                        f"Return value of `{render(call.node, 80)}` is ignored; failed transfers go unnoticed.",
                        contract=info.name,
                        function=fn,
                    )


@register
class UncheckedERC20Transfer(Detector):
    id = "unchecked-erc20-transfer"
    title = "Unchecked ERC20 transfer"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    swc = "SWC-104"
    cwe = "CWE-252"
    description = (
        "The boolean returned by an ERC20 `transfer`/`transferFrom`/`approve` is "
        "ignored. Several widely used tokens return `false` instead of "
        "reverting, and others (e.g. USDT) return nothing at all."
    )
    recommendation = "Use OpenZeppelin's `SafeERC20` (`safeTransfer`, `safeTransferFrom`, `forceApprove`)."
    references = ("https://github.com/d-xo/weird-erc20#missing-return-values",)

    ARITY = {"transfer": 2, "transferFrom": 3, "approve": 2}

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            fa = self.analyze(fn, info)
            for call in fa.calls:
                if call.kind is not CallKind.EXTERNAL or self.ARITY.get(call.name) != len(call.node.args):
                    continue
                if isinstance(call.receiver, A.Identifier) and call.receiver.name == "super":
                    continue
                rtype = fa.type_of(call.receiver) if call.receiver is not None else None
                if rtype and any(tag in rtype for tag in ("721", "1155", "NFT")):
                    continue  # ERC721/1155 transfers return nothing
                if not fa.result_is_used(call.node):
                    self.report(
                        info.file,
                        call.node,
                        f"Return value of `{render(call.node, 80)}` is not checked.",
                        contract=info.name,
                        function=fn,
                        confidence=Confidence.HIGH if call.confidence == "high" else Confidence.MEDIUM,
                    )


@register
class ControlledDelegatecall(Detector):
    id = "controlled-delegatecall"
    title = "Delegatecall to user-controlled address"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    swc = "SWC-112"
    cwe = "CWE-829"
    description = (
        "`delegatecall` executes foreign code in the context of this contract "
        "(its storage, balance and `msg.sender`). If the target can be chosen by "
        "the caller, anyone can overwrite storage (e.g. the owner) or "
        "`selfdestruct` the contract - see the Parity multisig hack."
    )
    recommendation = (
        "Only delegatecall to trusted, immutable implementation addresses, and "
        "restrict any function that changes the implementation with access control."
    )
    references = ("https://swcregistry.io/docs/SWC-112",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if not fn.is_public_entry:
                continue
            fa = self.analyze(fn, info)
            for call in fa.calls:
                is_dc = call.kind in (CallKind.DELEGATECALL, CallKind.CALLCODE) or call.name == "functionDelegateCall"
                if not is_dc:
                    continue
                target = call.receiver if call.name != "functionDelegateCall" or not call.node.args else call.node.args[0]
                if call.name == "functionDelegateCall" and isinstance(call.receiver, A.Identifier) and call.receiver.name == "Address":
                    target = call.node.args[0] if call.node.args else None
                if target is None or not fa.expr_controlled(target):
                    continue
                if fa.is_protected:
                    self.report(
                        info.file,
                        call.node,
                        f"`{fn.signature}` delegatecalls into a caller-supplied address "
                        f"`{render(target)}`; it is access-controlled ({fa.access_control}) "
                        "but a compromised admin key gives full control of storage.",
                        contract=info.name,
                        function=fn,
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                    )
                else:
                    self.report(
                        info.file,
                        call.node,
                        f"Anyone can make `{info.name}` delegatecall into an arbitrary "
                        f"address `{render(target)}` through `{fn.signature}`.",
                        contract=info.name,
                        function=fn,
                    )


@register
class ArbitraryExternalCall(Detector):
    id = "arbitrary-external-call"
    title = "Arbitrary external call with user-supplied data"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    cwe = "CWE-20"
    description = (
        "An unprotected function performs a low-level `call` where both the "
        "target and the calldata come from the caller. Attackers can make the "
        "contract call any function on any contract - typically "
        "`token.transferFrom(victim, attacker, amount)` against users who "
        "approved this contract."
    )
    recommendation = "Restrict the callable targets/selectors with an allow-list, or protect the function."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if not fn.is_public_entry:
                continue
            fa = self.analyze(fn, info)
            if fa.is_protected:
                continue
            for call in fa.calls:
                if call.kind is not CallKind.LOW_LEVEL_CALL or call.receiver is None:
                    continue
                data = call.node.args[0] if call.node.args else None
                if fa.expr_controlled(call.receiver) and data is not None and fa.expr_controlled(data):
                    self.report(
                        info.file,
                        call.node,
                        f"`{fn.signature}` forwards caller-controlled calldata to a caller-controlled target: `{render(call.node, 90)}`.",
                        contract=info.name,
                        function=fn,
                    )


@register
class ArbitrarySendEth(Detector):
    id = "arbitrary-send-eth"
    title = "Unprotected ETH transfer to arbitrary address"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    swc = "SWC-105"
    cwe = "CWE-284"
    description = (
        "A public function without access control sends ETH to an address chosen "
        "by the caller, and the amount is not tied to the caller's own balance. "
        "Anyone can drain the contract."
    )
    recommendation = "Protect the function (e.g. `onlyOwner`) or only pay out funds owed to `msg.sender`."
    references = ("https://swcregistry.io/docs/SWC-105",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if not fn.is_public_entry or fn.is_view:
                continue
            fa = self.analyze(fn, info)
            if fa.is_protected:
                continue
            body_mentions_sender = fn.body is not None and mentions_sender(fn.body)
            if any(c.name in SIGNATURE_CHECKS for c in fa.calls):
                continue  # authorised by an off-chain signature (see signature-* detectors)
            for call in fa.calls:
                if not call.sends_value or call.receiver is None:
                    continue
                if call.kind not in (CallKind.LOW_LEVEL_CALL, CallKind.TRANSFER, CallKind.SEND, CallKind.SEND_VALUE):
                    continue
                if mentions_sender(call.receiver):
                    continue
                if not fa.expr_controlled(call.receiver):
                    continue
                if body_mentions_sender:
                    # Likely "withdraw my own balance to address X".
                    continue
                self.report(
                    info.file,
                    call.node,
                    f"`{fn.signature}` sends ETH to caller-chosen `{render(call.receiver)}` "
                    "without any access control or balance accounting.",
                    contract=info.name,
                    function=fn,
                    # A payable function may just be refunding the caller's own msg.value.
                    confidence=Confidence.LOW if fn.is_payable else Confidence.MEDIUM,
                )


@register
class ExternalCallInLoop(Detector):
    id = "external-call-in-loop"
    title = "External call inside a loop"
    severity = Severity.LOW
    confidence = Confidence.MEDIUM
    swc = "SWC-113"
    cwe = "CWE-400"
    description = (
        "External calls inside loops make the whole transaction fail if a single "
        "call reverts (one malicious recipient can block everyone) and may run "
        "out of gas as the loop grows."
    )
    recommendation = "Favour the pull-over-push pattern: record what each party is owed and let them withdraw."
    references = ("https://swcregistry.io/docs/SWC-113",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            fa = self.analyze(fn, info)
            for call in fa.calls:
                if call.in_loop and call.kind.is_external and call.kind is not CallKind.STATICCALL:
                    sev = Severity.MEDIUM if call.sends_value else Severity.LOW
                    self.report(
                        info.file,
                        call.node,
                        f"External call `{render(call.node, 80)}` is executed inside a loop in `{fn.signature}`.",
                        contract=info.name,
                        function=fn,
                        severity=sev,
                    )


@register
class MsgValueInLoop(Detector):
    id = "msg-value-in-loop"
    title = "msg.value used inside a loop"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    cwe = "CWE-837"
    description = (
        "`msg.value` is constant during a transaction. Reusing it inside a loop "
        "(or in batched delegatecalls/multicall) credits the same ETH several "
        "times - the root cause of the Opyn and SushiSwap MISO bugs."
    )
    recommendation = "Track the remaining value in a local variable and decrease it on each iteration."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            fa = self.analyze(fn, info)
            for loop in fa.loops:
                body = getattr(loop, "body", None)
                if body is None:
                    continue
                for node in body.walk():
                    if is_member(node, "msg", "value"):
                        self.report(
                            info.file,
                            node,
                            f"`msg.value` is read inside a loop in `{fn.signature}`.",
                            contract=info.name,
                            function=fn,
                        )
                        break


@register
class TransferGasStipend(Detector):
    id = "transfer-gas-stipend"
    title = "Use of transfer()/send() with fixed gas stipend"
    severity = Severity.INFO
    confidence = Confidence.HIGH
    category = "best-practice"
    cwe = "CWE-655"
    description = (
        "`transfer` and `send` forward a hard-coded 2300 gas stipend. Gas cost "
        "changes (EIP-1884) and smart-contract wallets (Safe, account "
        "abstraction) can make these transfers fail permanently."
    )
    recommendation = 'Use `call{value: amount}("")` with a reentrancy guard and check the result.'
    references = ("https://consensys.io/diligence/blog/2019/09/stop-using-soliditys-transfer-now/",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            fa = self.analyze(fn, info)
            for call in fa.calls:
                if call.kind in (CallKind.TRANSFER, CallKind.SEND):
                    self.report(
                        info.file,
                        call.node,
                        f"`{render(call.node, 80)}` relies on the 2300 gas stipend.",
                        contract=info.name,
                        function=fn,
                    )
