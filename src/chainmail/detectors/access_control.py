"""Access-control detectors (SWC-105, SWC-106, SWC-115 and friends)."""

from __future__ import annotations

import re

from ..core import ast as A
from ..core.analysis import CallKind, FunctionAnalysis, identifiers, is_builtin_call, mentions, mentions_sender, render
from ..core.project import ContractInfo
from ..findings import Confidence, Severity
from .base import Detector, register

INITIALIZER_NAME_RE = re.compile(r"^(initialize|initialise|init|__\w+_init|setup|setUp|configure)\w*$", re.I)
INITIALIZER_MOD_RE = re.compile(
    r"^(initializer|reinitializer|onlyInitializing|initializerOnly|whenNotInitialized|notInitialized|uninitialized)$", re.I
)
CRITICAL_VAR_RE = re.compile(r"(^|_)(owner|admin|governance|governor|implementation|impl|guardian|superuser|root|authority)s?($|_)", re.I)
SENSITIVE_VAR_RE = re.compile(
    r"(owner|admin|operator|minter|treasury|feeRecipient|feeTo|feeReceiver|feeBps|feeRate|protocolFee|oracle|priceFeed|router|signer|validator|keeper|paused|whitelist|allowlist|blacklist|blocklist|manager|controller|strategy|beneficiary|guardian|pauser|upgrader|trustedForwarder)",
    re.I,
)
MINT_NAME_RE = re.compile(r"^_?(mint|mintTo|safeMint|issue|burnFrom)$", re.I)


def _is_constant_address(expr: A.Expression) -> bool:
    if isinstance(expr, A.FunctionCall) and isinstance(expr.target, A.ElementaryTypeExpr) and len(expr.args) == 1:
        return isinstance(expr.args[0], A.Literal)
    return isinstance(expr, A.Literal)


def _reaches_selfdestruct(det: Detector, fn: A.FunctionDef, info: ContractInfo, depth: int = 0, seen=None) -> A.FunctionCall | None:
    seen = seen or set()
    fa = det.analyze(fn, info)
    for call in fa.calls:
        if call.kind is CallKind.SELFDESTRUCT:
            return call.node
        if call.kind is CallKind.INTERNAL and call.resolved is not None and depth < 3 and id(call.resolved) not in seen:
            if call.resolved.body is not None and not det.analyze(call.resolved, info).is_protected:
                if _reaches_selfdestruct(det, call.resolved, info, depth + 1, seen | {id(call.resolved)}):
                    return call.node
    return None


@register
class UnprotectedSelfdestruct(Detector):
    id = "unprotected-selfdestruct"
    title = "Unprotected selfdestruct"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    swc = "SWC-106"
    cwe = "CWE-284"
    description = (
        "Anyone can call a function that reaches `selfdestruct`, destroying the contract and sending its ETH to an arbitrary address."
    )
    recommendation = "Remove `selfdestruct` (deprecated by EIP-6049) or restrict it to a trusted role."
    references = ("https://swcregistry.io/docs/SWC-106",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if not fn.is_public_entry:
                continue
            fa = self.analyze(fn, info)
            if fa.is_protected:
                continue
            node = _reaches_selfdestruct(self, fn, info)
            if node is not None:
                self.report(
                    info.file,
                    node,
                    f"`{fn.signature}` can be called by anyone and destroys the contract.",
                    contract=info.name,
                    function=fn,
                )


@register
class TxOriginAuth(Detector):
    id = "tx-origin-auth"
    title = "Authorization through tx.origin"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    swc = "SWC-115"
    cwe = "CWE-477"
    description = (
        "`tx.origin` is the externally-owned account that started the transaction, "
        "not the immediate caller. A malicious contract the owner interacts with "
        "can pass a `tx.origin == owner` check and act on the owner's behalf (phishing)."
    )
    recommendation = "Use `msg.sender` for authorization."
    references = ("https://swcregistry.io/docs/SWC-115",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info, include_modifiers=True):
            if fn.body is None:
                continue
            for node in fn.body.walk():
                if not (isinstance(node, A.BinaryOp) and node.op in ("==", "!=")):
                    continue
                if not (mentions(node.left, "tx", "origin") or mentions(node.right, "tx", "origin")):
                    continue
                other = node.right if mentions(node.left, "tx", "origin") else node.left
                if _is_constant_address(other):
                    continue  # e.g. `tx.origin == address(0)` to detect eth_call simulation
                if mentions_sender(other):
                    self.report(
                        info.file,
                        node,
                        f"`{render(node)}` is used to block contract callers. It breaks with "
                        "smart-contract wallets and will not hold under EIP-7702 delegated EOAs.",
                        contract=info.name,
                        function=fn,
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        title="tx.origin used to detect contracts",
                    )
                else:
                    self.report(
                        info.file,
                        node,
                        f"Authorization check `{render(node)}` relies on `tx.origin`.",
                        contract=info.name,
                        function=fn,
                    )


def _has_init_guard(fa: FunctionAnalysis) -> bool:
    """Look for require(!initialized) / if (initialized) revert / owner == address(0)."""
    state_names = {v.name for v in fa.info.all_state_vars()}
    for cond in fa.conditions:
        if set(identifiers(cond)) & state_names:
            return True
    for call in fa.calls:
        if call.name in ("require", "assert") and call.node.args:
            if set(identifiers(call.node.args[0])) & state_names:
                return True
        if call.kind is CallKind.INTERNAL and re.search(r"(init|Initializ)", call.name):
            # e.g. _disableInitializers / __Ownable_init (calls OZ guard)
            if "disable" in call.name.lower() or "checkInitializing" in call.name:
                return True
    return False


@register
class UnprotectedInitializer(Detector):
    id = "unprotected-initializer"
    title = "Unprotected initializer"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    cwe = "CWE-665"
    description = (
        "An initializer-like function is public, has no `initializer` modifier "
        "and does not check whether initialization already happened. Anyone can "
        "call it (again) to take ownership - the root cause of the Parity wallet "
        "and several proxy takeovers."
    )
    recommendation = (
        "Use OpenZeppelin's `Initializable` and mark the function `initializer`; "
        "call `_disableInitializers()` in the implementation's constructor."
    )
    references = ("https://docs.openzeppelin.com/upgrades-plugins/writing-upgradeable#initializers",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if fn.kind != "function" or not fn.is_public_entry or fn.is_view:
                continue
            if not INITIALIZER_NAME_RE.match(fn.name):
                continue
            if any(INITIALIZER_MOD_RE.match(m) for m in fn.modifier_names):
                continue
            fa = self.analyze(fn, info)
            if fa.is_protected or _has_init_guard(fa):
                continue
            if not fa.state_writes:
                continue
            written = sorted({w.var.name for w in fa.state_writes})
            self.report(
                info.file,
                fn,
                f"`{fn.signature}` initializes state ({', '.join(written[:5])}) and can be called by anyone, any number of times.",
                contract=info.name,
                function=fn,
                confidence=Confidence.HIGH if any(CRITICAL_VAR_RE.search(n) for n in written) else Confidence.MEDIUM,
            )


@register
class MissingAccessControl(Detector):
    id = "missing-access-control"
    title = "Sensitive state change without access control"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    swc = "SWC-105"
    cwe = "CWE-284"
    description = (
        "A public/external function updates a privileged state variable (owner, "
        "admin, implementation, fees, oracle, pause flag, ...) without any "
        "`msg.sender` check or access-control modifier."
    )
    recommendation = "Restrict the function with `onlyOwner`/`onlyRole` or an explicit `msg.sender` check."

    def check_contract(self, info: ContractInfo) -> None:
        if info.kind == "library":
            return
        for fn in self.own_functions(info):
            if fn.kind != "function" or not fn.is_public_entry or fn.is_view:
                continue
            if INITIALIZER_NAME_RE.match(fn.name):
                continue  # handled by unprotected-initializer
            fa = self.analyze(fn, info)
            if fa.is_protected:
                continue
            for write in fa.state_writes:
                var = write.var
                if not SENSITIVE_VAR_RE.search(var.name):
                    continue
                if var.type_name.startswith("mapping") and self._keyed_by_sender(write.node):
                    continue  # e.g. operatorApprovals[msg.sender][op] = true
                critical = bool(CRITICAL_VAR_RE.search(var.name))
                self.report(
                    info.file,
                    write.node,
                    f"Anyone can call `{fn.signature}` and modify privileged variable `{var.name}`.",
                    contract=info.name,
                    function=fn,
                    severity=Severity.CRITICAL if critical else Severity.HIGH,
                    confidence=Confidence.HIGH if critical else Confidence.MEDIUM,
                )
                break

    @staticmethod
    def _keyed_by_sender(node: A.Node) -> bool:
        target = node.target if isinstance(node, A.Assignment) else getattr(node, "operand", None)
        while isinstance(target, (A.IndexAccess, A.MemberAccess)):
            if isinstance(target, A.IndexAccess) and mentions_sender(target.index):
                return True
            target = target.base if isinstance(target, A.IndexAccess) else target.expr
        return False


@register
class UnprotectedMint(Detector):
    id = "unprotected-mint"
    title = "Unprotected token minting"
    severity = Severity.CRITICAL
    confidence = Confidence.MEDIUM
    cwe = "CWE-284"
    description = "A public function mints tokens to an arbitrary address without any access control."
    recommendation = "Restrict minting to a `MINTER_ROLE`/owner, or tie it to an on-chain payment/condition."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if fn.kind != "function" or not fn.is_public_entry or fn.is_view or fn.is_payable:
                continue
            if INITIALIZER_NAME_RE.match(fn.name):
                continue  # covered by unprotected-initializer
            fa = self.analyze(fn, info)
            if fa.is_protected:
                continue
            names = {c.name for c in fa.calls}
            if (
                "balanceOf" in names
                and fn.body is not None
                and any(isinstance(n, A.Identifier) and n.name == "this" for n in fn.body.walk())
            ):
                continue  # mints against measured deposits (e.g. Uniswap pair `mint`)
            if names & {"_burn", "transferFrom", "safeTransferFrom", "_spendAllowance", "permit"}:
                continue  # wrapper/deposit/flash-mint patterns pay for what they mint
            for call in fa.calls:
                if call.kind is not CallKind.INTERNAL or not MINT_NAME_RE.match(call.name):
                    continue
                if call.name.lower() == "burnfrom":
                    continue
                if not call.node.args or not fa.expr_tainted(call.node.args[0]):
                    continue
                if any(mentions_sender(a) for a in call.node.args):
                    continue
                if fa.conditions or any(c.name in ("require", "assert") for c in fa.calls):
                    conf = Confidence.LOW  # some precondition exists (e.g. merkle proof / sale open)
                else:
                    conf = Confidence.HIGH
                self.report(
                    info.file,
                    call.node,
                    f"`{fn.signature}` lets anyone mint to an arbitrary address via `{render(call.node, 70)}`.",
                    contract=info.name,
                    function=fn,
                    confidence=conf,
                    severity=Severity.CRITICAL if conf is Confidence.HIGH else Severity.MEDIUM,
                )
                break


@register
class UnprotectedUpgrade(Detector):
    id = "unprotected-upgrade"
    title = "Unprotected proxy upgrade"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe = "CWE-284"
    description = (
        "The upgrade authorization hook of a UUPS proxy (`_authorizeUpgrade`) is "
        "empty and has no access-control modifier, or an `upgradeTo*` function is "
        "public without protection. Anyone can point the proxy to malicious code."
    )
    recommendation = "Implement `_authorizeUpgrade(address) internal override onlyOwner {}`."
    references = ("https://docs.openzeppelin.com/contracts/5.x/api/proxy#UUPSUpgradeable-_authorizeUpgrade-address-",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            fa = self.analyze(fn, info)
            if fn.name == "_authorizeUpgrade":
                if fa.is_protected:
                    continue
                body_empty = fn.body is not None and not fn.body.statements
                has_revert = fn.body is not None and any(
                    isinstance(n, (A.RevertStatement, A.ThrowStatement)) or is_builtin_call(n, "require", "revert") for n in fn.body.walk()
                )
                if body_empty or not has_revert:
                    self.report(
                        info.file,
                        fn,
                        "`_authorizeUpgrade` does not restrict who may upgrade the implementation.",
                        contract=info.name,
                        function=fn,
                    )
            elif fn.name in ("upgradeTo", "upgradeToAndCall", "setImplementation", "upgrade") and fn.is_public_entry:
                if not fa.is_protected and fa.state_writes:
                    self.report(
                        info.file,
                        fn,
                        f"`{fn.signature}` changes the implementation without access control.",
                        contract=info.name,
                        function=fn,
                    )
