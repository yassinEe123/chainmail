"""Signature and hashing detectors (SWC-117, SWC-121, SWC-122, SWC-133)."""

from __future__ import annotations

import re

from ..core import ast as A
from ..core.analysis import CallKind, FunctionAnalysis, identifiers, is_builtin_call, is_member, render
from ..core.project import ContractInfo
from ..findings import Confidence, Severity
from .base import Detector, register

SECP256K1_HALF_N = "0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"
NONCE_RE = re.compile(r"(nonce|salt|used|executed|claimed|consumed|replay|deadline|expiry|expiration|id$|Id$)", re.I)
DOMAIN_RE = re.compile(r"(chainid|DOMAIN_SEPARATOR|domainSeparator|_hashTypedDataV4|_domainSeparatorV4|EIP712)", re.I)
RECOVER_NAMES = {"recover", "tryRecover", "isValidSignatureNow", "isValidSignature", "verify", "_verify", "_recover"}


def _signature_calls(fa: FunctionAnalysis) -> list:
    out = []
    for call in fa.calls:
        if (
            call.kind is CallKind.BUILTIN
            and call.name == "ecrecover"
            or call.name in RECOVER_NAMES
            and call.kind in (CallKind.LIBRARY, CallKind.EXTERNAL, CallKind.INTERNAL, CallKind.BUILTIN)
        ):
            out.append(call)
    return out


@register
class SignatureMalleability(Detector):
    id = "signature-malleability"
    title = "Raw ecrecover vulnerable to signature malleability"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    swc = "SWC-117"
    cwe = "CWE-347"
    description = (
        "`ecrecover` accepts both `(r, s, v)` and `(r, n - s, v')` for the same "
        "message. If signatures (rather than messages) are used to prevent "
        "replays, an attacker can forge a second valid signature."
    )
    recommendation = "Use OpenZeppelin `ECDSA.recover`, which rejects high-`s` signatures, and track nonces rather than signatures."
    references = ("https://swcregistry.io/docs/SWC-117",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            fa = self.analyze(fn, info)
            raw = [c for c in fa.calls if c.kind is CallKind.BUILTIN and c.name == "ecrecover"]
            if not raw:
                continue
            body = info.file.source.lower()
            if SECP256K1_HALF_N in body:
                continue
            self.report(
                info.file,
                raw[0].node,
                f"`{fn.signature}` calls `ecrecover` without restricting `s` to the lower half order.",
                contract=info.name,
                function=fn,
            )


@register
class EcrecoverZeroAddress(Detector):
    id = "ecrecover-zero-address"
    title = "ecrecover result not checked against address(0)"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    cwe = "CWE-252"
    description = (
        "`ecrecover` returns `address(0)` for invalid signatures. If the recovered "
        "address is compared to an uninitialized signer/owner (also zero), any "
        "garbage signature is accepted."
    )
    recommendation = "Require `recovered != address(0)` or use `ECDSA.recover`, which reverts on invalid signatures."

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if fn.body is None:
                continue
            fa = self.analyze(fn, info)
            raw = [c for c in fa.calls if c.kind is CallKind.BUILTIN and c.name == "ecrecover"]
            if not raw:
                continue
            checked = False
            for node in fn.body.walk():
                if isinstance(node, A.BinaryOp) and node.op in ("==", "!="):
                    for side in (node.left, node.right):
                        if (
                            isinstance(side, A.FunctionCall)
                            and isinstance(side.target, A.ElementaryTypeExpr)
                            and side.target.type_name == "address"
                        ):
                            if side.args and str(getattr(side.args[0], "value", "")) in ("0", "0x0"):
                                checked = True
            if not checked:
                self.report(
                    info.file, raw[0].node, "Recovered signer is never compared with `address(0)`.", contract=info.name, function=fn
                )


@register
class SignatureReplay(Detector):
    id = "signature-replay"
    title = "Signature replay"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    swc = "SWC-121"
    cwe = "CWE-294"
    description = (
        "A signature is verified, but the signed message does not include a "
        "nonce (or the contract does not record used signatures), and/or does "
        "not bind the chain id and verifying contract. The same signature can be "
        "submitted again, on another chain, or to another deployment."
    )
    recommendation = "Sign EIP-712 typed data including a per-signer nonce, `block.chainid` and `address(this)`; mark nonces as used."
    references = ("https://swcregistry.io/docs/SWC-121", "https://eips.ethereum.org/EIPS/eip-712")

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if not fn.is_public_entry or fn.is_view or fn.body is None:
                continue
            fa = self.analyze(fn, info)
            sigs = _signature_calls(fa)
            if not sigs:
                continue
            text_names = set(identifiers(fn.body)) | {p.name or "" for p in fn.params}
            members = {n.member for n in fn.body.walk() if isinstance(n, A.MemberAccess)}
            all_names = text_names | members
            has_nonce = any(NONCE_RE.search(n) for n in all_names if n)
            writes_used = any(NONCE_RE.search(w.var.name) for w in fa.state_writes)
            has_domain = any(DOMAIN_RE.search(n) for n in all_names if n) or any(is_member(n, "block", "chainid") for n in fn.body.walk())
            has_domain = has_domain or self._inherits_eip712(info)
            if not (has_nonce or writes_used):
                self.report(
                    info.file,
                    sigs[0].node,
                    f"`{fn.signature}` verifies a signature but tracks no nonce or used-signature state; it can be replayed.",
                    contract=info.name,
                    function=fn,
                )
            elif not has_domain:
                self.report(
                    info.file,
                    sigs[0].node,
                    f"Signed message in `{fn.signature}` does not bind `block.chainid`/domain separator (cross-chain replay).",
                    contract=info.name,
                    function=fn,
                    severity=Severity.LOW,
                    title="Cross-chain signature replay",
                )

    @staticmethod
    def _inherits_eip712(info: ContractInfo) -> bool:
        return any("EIP712" in b or "Permit" in b for b in info.all_base_names())


DYNAMIC_TYPES = re.compile(r"^(string|bytes|.*\[\])$")


@register
class EncodePackedCollision(Detector):
    id = "encode-packed-collision"
    title = "Hash collision with abi.encodePacked"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    swc = "SWC-133"
    cwe = "CWE-294"
    description = (
        "`abi.encodePacked` with two or more dynamic-length arguments is "
        'ambiguous: `("a", "bc")` and `("ab", "c")` produce the same '
        "bytes, so the resulting hash can collide (signature or ID forgery)."
    )
    recommendation = "Use `abi.encode`, or ensure at most one dynamic argument is packed."
    references = ("https://swcregistry.io/docs/SWC-133",)

    def check_contract(self, info: ContractInfo) -> None:
        for fn in self.own_functions(info):
            if fn.body is None:
                continue
            fa = self.analyze(fn, info)
            for node in fn.body.walk():
                if not (isinstance(node, A.FunctionCall) and is_member(node.target, "abi", "encodePacked")):
                    continue
                dynamic = [a for a in node.args if self._is_dynamic(fa, a)]
                if len(dynamic) >= 2:
                    parent = fa.parent(node)
                    hashed = isinstance(parent, A.FunctionCall) and is_builtin_call(parent, "keccak256", "sha256")
                    self.report(
                        info.file,
                        node,
                        f"`{render(node, 90)}` packs {len(dynamic)} dynamic values" + (" before hashing." if hashed else "."),
                        contract=info.name,
                        function=fn,
                        severity=Severity.MEDIUM if hashed else Severity.LOW,
                    )

    @staticmethod
    def _is_dynamic(fa: FunctionAnalysis, expr: A.Expression) -> bool:
        if isinstance(expr, A.Literal) and expr.kind == "string":
            return False  # constant literal length is known
        t = fa.type_of(expr)
        return bool(t and DYNAMIC_TYPES.match(t.split()[0]))
