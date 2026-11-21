"""Semantic analysis helpers shared by detectors.

This module turns the raw AST into facts detectors can query cheaply:

* every call site, classified (low-level call, ETH transfer, external call,
  internal call, builtin, ...) together with its call options and context,
* every state-variable write and read, in source order,
* a lightweight intra-procedural taint set seeded from function parameters,
* access-control heuristics (modifiers and in-body ``msg.sender`` guards),
* a pretty-printer that renders expressions back to Solidity-like text.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from functools import cached_property

from . import ast as A
from .project import ContractInfo, Project

# ---------------------------------------------------------------------------
# Pretty printer
# ---------------------------------------------------------------------------

_PREC = {
    "||": 3,
    "&&": 4,
    "==": 5,
    "!=": 5,
    "<": 6,
    ">": 6,
    "<=": 6,
    ">=": 6,
    "|": 7,
    "^": 8,
    "&": 9,
    "<<": 10,
    ">>": 10,
    ">>>": 10,
    "+": 11,
    "-": 11,
    "*": 12,
    "/": 12,
    "%": 12,
    "**": 13,
}


def render(node: A.Node | None, max_len: int = 120) -> str:
    text = _render(node)
    if len(text) > max_len:
        text = text[: max_len - 1] + "..."
    return text


def _render(node: A.Node | None) -> str:  # noqa: C901 - a big switch is clearest here
    if node is None:
        return ""
    if isinstance(node, A.Identifier):
        return node.name
    if isinstance(node, A.Literal):
        if node.kind == "string":
            return f'"{node.value}"'
        if node.kind == "hexstring":
            return f'hex"{node.value}"'
        return node.value + (f" {node.unit}" if node.unit else "")
    if isinstance(node, A.ElementaryTypeExpr):
        return node.type_name
    if isinstance(node, A.TypeNameExpr):
        return f"type({node.type_name})"
    if isinstance(node, A.NewExpr):
        return f"new {node.type_name}"
    if isinstance(node, A.MemberAccess):
        return f"{_render(node.expr)}.{node.member}"
    if isinstance(node, A.IndexAccess):
        return f"{_render(node.base)}[{_render(node.index)}]"
    if isinstance(node, A.IndexRange):
        return f"{_render(node.base)}[{_render(node.start)}:{_render(node.end)}]"
    if isinstance(node, A.CallOptions):
        opts = ", ".join(f"{k}: {_render(v)}" for k, v in node.options.items())
        return f"{_render(node.expr)}{{{opts}}}"
    if isinstance(node, A.FunctionCall):
        if node.names:
            inner = ", ".join(f"{n}: {_render(a)}" for n, a in zip(node.names, node.args))
            return f"{_render(node.callee)}({{{inner}}})"
        return f"{_render(node.callee)}({', '.join(_render(a) for a in node.args)})"
    if isinstance(node, A.UnaryOp):
        if node.prefix:
            sep = " " if node.op == "delete" else ""
            return f"{node.op}{sep}{_render(node.operand)}"
        return f"{_render(node.operand)}{node.op}"
    if isinstance(node, A.BinaryOp):
        prec = _PREC.get(node.op, 0)
        left = _render(node.left)
        right = _render(node.right)
        if isinstance(node.left, (A.BinaryOp, A.Conditional, A.Assignment)) and _PREC.get(getattr(node.left, "op", ""), 0) < prec:
            left = f"({left})"
        if (
            isinstance(node.right, (A.BinaryOp, A.Conditional, A.Assignment))
            and _PREC.get(getattr(node.right, "op", ""), 0) <= prec
            and node.op != "**"
        ):
            right = f"({right})"
        return f"{left} {node.op} {right}"
    if isinstance(node, A.Assignment):
        return f"{_render(node.target)} {node.op} {_render(node.value)}"
    if isinstance(node, A.Conditional):
        return f"{_render(node.cond)} ? {_render(node.true_expr)} : {_render(node.false_expr)}"
    if isinstance(node, A.TupleExpr):
        inner = ", ".join(_render(e) for e in node.elements)
        return f"[{inner}]" if node.is_array else f"({inner})"
    if isinstance(node, A.ExpressionStatement):
        return _render(node.expr) + ";"
    if isinstance(node, A.VariableDeclarationStatement):
        decls = ", ".join("" if d is None else f"{d.type_name}{' ' + d.storage if d.storage else ''} {d.name}" for d in node.declarations)
        if len(node.declarations) > 1:
            decls = f"({decls})"
        return f"{decls}{' = ' + _render(node.value) if node.value else ''};"
    if isinstance(node, A.ReturnStatement):
        return f"return {_render(node.value)};".replace("return ;", "return;")
    if isinstance(node, A.EmitStatement):
        return f"emit {_render(node.call)};"
    if isinstance(node, A.RevertStatement):
        return f"revert {_render(node.call)};"
    return type(node).__name__


# ---------------------------------------------------------------------------
# Expression helpers
# ---------------------------------------------------------------------------


def is_member(expr: A.Node, base: str, member: str) -> bool:
    return isinstance(expr, A.MemberAccess) and expr.member == member and isinstance(expr.expr, A.Identifier) and expr.expr.name == base


def mentions(expr: A.Node | None, base: str, member: str | None = None) -> bool:
    if expr is None:
        return False
    for node in expr.walk():
        if member is None:
            if isinstance(node, A.Identifier) and node.name == base:
                return True
        elif is_member(node, base, member):
            return True
    return False


def mentions_sender(expr: A.Node | None) -> bool:
    if expr is None:
        return False
    for node in expr.walk():
        if is_member(node, "msg", "sender"):
            return True
        if isinstance(node, A.FunctionCall) and isinstance(node.target, A.Identifier) and node.target.name == "_msgSender":
            return True
    return False


def identifiers(expr: A.Node | None) -> Iterator[str]:
    if expr is None:
        return
    for node in expr.walk():
        if isinstance(node, A.Identifier):
            yield node.name


def base_identifier(expr: A.Expression) -> A.Identifier | None:
    """Strip index/member access to find the root variable of an lvalue."""
    while True:
        if isinstance(expr, A.Identifier):
            return expr
        if isinstance(expr, (A.IndexAccess, A.IndexRange)):
            expr = expr.base
        elif isinstance(expr, A.MemberAccess):
            expr = expr.expr
        elif isinstance(expr, A.FunctionCall) and isinstance(expr.target, A.ElementaryTypeExpr):
            # payable(x) / address(x)
            if not expr.args:
                return None
            expr = expr.args[0]
        else:
            return None


def call_name(call: A.FunctionCall) -> str:
    target = call.target
    if isinstance(target, A.Identifier):
        return target.name
    if isinstance(target, A.MemberAccess):
        return target.member
    if isinstance(target, A.ElementaryTypeExpr):
        return target.type_name
    return ""


def is_builtin_call(node: A.Node, *names: str) -> bool:
    return isinstance(node, A.FunctionCall) and isinstance(node.target, A.Identifier) and node.target.name in names


def is_revert_like(stmt: A.Statement | None) -> bool:
    """Does the statement unconditionally abort execution?"""
    if stmt is None:
        return False
    if isinstance(stmt, (A.RevertStatement, A.ThrowStatement)):
        return True
    if isinstance(stmt, A.ExpressionStatement) and is_builtin_call(stmt.expr, "revert"):
        return True
    if isinstance(stmt, A.Block) and stmt.statements:
        return is_revert_like(stmt.statements[-1])
    return False


def int_literal(expr: A.Node | None) -> int | None:
    if isinstance(expr, A.Literal) and expr.kind in ("number", "hex"):
        try:
            return int(expr.value.replace("_", ""), 0)
        except ValueError:
            try:
                return int(float(expr.value))
            except ValueError:
                return None
    return None


# ---------------------------------------------------------------------------
# Call classification
# ---------------------------------------------------------------------------


class CallKind(str, Enum):
    LOW_LEVEL_CALL = "call"
    DELEGATECALL = "delegatecall"
    STATICCALL = "staticcall"
    CALLCODE = "callcode"
    SEND = "send"
    TRANSFER = "transfer"  # address.transfer(amount)
    SEND_VALUE = "sendValue"  # OZ Address.sendValue
    EXTERNAL = "external"
    INTERNAL = "internal"
    LIBRARY = "library"
    BUILTIN = "builtin"
    SELFDESTRUCT = "selfdestruct"
    CREATE = "create"
    CONVERSION = "conversion"
    OPTION = "option"  # legacy .value()/.gas() modifiers

    @property
    def sends_eth_capable(self) -> bool:
        return self in (
            CallKind.LOW_LEVEL_CALL,
            CallKind.SEND,
            CallKind.TRANSFER,
            CallKind.SEND_VALUE,
            CallKind.EXTERNAL,
            CallKind.CALLCODE,
        )

    @property
    def is_external(self) -> bool:
        return self in (
            CallKind.LOW_LEVEL_CALL,
            CallKind.DELEGATECALL,
            CallKind.STATICCALL,
            CallKind.CALLCODE,
            CallKind.SEND,
            CallKind.TRANSFER,
            CallKind.SEND_VALUE,
            CallKind.EXTERNAL,
        )

    @property
    def is_low_level(self) -> bool:
        return self in (CallKind.LOW_LEVEL_CALL, CallKind.DELEGATECALL, CallKind.STATICCALL, CallKind.CALLCODE, CallKind.SEND)


BUILTIN_FUNCTIONS = {
    "require",
    "assert",
    "revert",
    "keccak256",
    "sha256",
    "sha3",
    "ripemd160",
    "ecrecover",
    "addmod",
    "mulmod",
    "blockhash",
    "gasleft",
    "selfdestruct",
    "suicide",
    "type",
}
BUILTIN_NAMESPACES = {"abi", "msg", "block", "tx", "string", "bytes", "Math", "SafeCast", "Strings"}
ARRAY_MEMBERS = {"push", "pop", "concat"}
LOW_LEVEL = {
    "call": CallKind.LOW_LEVEL_CALL,
    "delegatecall": CallKind.DELEGATECALL,
    "staticcall": CallKind.STATICCALL,
    "callcode": CallKind.CALLCODE,
}
# Library helpers (OpenZeppelin & co) that perform external calls internally.
EXTERNAL_LIBRARY_FUNCTIONS = {
    "safeTransfer",
    "safeTransferFrom",
    "safeApprove",
    "safeIncreaseAllowance",
    "safeDecreaseAllowance",
    "forceApprove",
    "functionCall",
    "functionCallWithValue",
    "functionStaticCall",
    "functionDelegateCall",
    "safePermit",
    "safeTransferETH",
}
PURE_LIBRARY_HINTS = {
    "add",
    "sub",
    "mul",
    "div",
    "mod",
    "tryAdd",
    "trySub",
    "tryMul",
    "tryDiv",
    "toString",
    "toHexString",
    "toUint256",
    "toInt256",
    "toUint128",
    "toUint64",
    "toUint32",
    "toEthSignedMessageHash",
    "recover",
    "tryRecover",
    "contains",
    "length",
    "at",
    "values",
    "remove",
    "set",
    "get",
    "max",
    "min",
    "average",
    "mulDiv",
    "sqrt",
    "log2",
    "isContract",
    "verify",
    "processProof",
    "wadMul",
    "wadDiv",
    "rayMul",
    "rayDiv",
    "percentMul",
    "percentDiv",
}


@dataclass(eq=False)
class CallSite:
    node: A.FunctionCall
    kind: CallKind
    name: str
    receiver: A.Expression | None
    value: A.Expression | None = None
    gas: A.Expression | None = None
    in_loop: bool = False
    in_unchecked: bool = False
    confidence: str = "high"
    resolved: A.FunctionDef | None = None

    @property
    def loc(self) -> A.Loc:
        return self.node.loc

    @property
    def sends_value(self) -> bool:
        if self.kind in (CallKind.SEND, CallKind.TRANSFER, CallKind.SEND_VALUE):
            return True
        if self.value is None:
            return False
        return int_literal(self.value) != 0


@dataclass(eq=False)
class StateWrite:
    node: A.Node
    var: A.StateVariable
    loc: A.Loc
    in_loop: bool = False


@dataclass
class _VarInfo:
    type_name: str
    storage: str | None
    is_param: bool
    alias_of: str | None = None  # storage pointer to state var


class FunctionAnalysis:
    """Facts about a single function (or modifier) body."""

    def __init__(self, fn: A.FunctionDef, info: ContractInfo, project: Project) -> None:
        self.fn = fn
        self.info = info
        self.project = project
        self.parents: dict[int, A.Node] = {}
        self.locals: dict[str, _VarInfo] = {}
        self.calls: list[CallSite] = []
        self.state_writes: list[StateWrite] = []
        self.state_reads: list[tuple[A.Identifier, A.StateVariable]] = []
        self.loops: list[A.Statement] = []
        self.statements: list[A.Statement] = []
        self.conditions: list[A.Expression] = []  # require/assert/if/while conditions
        self.emits: list[A.EmitStatement] = []
        self.assembly: list[A.AssemblyStatement] = []
        self._state_vars = {v.name: v for v in info.all_state_vars()}

        for p in fn.params:
            if p.name:
                self.locals[p.name] = _VarInfo(p.type_name, p.storage, True)
        for p in fn.returns:
            if p.name:
                self.locals[p.name] = _VarInfo(p.type_name, p.storage, False)
        if fn.body is not None:
            self._visit(fn.body, None, loop_depth=0, unchecked=False)
        self.calls.sort(key=lambda c: (c.loc.line, c.loc.col))
        self.state_writes.sort(key=lambda w: (w.loc.line, w.loc.col))

    # ------------------------------------------------------------------
    def _visit(self, node: A.Node, parent: A.Node | None, loop_depth: int, unchecked: bool) -> None:
        if parent is not None:
            self.parents[id(node)] = parent
        in_loop = loop_depth > 0

        if isinstance(node, A.Statement):
            self.statements.append(node)
        if isinstance(node, A.Block) and node.unchecked:
            unchecked = True
        if isinstance(node, (A.ForStatement, A.WhileStatement, A.DoWhileStatement)):
            self.loops.append(node)
            loop_cond = getattr(node, "cond", None)
            if loop_cond is not None:
                self.conditions.append(loop_cond)
        if isinstance(node, A.IfStatement):
            self.conditions.append(node.cond)
        if isinstance(node, A.EmitStatement):
            self.emits.append(node)
        if isinstance(node, A.AssemblyStatement):
            self.assembly.append(node)

        if isinstance(node, A.VariableDeclarationStatement):
            for decl in node.declarations:
                if decl is None or not decl.name:
                    continue
                alias = None
                if decl.storage == "storage" and node.value is not None and len(node.declarations) == 1:
                    root = base_identifier(node.value)
                    if root is not None:
                        alias = self._resolve_state_name(root.name)
                self.locals[decl.name] = _VarInfo(decl.type_name, decl.storage, False, alias)
        elif isinstance(node, A.FunctionCall):
            self._record_call(node, in_loop, unchecked)
        elif isinstance(node, A.Assignment):
            for target in self._lvalues(node.target):
                self._record_write(target, node, in_loop)
        elif isinstance(node, A.UnaryOp) and node.op in ("++", "--", "delete"):
            self._record_write(node.operand, node, in_loop)
        elif isinstance(node, A.Identifier):
            var = self.state_var_for(node.name)
            if var is not None:
                self.state_reads.append((node, var))

        child_loop = loop_depth
        if isinstance(node, (A.ForStatement, A.WhileStatement, A.DoWhileStatement)):
            child_loop += 1
        for child in node.children():
            self._visit(child, node, child_loop, unchecked)

    def _lvalues(self, target: A.Expression) -> list[A.Expression]:
        if isinstance(target, A.TupleExpr):
            return [e for e in target.elements if e is not None]
        return [target]

    def _resolve_state_name(self, name: str) -> str | None:
        info = self.locals.get(name)
        if info is not None:
            return info.alias_of
        return name if name in self._state_vars else None

    def state_var_for(self, name: str) -> A.StateVariable | None:
        """Resolve an identifier to a state variable, honouring local shadowing."""
        if name in self.locals:
            alias = self.locals[name].alias_of
            return self._state_vars.get(alias) if alias else None
        return self._state_vars.get(name)

    def _record_write(self, target: A.Expression, node: A.Node, in_loop: bool) -> None:
        root = base_identifier(target)
        if root is None:
            return
        var = self.state_var_for(root.name)
        if var is not None:
            self.state_writes.append(StateWrite(node, var, node.loc, in_loop))

    # ------------------------------------------------------------------
    def _record_call(self, call: A.FunctionCall, in_loop: bool, unchecked: bool) -> None:
        site = self.classify(call)
        site.in_loop = in_loop
        site.in_unchecked = unchecked
        self.calls.append(site)
        # Array push/pop on state arrays are writes.
        target = call.target
        if isinstance(target, A.MemberAccess) and target.member in ("push", "pop"):
            self._record_write(target.expr, call, in_loop)

    def type_of(self, expr: A.Expression) -> str | None:
        """Best-effort static type of an expression (as source text)."""
        if isinstance(expr, A.Identifier):
            if expr.name in self.locals:
                return self.locals[expr.name].type_name
            var = self._state_vars.get(expr.name)
            if var is not None:
                return var.type_name
            if expr.name == "this":
                return self.info.name
            return None
        if isinstance(expr, A.FunctionCall):
            target = expr.target
            if isinstance(target, A.ElementaryTypeExpr):
                return "address" if target.type_name in ("payable", "address payable") else target.type_name
            if isinstance(target, A.Identifier) and (self.project.lookup(target.name) or _looks_like_type(target.name)):
                if len(expr.args) == 1 and not self._is_function_name(target.name):
                    return target.name
            if isinstance(target, A.Identifier):
                fns = self.info.functions_named(target.name)
                if fns and len(fns[0].returns) == 1:
                    return fns[0].returns[0].type_name
        if isinstance(expr, A.IndexAccess):
            base_type = self.type_of(expr.base)
            if base_type:
                return _element_type(base_type)
        if isinstance(expr, A.BinaryOp) and expr.op in ("+", "-", "*", "/", "%", "**", "&", "|", "^", "<<", ">>"):
            return self.type_of(expr.left) or self.type_of(expr.right)
        if isinstance(expr, A.TupleExpr) and len(expr.elements) == 1 and expr.elements[0] is not None:
            return self.type_of(expr.elements[0])
        if isinstance(expr, A.MemberAccess):
            base_type = self.type_of(expr.expr)
            if base_type:
                member_type = self._struct_member_type(base_type, expr.member)
                if member_type:
                    return member_type
            if expr.member == "length":
                return "uint256"
            if is_member(expr, "msg", "value") or is_member(expr, "block", "timestamp") or is_member(expr, "block", "number"):
                return "uint256"
            if is_member(expr, "msg", "sender") or is_member(expr, "tx", "origin"):
                return "address"
            if is_member(expr, "block", "coinbase"):
                return "address"
        return None

    def _struct_member_type(self, struct_type: str, member: str) -> str | None:
        short = struct_type.split()[0].split(".")[-1]
        for c in self.info.linearization:
            for st in c.contract.structs:
                if st.name == short:
                    for m in st.members:
                        if m.name == member:
                            return m.type_name
        for infos in self.project.contracts.values():
            for c in infos:
                for st in c.contract.structs:
                    if st.name == short:
                        for m in st.members:
                            if m.name == member:
                                return m.type_name
        return None

    def _is_function_name(self, name: str) -> bool:
        return bool(self.info.functions_named(name))

    def classify(self, call: A.FunctionCall) -> CallSite:
        target = call.target
        opts = call.options
        value = opts.get("value")
        gas = opts.get("gas")

        # Legacy: addr.call.value(x)(data) / addr.call.gas(g).value(v)(data)
        inner = target
        while isinstance(inner, A.FunctionCall) and isinstance(inner.target, A.MemberAccess) and inner.target.member in ("value", "gas"):
            if inner.target.member == "value" and inner.args:
                value = inner.args[0]
            elif inner.args:
                gas = inner.args[0]
            inner = inner.target.expr
        if inner is not target:
            target = inner

        if isinstance(target, A.MemberAccess):
            member = target.member
            receiver = target.expr
            if member in ("value", "gas") and isinstance(receiver, A.MemberAccess) and receiver.member in LOW_LEVEL:
                return CallSite(call, CallKind.OPTION, member, receiver)
            if member in LOW_LEVEL:
                return CallSite(call, LOW_LEVEL[member], member, receiver, value, gas)
            if member == "send" and len(call.args) == 1:
                return CallSite(call, CallKind.SEND, member, receiver, call.args[0])
            if member == "transfer" and len(call.args) == 1:
                rtype = self.type_of(receiver)
                if rtype is None or rtype.startswith("address") or isinstance(receiver, A.FunctionCall):
                    return CallSite(call, CallKind.TRANSFER, member, receiver, call.args[0])
            if member == "sendValue" and len(call.args) == 2:
                return CallSite(call, CallKind.SEND_VALUE, member, call.args[0], call.args[1])
            if member in EXTERNAL_LIBRARY_FUNCTIONS:
                if member == "functionCallWithValue" and value is None and len(call.args) >= 2:
                    lib_form = isinstance(receiver, A.Identifier) and receiver.name == "Address"
                    value = call.args[2] if lib_form and len(call.args) >= 3 else call.args[1]
                if member == "safeTransferETH" and len(call.args) >= 2:
                    value = call.args[1]
                return CallSite(call, CallKind.EXTERNAL, member, receiver, value, gas)
            if isinstance(receiver, A.Identifier):
                rname = receiver.name
                if rname in BUILTIN_NAMESPACES and rname not in self.locals:
                    return CallSite(call, CallKind.BUILTIN, member, receiver)
                if rname == "super":
                    resolved = self._resolve_internal(member, skip_self=True)
                    return CallSite(call, CallKind.INTERNAL, member, None, resolved=resolved)
                if rname == "this":
                    return CallSite(call, CallKind.EXTERNAL, member, receiver, value, gas, confidence="medium")
                if self.project.is_library(rname) and rname not in self.locals:
                    return CallSite(call, CallKind.LIBRARY, member, receiver)
                if rname not in self.locals and rname not in self._state_vars and self.project.lookup(rname):
                    # Contract.staticFunctionSelector or similar.
                    return CallSite(call, CallKind.BUILTIN, member, receiver)
            if isinstance(receiver, (A.ElementaryTypeExpr, A.TypeNameExpr)):
                return CallSite(call, CallKind.BUILTIN, member, receiver)
            if member in ARRAY_MEMBERS:
                return CallSite(call, CallKind.BUILTIN, member, receiver)

            rtype = self.type_of(receiver)
            if rtype is not None:
                base = rtype.split()[0]
                if "." in base and not base.endswith("]"):
                    # Nested type such as `EnumerableSet.AddressSet` or
                    # `Checkpoints.Trace208`: a struct/UDVT used with a library.
                    return CallSite(call, CallKind.LIBRARY, member, receiver)
                if base.startswith("address"):
                    # A non-builtin member on an address only compiles through
                    # a ``using X for address`` library.
                    return CallSite(call, CallKind.LIBRARY, member, receiver)
                if _is_value_type(base) or base.startswith("mapping") or base.endswith("]"):
                    return CallSite(call, CallKind.LIBRARY, member, receiver)
                if self.project.is_library(base):
                    return CallSite(call, CallKind.LIBRARY, member, receiver)
                lookup = self.project.lookup(base)
                if lookup is not None and lookup.kind in ("contract", "interface", "abstract"):
                    return CallSite(call, CallKind.EXTERNAL, member, receiver, value, gas)
                if lookup is not None:  # struct-typed or library-typed
                    return CallSite(call, CallKind.LIBRARY, member, receiver)
                if _looks_like_type(base):
                    # Unknown user type (import not provided): most likely an
                    # interface / contract.
                    return CallSite(call, CallKind.EXTERNAL, member, receiver, value, gas, confidence="medium")
            if member in PURE_LIBRARY_HINTS:
                return CallSite(call, CallKind.LIBRARY, member, receiver, confidence="low")
            return CallSite(call, CallKind.EXTERNAL, member, receiver, value, gas, confidence="low")

        if isinstance(target, A.Identifier):
            name = target.name
            if name in ("selfdestruct", "suicide"):
                return CallSite(call, CallKind.SELFDESTRUCT, name, None)
            if name in BUILTIN_FUNCTIONS and name not in self.locals:
                return CallSite(call, CallKind.BUILTIN, name, None)
            resolved = self._resolve_internal(name)
            if resolved is not None:
                return CallSite(call, CallKind.INTERNAL, name, None, resolved=resolved)
            if self.project.lookup(name) or _looks_like_type(name):
                return CallSite(call, CallKind.CONVERSION, name, None)
            if name in self.locals:  # function-typed variable
                return CallSite(call, CallKind.EXTERNAL, name, None, confidence="low")
            return CallSite(call, CallKind.INTERNAL, name, None, confidence="low")

        if isinstance(target, A.NewExpr):
            return CallSite(call, CallKind.CREATE, target.type_name, None, value)
        if isinstance(target, A.ElementaryTypeExpr):
            return CallSite(call, CallKind.CONVERSION, target.type_name, None)
        return CallSite(call, CallKind.BUILTIN, call_name(call), None, confidence="low")

    def _resolve_internal(self, name: str, skip_self: bool = False) -> A.FunctionDef | None:
        lin = self.info.linearization[1:] if skip_self else self.info.linearization
        for info in lin:
            for fn in info.contract.functions:
                if fn.name == name:
                    return fn
        for sf in self.project.files:
            for fn in sf.unit.free_functions:
                if fn.name == name:
                    return fn
        return None

    # ------------------------------------------------------------------
    # Derived facts
    # ------------------------------------------------------------------
    def parent(self, node: A.Node) -> A.Node | None:
        return self.parents.get(id(node))

    def enclosing_statement(self, node: A.Node) -> A.Statement | None:
        cur: A.Node | None = node
        while cur is not None and not isinstance(cur, A.Statement):
            cur = self.parent(cur)
        return cur

    def ancestors(self, node: A.Node) -> Iterator[A.Node]:
        cur = self.parent(node)
        while cur is not None:
            yield cur
            cur = self.parent(cur)

    def is_in_condition(self, node: A.Node) -> bool:
        """Is ``node`` part of a require/assert/if/loop condition or ternary test?"""
        child = node
        for anc in self.ancestors(node):
            if isinstance(anc, A.FunctionCall) and is_builtin_call(anc, "require", "assert"):
                return bool(anc.args) and child is anc.args[0]
            if isinstance(anc, (A.IfStatement, A.WhileStatement, A.DoWhileStatement)):
                return child is anc.cond
            if isinstance(anc, A.ForStatement):
                return child is anc.cond
            if isinstance(anc, A.Conditional):
                return child is anc.cond
            if isinstance(anc, A.Statement):
                return False
            child = anc
        return False

    def result_is_used(self, call: A.FunctionCall) -> bool:
        """Is the return value of ``call`` consumed and *checked*?"""
        parent = self.parent(call)
        # Unwrap trivial wrappers
        while isinstance(parent, A.MemberAccess) or (isinstance(parent, A.TupleExpr) and len(parent.elements) == 1):
            parent = self.parent(parent)
        if parent is None or isinstance(parent, A.ExpressionStatement):
            return False
        if isinstance(parent, A.VariableDeclarationStatement):
            first = parent.declarations[0] if parent.declarations else None
            if first is None or not first.name:
                return False
            return self._name_checked_later(first.name, parent)
        if isinstance(parent, A.Assignment):
            target: A.Expression | None = parent.target
            if isinstance(target, A.TupleExpr):
                target = target.elements[0] if target.elements else None
            if isinstance(target, A.Identifier):
                return self._name_checked_later(target.name, parent)
            return True
        return True

    def _name_checked_later(self, name: str, after: A.Node) -> bool:
        line = after.loc.line
        for cond in self.conditions:
            if cond.loc.line >= line and name in set(identifiers(cond)):
                return True
        for call in self.calls:
            if (
                call.loc.line >= line
                and call.name in ("require", "assert")
                and call.node.args
                and name in set(identifiers(call.node.args[0]))
            ):
                return True
            if (
                call.loc.line >= line
                and call.kind in (CallKind.INTERNAL, CallKind.LIBRARY, CallKind.BUILTIN, CallKind.EXTERNAL)
                and call.name not in ("require", "assert")
                and any(name in set(identifiers(a)) for a in call.node.args)
            ):
                return True  # passed to a helper such as Address.verifyCallResult
        for stmt in self.statements:
            if isinstance(stmt, A.ReturnStatement) and stmt.loc.line >= line and name in set(identifiers(stmt.value)):
                return True
        return False

    # -- taint ----------------------------------------------------------
    @cached_property
    def tainted(self) -> set[str]:
        """Local names whose *value* may be chosen by the caller.

        Propagation follows value flow only: ``x = param`` or ``(a, b) =
        abi.decode(param, ...)`` taints the left-hand side, whereas a storage
        lookup keyed by a parameter (``s_jobs[id]``) does not - the caller picks
        the key, not the stored value.
        """
        tainted = {p.name for p in self.fn.params if p.name}
        changed = True
        while changed:
            changed = False
            for stmt in self.statements:
                if isinstance(stmt, A.VariableDeclarationStatement) and stmt.value is not None:
                    if self.expr_controlled(stmt.value, tainted):
                        for d in stmt.declarations:
                            if d and d.name and d.name not in tainted:
                                tainted.add(d.name)
                                changed = True
            for node in self.fn.body.walk() if self.fn.body else []:
                if isinstance(node, A.Assignment) and isinstance(node.target, A.Identifier):
                    tname = node.target.name
                    if tname in self.locals and tname not in tainted and self.expr_controlled(node.value, tainted):
                        tainted.add(tname)
                        changed = True
        return tainted

    def expr_controlled(self, expr: A.Node | None, tainted: set[str] | None = None) -> bool:
        """Can the caller choose the value of ``expr``?"""
        if expr is None:
            return False
        names = self.tainted if tainted is None else tainted
        if isinstance(expr, A.Identifier):
            return expr.name in names
        if is_member(expr, "msg", "data"):
            return True
        if isinstance(expr, A.IndexAccess):
            if isinstance(expr.base, A.Identifier) and self.state_var_for(expr.base.name) is not None:
                return False  # storage lookup: caller picks the key, not the value
            return self.expr_controlled(expr.base, names)
        if isinstance(expr, A.IndexRange):
            return self.expr_controlled(expr.base, names)
        if isinstance(expr, A.MemberAccess):
            return self.expr_controlled(expr.expr, names)
        if isinstance(expr, A.FunctionCall):
            target = expr.target
            if isinstance(target, A.ElementaryTypeExpr) or (
                isinstance(target, A.Identifier)
                and len(expr.args) == 1
                and (self.project.lookup(target.name) or _looks_like_type(target.name))
                and not self._is_function_name(target.name)
            ):
                return any(self.expr_controlled(a, names) for a in expr.args)  # conversions
            if is_member(target, "abi", "decode") and expr.args:
                return self.expr_controlled(expr.args[0], names)
            if isinstance(target, A.MemberAccess) and target.member in ("decode", "slice", "concat"):
                return any(self.expr_controlled(a, names) for a in expr.args)
            return False
        if isinstance(expr, (A.BinaryOp,)):
            return self.expr_controlled(expr.left, names) or self.expr_controlled(expr.right, names)
        if isinstance(expr, A.Conditional):
            return self.expr_controlled(expr.true_expr, names) or self.expr_controlled(expr.false_expr, names)
        if isinstance(expr, A.TupleExpr):
            return any(self.expr_controlled(e, names) for e in expr.elements if e is not None)
        if isinstance(expr, A.CallOptions):
            return self.expr_controlled(expr.expr, names)
        return False

    def expr_tainted(self, expr: A.Node | None, tainted: set[str] | None = None) -> bool:
        """Loose check: does ``expr`` *mention* any caller-influenced name?"""
        if expr is None:
            return False
        names = self.tainted if tainted is None else tainted
        for node in expr.walk():
            if isinstance(node, A.Identifier) and node.name in names:
                return True
            if is_member(node, "msg", "data"):
                return True
        return False

    # -- access control -------------------------------------------------
    @cached_property
    def access_control(self) -> str | None:
        """Return a description of the guard protecting this function, if any."""
        return access_control_guard(self.fn, self.info, self.project)

    @property
    def is_protected(self) -> bool:
        return self.access_control is not None

    @cached_property
    def external_calls(self) -> list[CallSite]:
        return [c for c in self.calls if c.kind.is_external]

    def internal_callees(self) -> list[A.FunctionDef]:
        return [c.resolved for c in self.calls if c.kind is CallKind.INTERNAL and c.resolved is not None]


ACCESS_MODIFIER_RE = re.compile(
    r"(only|auth|admin|owner|role|governance|governor|guardian|restricted|keeper|operator|minter|manager|whitelist|allowlist|controller|requiresAuth|isAuthorized|ownerOrApproved)",
    re.IGNORECASE,
)
ACCESS_CALL_RE = re.compile(
    r"^_?(check(Owner|Role|Admin|Auth|Caller|Sender|Permission|Authorized|OnlyOwner)\w*|onlyOwner|only\w+|requireAuth\w*|_?authorize\w*|_?require(Owner|Admin|Role|Auth|Caller|Sender|Governance|Authorized|OnlyOwner|Sender)\w*|enforce\w*Owner|assertOwner|isOwner|hasRole|_validateCaller|_checkAccess)$",
)


def _guard_in_body(body: A.Block | None, info: ContractInfo, project: Project, depth: int = 0) -> str | None:
    if body is None or depth > 2:
        return None
    for node in body.walk():
        if isinstance(node, A.FunctionCall):
            name = call_name(node)
            if is_builtin_call(node, "require", "assert") and node.args and _is_sender_check(node.args[0]):
                return f"{name}({render(node.args[0], 60)})"
            bare = (name or "").lstrip("_")
            if ACCESS_CALL_RE.match(name or ""):
                if any(mentions_sender(a) for a in node.args) or bare.startswith(
                    ("check", "only", "require", "authorize", "enforce", "assert", "validate")
                ):
                    return f"{name}(...)"
            if bare.startswith(("check", "only", "require", "authorize", "auth", "validate", "enforce", "assert")) and any(
                _is_bare_sender(a) for a in node.args
            ):
                return f"{name}(msg.sender)"
            if depth < 2:
                candidates: list[A.FunctionDef] = []
                if isinstance(node.target, A.Identifier):
                    candidates = [fn for fn in info.functions_named(name) if fn.visibility in ("internal", "private")]
                elif (
                    isinstance(node.target, A.MemberAccess)
                    and isinstance(node.target.expr, A.Identifier)
                    and node.target.expr.name == "super"
                ):
                    candidates = [fn for base in info.linearization[1:] for fn in base.contract.functions if fn.name == name]
                for fn in candidates:
                    inner = _guard_in_body(fn.body, info, project, depth + 1)
                    if inner:
                        return f"{name}() → {inner}"
        elif isinstance(node, A.IfStatement):
            if _is_sender_check(node.cond) and (is_revert_like(node.then) or _returns_early(node.then)):
                return f"if ({render(node.cond, 60)}) revert"
            if _is_sender_check(node.cond):
                return f"if ({render(node.cond, 60)})"
    return None


def _returns_early(stmt: A.Statement | None) -> bool:
    if isinstance(stmt, A.ReturnStatement):
        return True
    if isinstance(stmt, A.Block) and stmt.statements:
        return isinstance(stmt.statements[-1], A.ReturnStatement)
    return False


ACCESS_MAPPING_RE = re.compile(
    r"(admin|owner|auth|whitelist|allowlist|role|operator|minter|trusted|allowed|approved|guardian|keeper|manager|governor|controller|isAdmin|wards|members?)",
    re.IGNORECASE,
)
ACCESS_PREDICATE_RE = re.compile(
    r"^_?(hasRole|hasAnyRole|isOwner|isAuthorized|isAdmin|isOperator|isWhitelisted|isAllowed|isTrusted|canCall|isApprovedOrOwner|isApprovedForAll|_isApprovedOrOwner|isGuardian|isKeeper|isMinter|isManager|isMember|isController|auth\w*|check\w*)$"
)


def _is_sender_check(cond: A.Expression) -> bool:
    """Does ``cond`` restrict *who* may call (as opposed to *what* they own)?"""
    if not (mentions_sender(cond) or mentions(cond, "tx", "origin")):
        return False
    for node in cond.walk():
        if isinstance(node, A.BinaryOp) and node.op in ("==", "!="):
            # msg.sender == owner (but not balances[msg.sender] == x)
            for side, other in ((node.left, node.right), (node.right, node.left)):
                if _is_bare_sender(side) and not _is_bare_sender(other):
                    return True
        if isinstance(node, A.IndexAccess) and node.index is not None and _is_bare_sender(node.index):
            root = base_identifier(node)
            if root is not None and ACCESS_MAPPING_RE.search(root.name):
                return True  # isAdmin[msg.sender], wards[msg.sender] == 1
        if isinstance(node, A.FunctionCall) and any(_is_bare_sender(a) for a in node.args):
            if ACCESS_PREDICATE_RE.match(call_name(node) or ""):
                return True  # hasRole(ROLE, msg.sender)
    return False


def _is_bare_sender(expr: A.Node | None) -> bool:
    if expr is None:
        return False
    if is_member(expr, "msg", "sender") or is_member(expr, "tx", "origin"):
        return True
    if isinstance(expr, A.FunctionCall):
        name = call_name(expr)
        if name == "_msgSender":
            return True
        if isinstance(expr.target, A.ElementaryTypeExpr) and len(expr.args) == 1:
            return _is_bare_sender(expr.args[0])  # address(msg.sender)
    return False


def access_control_guard(fn: A.FunctionDef, info: ContractInfo, project: Project) -> str | None:
    for inv in fn.modifiers:
        mod = info.modifier(inv.name)
        if mod is not None:
            guard = _guard_in_body(mod.body, info, project)
            if guard:
                return f"modifier {inv.name}"
            if ACCESS_MODIFIER_RE.search(inv.name) and any(mentions_sender(a) for a in inv.args):
                return f"modifier {inv.name}"
            if re.match(r"^only[A-Z_]", inv.name) and mod.body is not None and any(isinstance(n, A.FunctionCall) for n in mod.body.walk()):
                return f"modifier {inv.name}"  # conventional name delegating to a helper we cannot resolve
        elif ACCESS_MODIFIER_RE.search(inv.name):
            # Inherited from a contract that is not part of the scan (e.g.
            # OpenZeppelin's Ownable): trust the conventional name.
            return f"modifier {inv.name}"
    guard = _guard_in_body(fn.body, info, project)
    if guard:
        return guard
    return None


_VALUE_TYPE_RE = re.compile(r"^(u?int\d*|bytes\d+|byte|bool|address|u?fixed\S*|string|bytes)$")


def _is_value_type(type_name: str) -> bool:
    return bool(_VALUE_TYPE_RE.match(type_name))


def _looks_like_type(name: str) -> bool:
    return bool(name) and name[0].isupper() and not name.isupper()


def _element_type(type_name: str) -> str | None:
    type_name = type_name.strip()
    if type_name.startswith("mapping("):
        depth = 0
        for i, ch in enumerate(type_name):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "=" and type_name[i : i + 2] == "=>" and depth == 1:
                return type_name[i + 2 : -1].strip()
        return None
    if type_name.endswith("]"):
        return type_name[: type_name.rfind("[")]
    return None


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


@dataclass
class AnalysisCache:
    project: Project
    _cache: dict[tuple[int, int], FunctionAnalysis] = field(default_factory=dict)

    def get(self, fn: A.FunctionDef, info: ContractInfo) -> FunctionAnalysis:
        key = (id(fn), id(info))
        if key not in self._cache:
            self._cache[key] = FunctionAnalysis(fn, info, self.project)
        return self._cache[key]
