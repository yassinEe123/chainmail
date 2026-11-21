"""AST node definitions for the Chainmail Solidity front-end.

The tree is intentionally simpler than ``solc``'s compact JSON AST: it keeps
exactly the information vulnerability detectors need (structure, types as
text, call shapes, data-flow-relevant expressions) while remaining easy to
construct from a tolerant recursive-descent parser.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field


@dataclass(slots=True)
class Loc:
    line: int
    col: int
    end_line: int = 0

    def __str__(self) -> str:
        return f"{self.line}:{self.col}"


@dataclass(eq=False)
class Node:
    loc: Loc

    def children(self) -> Iterator[Node]:
        """Yield direct child nodes (generic, reflection-based)."""
        for name in getattr(self, "__dataclass_fields__", {}):
            if name in ("loc", "parent"):
                continue
            value = getattr(self, name)
            if isinstance(value, Node):
                yield value
            elif isinstance(value, (list, tuple)):
                for item in value:
                    if isinstance(item, Node):
                        yield item
                    elif isinstance(item, tuple):
                        for sub in item:
                            if isinstance(sub, Node):
                                yield sub
            elif isinstance(value, dict):
                for item in value.values():
                    if isinstance(item, Node):
                        yield item

    def walk(self) -> Iterator[Node]:
        """Depth-first pre-order traversal including ``self``."""
        stack: list[Node] = [self]
        while stack:
            node = stack.pop()
            yield node
            kids = list(node.children())
            stack.extend(reversed(kids))


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------
@dataclass(eq=False)
class Expression(Node):
    pass


@dataclass(eq=False)
class Identifier(Expression):
    name: str


@dataclass(eq=False)
class Literal(Expression):
    value: str
    kind: str  # number | hex | string | bool | hexstring | unicode
    unit: str | None = None


@dataclass(eq=False)
class ElementaryTypeExpr(Expression):
    """A type used in expression position, e.g. ``address(x)`` or ``uint256(y)``."""

    type_name: str


@dataclass(eq=False)
class MemberAccess(Expression):
    expr: Expression
    member: str


@dataclass(eq=False)
class IndexAccess(Expression):
    base: Expression
    index: Expression | None


@dataclass(eq=False)
class IndexRange(Expression):
    base: Expression
    start: Expression | None
    end: Expression | None


@dataclass(eq=False)
class CallOptions(Expression):
    """``target{value: x, gas: y}`` - options applied before a call."""

    expr: Expression
    options: dict[str, Expression]


@dataclass(eq=False)
class FunctionCall(Expression):
    callee: Expression
    args: list[Expression]
    names: list[str] = field(default_factory=list)  # named arguments, if any

    @property
    def options(self) -> dict[str, Expression]:
        return self.callee.options if isinstance(self.callee, CallOptions) else {}

    @property
    def target(self) -> Expression:
        """Callee with call options stripped."""
        return self.callee.expr if isinstance(self.callee, CallOptions) else self.callee


@dataclass(eq=False)
class UnaryOp(Expression):
    op: str
    operand: Expression
    prefix: bool = True


@dataclass(eq=False)
class BinaryOp(Expression):
    op: str
    left: Expression
    right: Expression


@dataclass(eq=False)
class Assignment(Expression):
    op: str  # '=', '+=', ...
    target: Expression
    value: Expression


@dataclass(eq=False)
class Conditional(Expression):
    cond: Expression
    true_expr: Expression
    false_expr: Expression


@dataclass(eq=False)
class TupleExpr(Expression):
    elements: list[Expression | None]
    is_array: bool = False


@dataclass(eq=False)
class NewExpr(Expression):
    type_name: str


@dataclass(eq=False)
class TypeNameExpr(Expression):
    """``type(X)`` or a parenthesised type in an expression."""

    type_name: str


# ---------------------------------------------------------------------------
# Statements
# ---------------------------------------------------------------------------
@dataclass(eq=False)
class Statement(Node):
    pass


@dataclass(eq=False)
class Block(Statement):
    statements: list[Statement]
    unchecked: bool = False


@dataclass(eq=False)
class ExpressionStatement(Statement):
    expr: Expression


@dataclass(eq=False)
class VariableDeclaration(Node):
    type_name: str
    name: str | None
    storage: str | None = None  # memory | storage | calldata
    indexed: bool = False


@dataclass(eq=False)
class VariableDeclarationStatement(Statement):
    declarations: list[VariableDeclaration | None]
    value: Expression | None


@dataclass(eq=False)
class IfStatement(Statement):
    cond: Expression
    then: Statement
    orelse: Statement | None


@dataclass(eq=False)
class ForStatement(Statement):
    init: Statement | None
    cond: Expression | None
    post: Expression | None
    body: Statement


@dataclass(eq=False)
class WhileStatement(Statement):
    cond: Expression
    body: Statement


@dataclass(eq=False)
class DoWhileStatement(Statement):
    body: Statement
    cond: Expression


@dataclass(eq=False)
class ReturnStatement(Statement):
    value: Expression | None


@dataclass(eq=False)
class EmitStatement(Statement):
    call: Expression


@dataclass(eq=False)
class RevertStatement(Statement):
    call: Expression


@dataclass(eq=False)
class BreakStatement(Statement):
    pass


@dataclass(eq=False)
class ContinueStatement(Statement):
    pass


@dataclass(eq=False)
class ThrowStatement(Statement):
    pass


@dataclass(eq=False)
class PlaceholderStatement(Statement):
    """The ``_;`` inside a modifier body."""


@dataclass(eq=False)
class AssemblyStatement(Statement):
    code: str
    flags: list[str] = field(default_factory=list)


@dataclass(eq=False)
class CatchClause(Node):
    kind: str | None
    params: list[Parameter]
    body: Block


@dataclass(eq=False)
class TryStatement(Statement):
    expr: Expression
    returns: list[Parameter]
    body: Block
    catches: list[CatchClause]


# ---------------------------------------------------------------------------
# Declarations
# ---------------------------------------------------------------------------
@dataclass(eq=False)
class Parameter(Node):
    type_name: str
    name: str | None
    storage: str | None = None
    indexed: bool = False


@dataclass(eq=False)
class ModifierInvocation(Node):
    name: str
    args: list[Expression] = field(default_factory=list)


@dataclass(eq=False)
class FunctionDef(Node):
    name: str
    kind: str  # function | constructor | fallback | receive | modifier
    params: list[Parameter]
    returns: list[Parameter]
    visibility: str | None
    mutability: str | None  # pure | view | payable | constant | None
    modifiers: list[ModifierInvocation]
    body: Block | None
    is_virtual: bool = False
    is_override: bool = False
    contract_name: str = ""
    natspec: str = ""

    @property
    def is_constructor(self) -> bool:
        return self.kind == "constructor"

    @property
    def is_modifier(self) -> bool:
        return self.kind == "modifier"

    @property
    def is_public_entry(self) -> bool:
        """Reachable directly by an external account / contract."""
        if self.kind in ("fallback", "receive"):
            return True
        if self.kind != "function":
            return False
        # Before 0.5.0 the default visibility was public.
        return self.visibility in (None, "public", "external")

    @property
    def is_view(self) -> bool:
        return self.mutability in ("view", "pure", "constant")

    @property
    def is_payable(self) -> bool:
        return self.mutability == "payable"

    @property
    def signature(self) -> str:
        types = ",".join(p.type_name for p in self.params)
        label = self.name or self.kind
        return f"{label}({types})"

    @property
    def modifier_names(self) -> list[str]:
        return [m.name for m in self.modifiers]


@dataclass(eq=False)
class StateVariable(Node):
    type_name: str
    name: str
    visibility: str | None
    is_constant: bool = False
    is_immutable: bool = False
    value: Expression | None = None
    contract_name: str = ""


@dataclass(eq=False)
class EventDef(Node):
    name: str
    params: list[Parameter]


@dataclass(eq=False)
class ErrorDef(Node):
    name: str
    params: list[Parameter]


@dataclass(eq=False)
class StructDef(Node):
    name: str
    members: list[Parameter]


@dataclass(eq=False)
class EnumDef(Node):
    name: str
    values: list[str]


@dataclass(eq=False)
class UsingFor(Node):
    library: str
    target: str


@dataclass(eq=False)
class ContractDef(Node):
    name: str
    kind: str  # contract | interface | library | abstract
    bases: list[str]
    state_vars: list[StateVariable] = field(default_factory=list)
    functions: list[FunctionDef] = field(default_factory=list)
    modifiers: list[FunctionDef] = field(default_factory=list)
    events: list[EventDef] = field(default_factory=list)
    errors: list[ErrorDef] = field(default_factory=list)
    structs: list[StructDef] = field(default_factory=list)
    enums: list[EnumDef] = field(default_factory=list)
    using_for: list[UsingFor] = field(default_factory=list)
    natspec: str = ""

    def get_function(self, name: str) -> FunctionDef | None:
        for fn in self.functions:
            if fn.name == name:
                return fn
        return None

    def get_state_var(self, name: str) -> StateVariable | None:
        for var in self.state_vars:
            if var.name == name:
                return var
        return None


@dataclass(eq=False)
class PragmaDirective(Node):
    name: str
    value: str


@dataclass(eq=False)
class ImportDirective(Node):
    path: str


@dataclass(eq=False)
class SourceUnit(Node):
    path: str
    source: str
    pragmas: list[PragmaDirective] = field(default_factory=list)
    imports: list[ImportDirective] = field(default_factory=list)
    contracts: list[ContractDef] = field(default_factory=list)
    free_functions: list[FunctionDef] = field(default_factory=list)

    @property
    def solidity_pragma(self) -> PragmaDirective | None:
        for pragma in self.pragmas:
            if pragma.name == "solidity":
                return pragma
        return None
