"""Tolerant recursive-descent parser for Solidity (0.4.x → 0.8.x).

Design goals:

* **No compiler dependency.** Chainmail must be able to audit code that does
  not compile, uses an exotic ``solc`` version, or misses its imports.
* **Error tolerance.** A syntax error inside one function must not prevent the
  rest of the file from being analysed. Errors are recorded and the parser
  resynchronises at the next statement / member boundary.
* **Detector-friendly output.** Expressions are fully parsed (Pratt parser) so
  that detectors can reason about call targets, call options, assignments,
  comparisons and data flow.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from . import ast as A
from .lexer import Comment, SuspiciousChar, Token, TokenKind, tokenize

T = TypeVar("T")

ELEMENTARY_TYPE_RE = re.compile(
    r"^(u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?"
    r"|bytes([1-9]|[12][0-9]|3[0-2])?|byte|address|bool|string|u?fixed(\d+x\d+)?|var)$"
)
STORAGE_LOCATIONS = ("memory", "storage", "calldata")
VISIBILITIES = ("public", "private", "internal", "external")
MUTABILITIES = ("pure", "view", "payable", "constant", "nonpayable")
NUMBER_UNITS = (
    "wei",
    "gwei",
    "szabo",
    "finney",
    "ether",
    "seconds",
    "minutes",
    "hours",
    "days",
    "weeks",
    "years",
)
ASSIGN_OPS = ("=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "<<=", ">>=", ">>>=")

# Binary operator precedence table (higher binds tighter).
BINARY_PRECEDENCE: dict[str, int] = {
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
RIGHT_ASSOC = {"**"}
UNARY_PREFIX = ("!", "-", "~", "++", "--", "delete", "+")


class ParseError(Exception):
    def __init__(self, message: str, token: Token) -> None:
        super().__init__(f"{message} (line {token.line}, col {token.col}, near {token.value!r})")
        self.token = token
        self.message = message


@dataclass(slots=True)
class ParseDiagnostic:
    message: str
    line: int
    col: int

    def __str__(self) -> str:
        return f"{self.line}:{self.col}: {self.message}"


@dataclass(slots=True)
class ParseResult:
    unit: A.SourceUnit
    comments: list[Comment]
    suspicious_chars: list[SuspiciousChar]
    errors: list[ParseDiagnostic]


class Parser:
    def __init__(self, source: str, path: str = "<memory>") -> None:
        self.source = source
        self.path = path
        self.tokens, self.comments, self.suspicious = tokenize(source)
        self.i = 0
        self.errors: list[ParseDiagnostic] = []
        self._doc_comments = {c.end_line: c for c in self.comments if c.text.startswith(("///", "/**"))}

    # ------------------------------------------------------------------
    # Token helpers
    # ------------------------------------------------------------------
    @property
    def tok(self) -> Token:
        return self.tokens[self.i]

    def peek(self, ahead: int = 1) -> Token:
        idx = min(self.i + ahead, len(self.tokens) - 1)
        return self.tokens[idx]

    def at(self, *values: str) -> bool:
        tok = self.tok
        return tok.kind not in (TokenKind.STRING, TokenKind.HEX_STRING, TokenKind.UNICODE_STRING, TokenKind.EOF) and tok.value in values

    def at_eof(self) -> bool:
        return self.tok.kind is TokenKind.EOF

    def next(self) -> Token:
        tok = self.tokens[self.i]
        if tok.kind is not TokenKind.EOF:
            self.i += 1
        return tok

    def accept(self, *values: str) -> Token | None:
        if self.at(*values):
            return self.next()
        return None

    def expect(self, value: str) -> Token:
        if not self.at(value):
            raise ParseError(f"expected {value!r}", self.tok)
        return self.next()

    def expect_ident(self) -> Token:
        tok = self.tok
        # Many keywords are valid identifiers in some positions (e.g. ``from``,
        # ``error``, ``global``, ``type``). We accept identifiers and a small set
        # of contextual keywords.
        if tok.kind is TokenKind.IDENT or tok.value in ("error", "global", "revert", "receive", "fallback", "type", "as"):
            return self.next()
        raise ParseError("expected identifier", tok)

    def loc(self, tok: Token | None = None) -> A.Loc:
        tok = tok or self.tok
        return A.Loc(tok.line, tok.col, tok.line)

    def close(self, node: A.Node) -> None:
        prev = self.tokens[max(self.i - 1, 0)]
        node.loc.end_line = prev.line

    def skip_balanced(self, open_: str, close_: str) -> int:
        """Skip from an opening delimiter to its matching closer; return end offset."""
        self.expect(open_)
        depth = 1
        while depth and not self.at_eof():
            tok = self.next()
            if tok.kind is TokenKind.PUNCT:
                if tok.value == open_:
                    depth += 1
                elif tok.value == close_:
                    depth -= 1
        return self.tokens[self.i - 1].offset

    def recover_to(self, stop: tuple[str, ...], consume: bool = True) -> None:
        """Skip tokens until one of ``stop`` at nesting depth 0."""
        depth = 0
        while not self.at_eof():
            tok = self.tok
            if tok.kind is TokenKind.PUNCT:
                if tok.value in "({[":
                    depth += 1
                elif tok.value in ")}]":
                    if depth == 0:
                        if tok.value in stop and consume:
                            self.next()
                        return
                    depth -= 1
                    if depth == 0 and tok.value == "}" and "}" in stop:
                        self.next()
                        return
                elif tok.value in stop and depth == 0:
                    if consume:
                        self.next()
                    return
            self.next()

    def try_parse(self, fn: Callable[[], T]) -> T | None:
        saved = self.i
        saved_errors = len(self.errors)
        try:
            return fn()
        except ParseError:
            self.i = saved
            del self.errors[saved_errors:]
            return None

    def error(self, err: ParseError) -> None:
        self.errors.append(ParseDiagnostic(err.message + f" near {err.token.value!r}", err.token.line, err.token.col))

    def natspec_for(self, line: int) -> str:
        parts: list[str] = []
        cursor = line - 1
        while cursor in self._doc_comments:
            comment = self._doc_comments[cursor]
            parts.insert(0, comment.text)
            cursor = comment.line - 1
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Source unit
    # ------------------------------------------------------------------
    def parse(self) -> ParseResult:
        unit = A.SourceUnit(self.loc(), self.path, self.source)
        while not self.at_eof():
            start = self.i
            try:
                self._source_unit_member(unit)
            except ParseError as err:
                self.error(err)
                self.i = max(self.i, start + 1)
                self.recover_to((";", "}"))
        self.close(unit)
        return ParseResult(unit, self.comments, self.suspicious, self.errors)

    def _source_unit_member(self, unit: A.SourceUnit) -> None:
        if self.at("pragma"):
            unit.pragmas.append(self._pragma())
        elif self.at("import"):
            unit.imports.append(self._import())
        elif self.at("contract", "interface", "library", "abstract"):
            unit.contracts.append(self._contract())
        elif self.at("function"):
            fn = self._function()
            unit.free_functions.append(fn)
        elif self.at("struct", "enum", "event", "error", "using", "type"):
            # File-level declarations are parsed into a throwaway contract.
            holder = A.ContractDef(self.loc(), "", "file", [])
            self._contract_member(holder)
        elif self.at(";"):
            self.next()
        else:
            # File-level constant or something unknown.
            holder = A.ContractDef(self.loc(), "", "file", [])
            self._contract_member(holder)

    def _pragma(self) -> A.PragmaDirective:
        start = self.expect("pragma")
        name_tok = self.next()
        begin = self.tok.offset
        while not self.at(";") and not self.at_eof():
            self.next()
        end = self.tok.offset
        self.expect(";")
        value = self.source[begin:end].strip()
        return A.PragmaDirective(self.loc(start), name_tok.value, value)

    def _import(self) -> A.ImportDirective:
        start = self.expect("import")
        path = ""
        while not self.at(";") and not self.at_eof():
            tok = self.next()
            if tok.kind is TokenKind.STRING and not path:
                path = tok.value
        self.expect(";")
        return A.ImportDirective(self.loc(start), path)

    # ------------------------------------------------------------------
    # Contracts
    # ------------------------------------------------------------------
    def _contract(self) -> A.ContractDef:
        start = self.tok
        kind = self.next().value
        if kind == "abstract":
            self.expect("contract")
        name = self.expect_ident().value
        bases: list[str] = []
        if self.accept("is"):
            while True:
                bases.append(self._qualified_name())
                if self.at("("):
                    self.skip_balanced("(", ")")
                if not self.accept(","):
                    break
        contract = A.ContractDef(self.loc(start), name, kind, bases)
        contract.natspec = self.natspec_for(start.line)
        self.expect("{")
        while not self.at("}") and not self.at_eof():
            member_start = self.i
            try:
                self._contract_member(contract)
            except ParseError as err:
                self.error(err)
                self.i = max(self.i, member_start + 1)
                self.recover_to((";", "}"))
        self.expect("}")
        self.close(contract)
        for fn in contract.functions + contract.modifiers:
            fn.contract_name = name
        for var in contract.state_vars:
            var.contract_name = name
        return contract

    def _qualified_name(self) -> str:
        parts = [self.expect_ident().value]
        while self.at(".") and self.peek().kind is TokenKind.IDENT:
            self.next()
            parts.append(self.next().value)
        return ".".join(parts)

    def _contract_member(self, contract: A.ContractDef) -> None:
        tok = self.tok
        if tok.is_("function", "constructor", "fallback", "receive", "modifier"):
            # ``fallback``/``receive`` may also be ordinary identifiers in old
            # code; they are functions only when followed by '('.
            if tok.value in ("fallback", "receive") and not self.peek().is_("("):
                contract.state_vars.append(self._state_variable())
                return
            fn = self._function()
            fn.contract_name = contract.name
            if fn.kind == "modifier":
                contract.modifiers.append(fn)
            else:
                # Pre-0.4.22 constructor: function with the contract's name.
                contract.functions.append(fn)
        elif tok.is_("event"):
            contract.events.append(self._event())
        elif tok.is_("error") and self.peek().kind is TokenKind.IDENT and self.peek(2).is_("("):
            contract.errors.append(self._error_def())
        elif tok.is_("struct"):
            contract.structs.append(self._struct())
        elif tok.is_("enum"):
            contract.enums.append(self._enum())
        elif tok.is_("using"):
            contract.using_for.append(self._using())
        elif tok.is_("type") and self.peek().kind is TokenKind.IDENT and self.peek(2).is_("is"):
            # User-defined value type: ``type Price is uint128;``
            self.recover_to((";",))
        elif tok.is_(";"):
            self.next()
        else:
            contract.state_vars.append(self._state_variable())

    def _event(self) -> A.EventDef:
        start = self.expect("event")
        name = self.expect_ident().value
        params = self._parameter_list()
        self.accept("anonymous")
        self.expect(";")
        return A.EventDef(self.loc(start), name, params)

    def _error_def(self) -> A.ErrorDef:
        start = self.expect("error")
        name = self.expect_ident().value
        params = self._parameter_list()
        self.expect(";")
        return A.ErrorDef(self.loc(start), name, params)

    def _struct(self) -> A.StructDef:
        start = self.expect("struct")
        name = self.expect_ident().value
        self.expect("{")
        members: list[A.Parameter] = []
        while not self.at("}") and not self.at_eof():
            mtok = self.tok
            type_name = self._type_name()
            member_name = self.expect_ident().value
            self.expect(";")
            members.append(A.Parameter(self.loc(mtok), type_name, member_name))
        self.expect("}")
        return A.StructDef(self.loc(start), name, members)

    def _enum(self) -> A.EnumDef:
        start = self.expect("enum")
        name = self.expect_ident().value
        self.expect("{")
        values: list[str] = []
        while not self.at("}") and not self.at_eof():
            values.append(self.expect_ident().value)
            if not self.accept(","):
                break
        self.expect("}")
        return A.EnumDef(self.loc(start), name, values)

    def _using(self) -> A.UsingFor:
        start = self.expect("using")
        if self.at("{"):
            begin = self.tok.offset
            self.skip_balanced("{", "}")
            library = self.source[begin : self.tokens[self.i - 1].offset + 1]
        else:
            library = self._qualified_name()
        self.expect("for")
        if self.accept("*"):
            target = "*"
        else:
            target = self._type_name()
        self.accept("global")
        self.expect(";")
        return A.UsingFor(self.loc(start), library, target)

    def _state_variable(self) -> A.StateVariable:
        start = self.tok
        type_name = self._type_name()
        visibility: str | None = None
        is_constant = is_immutable = False
        while True:
            if self.at(*VISIBILITIES):
                visibility = self.next().value
            elif self.accept("constant"):
                is_constant = True
            elif self.accept("immutable"):
                is_immutable = True
            elif self.at("override"):
                self.next()
                if self.at("("):
                    self.skip_balanced("(", ")")
            elif self.accept("transient"):
                pass
            else:
                break
        name = self.expect_ident().value
        value = None
        if self.accept("="):
            value = self._expression()
        self.expect(";")
        var = A.StateVariable(self.loc(start), type_name, name, visibility, is_constant, is_immutable, value)
        self.close(var)
        return var

    # ------------------------------------------------------------------
    # Types
    # ------------------------------------------------------------------
    def _type_name(self) -> str:
        tok = self.tok
        if tok.is_("mapping"):
            self.next()
            self.expect("(")
            key = self._type_name()
            if self.tok.kind is TokenKind.IDENT:  # named mapping key (0.8.18+)
                self.next()
            self.expect("=>")
            value = self._type_name()
            if self.tok.kind is TokenKind.IDENT:
                self.next()
            self.expect(")")
            base = f"mapping({key} => {value})"
        elif tok.is_("function"):
            begin = tok.offset
            self.next()
            self._parameter_list()
            while self.at(*VISIBILITIES, *MUTABILITIES):
                self.next()
            if self.accept("returns"):
                self._parameter_list()
            base = re.sub(r"\s+", " ", self.source[begin : self.tokens[self.i - 1].offset + 1])
        elif tok.is_("address"):
            self.next()
            base = "address payable" if self.accept("payable") else "address"
        elif tok.kind is TokenKind.IDENT or tok.is_("bool", "string", "bytes", "byte", "var"):
            if tok.kind is TokenKind.IDENT:
                base = self._qualified_name()
            else:
                base = self.next().value
        else:
            raise ParseError("expected type name", tok)

        while self.at("["):
            begin = self.tok.offset
            self.skip_balanced("[", "]")
            base += re.sub(r"\s+", "", self.source[begin : self.tokens[self.i - 1].offset + 1])
        return base

    def _parameter_list(self) -> list[A.Parameter]:
        self.expect("(")
        params: list[A.Parameter] = []
        while not self.at(")") and not self.at_eof():
            ptok = self.tok
            type_name = self._type_name()
            storage = None
            indexed = False
            while self.at(*STORAGE_LOCATIONS, "indexed", "payable"):
                word = self.next().value
                if word == "indexed":
                    indexed = True
                elif word == "payable":
                    type_name += " payable"
                else:
                    storage = word
            name = None
            if self.tok.kind is TokenKind.IDENT or self.at("error", "type", "receive", "fallback"):
                name = self.next().value
            params.append(A.Parameter(self.loc(ptok), type_name, name, storage, indexed))
            if not self.accept(","):
                break
        self.expect(")")
        return params

    # ------------------------------------------------------------------
    # Functions & modifiers
    # ------------------------------------------------------------------
    def _function(self) -> A.FunctionDef:
        start = self.tok
        keyword = self.next().value
        name = ""
        kind = keyword
        if keyword == "function":
            if self.tok.kind is TokenKind.IDENT or self.at("receive", "fallback"):
                name = self.next().value
                kind = "function"
            else:
                # ``function() payable { }`` - unnamed pre-0.6 fallback.
                kind = "fallback"
        elif keyword == "modifier":
            name = self.expect_ident().value
        else:
            name = keyword

        params: list[A.Parameter] = []
        if self.at("("):
            params = self._parameter_list()

        visibility = mutability = None
        modifiers: list[A.ModifierInvocation] = []
        returns: list[A.Parameter] = []
        is_virtual = is_override = False
        while not self.at("{", ";") and not self.at_eof():
            tok = self.tok
            if self.at(*VISIBILITIES):
                visibility = self.next().value
            elif self.at(*MUTABILITIES):
                mutability = self.next().value
            elif self.accept("virtual"):
                is_virtual = True
            elif self.at("override"):
                self.next()
                is_override = True
                if self.at("("):
                    self.skip_balanced("(", ")")
            elif self.accept("returns"):
                returns = self._parameter_list()
            elif tok.kind is TokenKind.IDENT:
                mod_name = self._qualified_name()
                args: list[A.Expression] = []
                if self.at("("):
                    args = self._call_arguments()[0]
                modifiers.append(A.ModifierInvocation(self.loc(tok), mod_name, args))
            else:
                raise ParseError("unexpected token in function header", tok)

        body: A.Block | None = None
        if self.at("{"):
            body = self._block()
        else:
            self.expect(";")

        fn = A.FunctionDef(
            self.loc(start),
            name,
            kind,
            params,
            returns,
            visibility,
            mutability,
            modifiers,
            body,
            is_virtual,
            is_override,
        )
        fn.natspec = self.natspec_for(start.line)
        self.close(fn)
        return fn

    # ------------------------------------------------------------------
    # Statements
    # ------------------------------------------------------------------
    def _block(self, unchecked: bool = False) -> A.Block:
        start = self.expect("{")
        stmts: list[A.Statement] = []
        while not self.at("}") and not self.at_eof():
            stmt_start = self.i
            try:
                stmts.append(self._statement())
            except ParseError as err:
                self.error(err)
                self.i = max(self.i, stmt_start + 1)
                # Skip to the end of the broken statement. A '}' at depth 0 is
                # the enclosing block's closer and is left for us to consume.
                self.recover_to((";",), consume=True)
        self.expect("}")
        block = A.Block(self.loc(start), stmts, unchecked)
        self.close(block)
        return block

    def _statement(self) -> A.Statement:
        tok = self.tok
        loc = self.loc(tok)

        if tok.is_("{"):
            return self._block()
        if tok.is_("unchecked") and self.peek().is_("{"):
            self.next()
            return self._block(unchecked=True)
        if tok.is_("if"):
            self.next()
            self.expect("(")
            cond = self._expression()
            self.expect(")")
            then = self._statement()
            orelse = self._statement() if self.accept("else") else None
            node = A.IfStatement(loc, cond, then, orelse)
            self.close(node)
            return node
        if tok.is_("for"):
            self.next()
            self.expect("(")
            init: A.Statement | None = None
            if not self.accept(";"):
                init = self._simple_statement()
            for_cond = None if self.at(";") else self._expression()
            self.expect(";")
            post = None if self.at(")") else self._expression()
            self.expect(")")
            body = self._statement()
            for_node = A.ForStatement(loc, init, for_cond, post, body)
            self.close(for_node)
            return for_node
        if tok.is_("while"):
            self.next()
            self.expect("(")
            cond = self._expression()
            self.expect(")")
            body = self._statement()
            while_node = A.WhileStatement(loc, cond, body)
            self.close(while_node)
            return while_node
        if tok.is_("do"):
            self.next()
            body = self._statement()
            self.expect("while")
            self.expect("(")
            cond = self._expression()
            self.expect(")")
            self.expect(";")
            return A.DoWhileStatement(loc, body, cond)
        if tok.is_("return"):
            self.next()
            value = None if self.at(";") else self._expression()
            self.expect(";")
            return A.ReturnStatement(loc, value)
        if tok.is_("emit"):
            self.next()
            call = self._expression()
            self.expect(";")
            return A.EmitStatement(loc, call)
        if tok.is_("revert") and self.peek().kind is TokenKind.IDENT:
            self.next()
            call = self._expression()
            self.expect(";")
            return A.RevertStatement(loc, call)
        if tok.is_("break"):
            self.next()
            self.expect(";")
            return A.BreakStatement(loc)
        if tok.is_("continue"):
            self.next()
            self.expect(";")
            return A.ContinueStatement(loc)
        if tok.is_("throw"):
            self.next()
            self.expect(";")
            return A.ThrowStatement(loc)
        if tok.kind is TokenKind.IDENT and tok.value == "_" and self.peek().is_(";"):
            self.next()
            self.next()
            return A.PlaceholderStatement(loc)
        if tok.is_("assembly"):
            return self._assembly()
        if tok.is_("try"):
            return self._try()
        return self._simple_statement()

    def _assembly(self) -> A.AssemblyStatement:
        start = self.expect("assembly")
        if self.tok.kind is TokenKind.STRING:
            self.next()
        flags: list[str] = []
        if self.at("("):
            self.next()
            while not self.at(")") and not self.at_eof():
                tok = self.next()
                if tok.kind is TokenKind.STRING:
                    flags.append(tok.value)
            self.expect(")")
        begin = self.tok.offset
        end = self.skip_balanced("{", "}")
        node = A.AssemblyStatement(self.loc(start), self.source[begin : end + 1], flags)
        self.close(node)
        return node

    def _try(self) -> A.TryStatement:
        start = self.expect("try")
        expr = self._expression()
        returns: list[A.Parameter] = []
        if self.accept("returns"):
            returns = self._parameter_list()
        body = self._block()
        catches: list[A.CatchClause] = []
        while self.at("catch"):
            ctok = self.next()
            kind = None
            params: list[A.Parameter] = []
            if self.tok.kind is TokenKind.IDENT:
                kind = self.next().value
            if self.at("("):
                params = self._parameter_list()
            cbody = self._block()
            catches.append(A.CatchClause(self.loc(ctok), kind, params, cbody))
        node = A.TryStatement(self.loc(start), expr, returns, body, catches)
        self.close(node)
        return node

    def _simple_statement(self) -> A.Statement:
        """Variable declaration or expression statement, terminated by ';'."""
        loc = self.loc()
        decl = self.try_parse(self._variable_declaration_statement)
        if decl is not None:
            return decl
        expr = self._expression()
        self.expect(";")
        stmt = A.ExpressionStatement(loc, expr)
        self.close(stmt)
        return stmt

    def _variable_declaration_statement(self) -> A.VariableDeclarationStatement:
        loc = self.loc()
        if self.at("("):
            # Tuple destructuring declaration: (uint a, , bool b) = f();
            self.next()
            decls: list[A.VariableDeclaration | None] = []
            while True:
                if self.at(",", ")"):
                    decls.append(None)
                else:
                    decls.append(self._single_declaration())
                if not self.accept(","):
                    break
            self.expect(")")
            if all(d is None for d in decls):
                raise ParseError("not a declaration", self.tok)
            self.expect("=")
            value: A.Expression | None = self._expression()
            self.expect(";")
            stmt = A.VariableDeclarationStatement(loc, decls, value)
            self.close(stmt)
            return stmt
        decl = self._single_declaration()
        value = None
        if self.accept("="):
            value = self._expression()
        self.expect(";")
        stmt = A.VariableDeclarationStatement(loc, [decl], value)
        self.close(stmt)
        return stmt

    def _single_declaration(self) -> A.VariableDeclaration:
        tok = self.tok
        type_name = self._type_name()
        storage = None
        while self.at(*STORAGE_LOCATIONS):
            storage = self.next().value
        if not (self.tok.kind is TokenKind.IDENT or self.at("error", "type")):
            raise ParseError("not a declaration", self.tok)
        name = self.next().value
        if not self.at("=", ";", ",", ")"):
            raise ParseError("not a declaration", self.tok)
        return A.VariableDeclaration(self.loc(tok), type_name, name, storage)

    # ------------------------------------------------------------------
    # Expressions (Pratt parser)
    # ------------------------------------------------------------------
    def _expression(self) -> A.Expression:
        return self._assignment()

    def _assignment(self) -> A.Expression:
        left = self._conditional()
        if self.at(*ASSIGN_OPS):
            op_tok = self.next()
            value = self._assignment()
            return A.Assignment(self.loc(op_tok), op_tok.value, left, value)
        return left

    def _conditional(self) -> A.Expression:
        cond = self._binary(0)
        if self.at("?"):
            q = self.next()
            true_expr = self._assignment()
            self.expect(":")
            false_expr = self._assignment()
            return A.Conditional(self.loc(q), cond, true_expr, false_expr)
        return cond

    def _binary(self, min_prec: int) -> A.Expression:
        left = self._unary()
        while True:
            tok = self.tok
            if tok.kind is not TokenKind.OPERATOR or tok.value not in BINARY_PRECEDENCE:
                break
            prec = BINARY_PRECEDENCE[tok.value]
            if prec < min_prec:
                break
            self.next()
            next_min = prec if tok.value in RIGHT_ASSOC else prec + 1
            right = self._binary(next_min)
            left = A.BinaryOp(self.loc(tok), tok.value, left, right)
        return left

    def _unary(self) -> A.Expression:
        tok = self.tok
        if tok.kind is TokenKind.OPERATOR and tok.value in UNARY_PREFIX or tok.is_("delete"):
            self.next()
            operand = self._unary()
            return A.UnaryOp(self.loc(tok), tok.value, operand, True)
        return self._postfix(self._primary())

    def _call_arguments(self) -> tuple[list[A.Expression], list[str]]:
        self.expect("(")
        args: list[A.Expression] = []
        names: list[str] = []
        if self.at("{"):
            # Named arguments: f({a: 1, b: 2})
            self.next()
            while not self.at("}") and not self.at_eof():
                names.append(self.expect_ident().value)
                self.expect(":")
                args.append(self._expression())
                if not self.accept(","):
                    break
            self.expect("}")
        else:
            while not self.at(")") and not self.at_eof():
                args.append(self._expression())
                if not self.accept(","):
                    break
        self.expect(")")
        return args, names

    def _postfix(self, expr: A.Expression) -> A.Expression:
        while True:
            tok = self.tok
            if tok.is_("("):
                args, names = self._call_arguments()
                expr = A.FunctionCall(self.loc(tok), expr, args, names)
                self._fix_call_loc(expr)
            elif tok.is_("."):
                self.next()
                member = self.next()
                expr = A.MemberAccess(self.loc(member), expr, member.value)
            elif tok.is_("["):
                self.next()
                start = end = None
                if self.at(":"):
                    self.next()
                    if not self.at("]"):
                        end = self._expression()
                    self.expect("]")
                    expr = A.IndexRange(self.loc(tok), expr, None, end)
                    continue
                index = None if self.at("]") else self._expression()
                if self.accept(":"):
                    start = index
                    if not self.at("]"):
                        end = self._expression()
                    self.expect("]")
                    expr = A.IndexRange(self.loc(tok), expr, start, end)
                    continue
                self.expect("]")
                expr = A.IndexAccess(self.loc(tok), expr, index)
            elif tok.is_("{") and self.peek().kind is TokenKind.IDENT and self.peek(2).is_(":"):
                self.next()
                options: dict[str, A.Expression] = {}
                while not self.at("}") and not self.at_eof():
                    key = self.expect_ident().value
                    self.expect(":")
                    options[key] = self._expression()
                    if not self.accept(","):
                        break
                self.expect("}")
                expr = A.CallOptions(self.loc(tok), expr, options)
            elif tok.is_("++", "--"):
                self.next()
                expr = A.UnaryOp(self.loc(tok), tok.value, expr, False)
            else:
                return expr

    def _fix_call_loc(self, call: A.FunctionCall) -> None:
        # Attribute the call to the line where its callee starts, which is what
        # humans expect when reading a report.
        call.loc = A.Loc(call.target.loc.line, call.target.loc.col, self.tokens[self.i - 1].line)

    def _primary(self) -> A.Expression:
        tok = self.tok
        loc = self.loc(tok)
        kind = tok.kind

        if kind is TokenKind.NUMBER or kind is TokenKind.HEX_NUMBER:
            self.next()
            unit = None
            if self.tok.kind is TokenKind.IDENT and self.tok.value in NUMBER_UNITS:
                unit = self.next().value
            return A.Literal(loc, tok.value, "hex" if kind is TokenKind.HEX_NUMBER else "number", unit)
        if kind in (TokenKind.STRING, TokenKind.HEX_STRING, TokenKind.UNICODE_STRING):
            self.next()
            value = tok.value
            while self.tok.kind is kind:  # adjacent string literal concatenation
                value += self.next().value
            label = {TokenKind.STRING: "string", TokenKind.HEX_STRING: "hexstring"}.get(kind, "unicode")
            return A.Literal(loc, value, label)
        if tok.is_("true", "false"):
            self.next()
            return A.Literal(loc, tok.value, "bool")
        if tok.is_("("):
            self.next()
            elements: list[A.Expression | None] = []
            while True:
                if self.at(",", ")"):
                    elements.append(None)
                else:
                    elements.append(self._expression())
                if not self.accept(","):
                    break
            self.expect(")")
            if len(elements) == 1 and elements[0] is not None:
                return elements[0]
            return A.TupleExpr(loc, elements)
        if tok.is_("["):
            self.next()
            items: list[A.Expression | None] = []
            while not self.at("]") and not self.at_eof():
                items.append(self._expression())
                if not self.accept(","):
                    break
            self.expect("]")
            return A.TupleExpr(loc, items, is_array=True)
        if tok.is_("new"):
            self.next()
            type_name = self._type_name()
            return A.NewExpr(loc, type_name)
        if tok.is_("type") and self.peek().is_("("):
            self.next()
            self.expect("(")
            type_name = self._type_name()
            self.expect(")")
            return A.TypeNameExpr(loc, type_name)
        if tok.is_("payable"):
            self.next()
            return A.ElementaryTypeExpr(loc, "payable")
        if tok.is_("address"):
            self.next()
            if self.accept("payable"):
                return A.ElementaryTypeExpr(loc, "address payable")
            return A.ElementaryTypeExpr(loc, "address")
        if tok.is_("bool", "string", "bytes", "byte"):
            self.next()
            return A.ElementaryTypeExpr(loc, tok.value)
        if tok.is_("mapping"):
            return A.ElementaryTypeExpr(loc, self._type_name())
        if kind is TokenKind.IDENT:
            self.next()
            if ELEMENTARY_TYPE_RE.match(tok.value):
                return A.ElementaryTypeExpr(loc, tok.value)
            return A.Identifier(loc, tok.value)
        if tok.is_("revert", "error", "receive", "fallback", "global", "this", "super"):
            self.next()
            return A.Identifier(loc, tok.value)
        if kind is TokenKind.KEYWORD:
            # Keywords like ``storage``/``memory`` cannot start an expression,
            # but some (e.g. ``this``) are lexed as identifiers already. Treat
            # any other keyword as an identifier for robustness.
            self.next()
            return A.Identifier(loc, tok.value)
        raise ParseError("expected expression", tok)


def parse_source(source: str, path: str = "<memory>") -> ParseResult:
    """Parse Solidity source text and return the AST plus diagnostics."""
    return Parser(source, path).parse()
