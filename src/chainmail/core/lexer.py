"""Solidity tokenizer.

A hand-written, position-aware lexer that turns Solidity source into a flat
stream of tokens. Comments are not discarded: they are collected separately so
that inline suppression directives (``// chainmail-disable-next-line ...``) and
NatSpec can be inspected by later stages.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class TokenKind(Enum):
    IDENT = auto()
    KEYWORD = auto()
    NUMBER = auto()
    HEX_NUMBER = auto()
    STRING = auto()
    HEX_STRING = auto()
    UNICODE_STRING = auto()
    OPERATOR = auto()
    PUNCT = auto()
    EOF = auto()


KEYWORDS = frozenset(
    {
        "abstract",
        "address",
        "anonymous",
        "as",
        "assembly",
        "bool",
        "break",
        "byte",
        "bytes",
        "calldata",
        "catch",
        "constant",
        "constructor",
        "continue",
        "contract",
        "delete",
        "do",
        "else",
        "emit",
        "enum",
        "error",
        "event",
        "external",
        "fallback",
        "false",
        "for",
        "function",
        "global",
        "if",
        "immutable",
        "import",
        "indexed",
        "interface",
        "internal",
        "is",
        "library",
        "mapping",
        "memory",
        "modifier",
        "new",
        "override",
        "payable",
        "pragma",
        "private",
        "public",
        "pure",
        "receive",
        "return",
        "returns",
        "revert",
        "storage",
        "string",
        "struct",
        "throw",
        "true",
        "try",
        "type",
        "unchecked",
        "using",
        "var",
        "view",
        "virtual",
        "while",
    }
)

# Ordered longest-first so that greedy matching works.
OPERATORS = (
    ">>>=",
    "<<=",
    ">>=",
    ">>>",
    "**=",
    "...",
    "==",
    "!=",
    "<=",
    ">=",
    "&&",
    "||",
    "++",
    "--",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    "&=",
    "|=",
    "^=",
    "<<",
    ">>",
    "**",
    "=>",
    ":=",
    "->",
    "+",
    "-",
    "*",
    "/",
    "%",
    "&",
    "|",
    "^",
    "~",
    "!",
    "<",
    ">",
    "=",
    "?",
    ":",
    ".",
)
PUNCTUATION = frozenset("(){}[];,")

# Characters that are legal in source but frequently abused to disguise code
# (SWC-130). They are recorded by the lexer so a detector can flag them.
BIDI_CONTROL_CHARS = frozenset("‪‫‬‭‮⁦⁧⁨⁩‎‏")


@dataclass(frozen=True, slots=True)
class Token:
    kind: TokenKind
    value: str
    line: int
    col: int
    offset: int

    def is_(self, *values: str) -> bool:
        return self.value in values and self.kind not in (
            TokenKind.STRING,
            TokenKind.HEX_STRING,
            TokenKind.UNICODE_STRING,
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"Token({self.kind.name}, {self.value!r}, {self.line}:{self.col})"


@dataclass(frozen=True, slots=True)
class Comment:
    text: str
    line: int
    end_line: int
    is_block: bool


@dataclass(frozen=True, slots=True)
class SuspiciousChar:
    char: str
    line: int
    col: int


class LexerError(Exception):
    def __init__(self, message: str, line: int, col: int) -> None:
        super().__init__(f"{message} at {line}:{col}")
        self.line = line
        self.col = col


class Lexer:
    def __init__(self, source: str) -> None:
        self.src = source
        self.pos = 0
        self.line = 1
        self.col = 1
        self.tokens: list[Token] = []
        self.comments: list[Comment] = []
        self.suspicious: list[SuspiciousChar] = []

    # -- low level helpers -------------------------------------------------
    def _peek(self, ahead: int = 0) -> str:
        idx = self.pos + ahead
        return self.src[idx] if idx < len(self.src) else ""

    def _advance(self, n: int = 1) -> str:
        chunk = self.src[self.pos : self.pos + n]
        for ch in chunk:
            if ch in BIDI_CONTROL_CHARS:
                self.suspicious.append(SuspiciousChar(ch, self.line, self.col))
            if ch == "\n":
                self.line += 1
                self.col = 1
            else:
                self.col += 1
        self.pos += n
        return chunk

    def _emit(self, kind: TokenKind, value: str, line: int, col: int, offset: int) -> None:
        self.tokens.append(Token(kind, value, line, col, offset))

    # -- main loop ---------------------------------------------------------
    def tokenize(self) -> list[Token]:
        src = self.src
        n = len(src)
        while self.pos < n:
            ch = src[self.pos]
            if ch in " \t\r\n\f\v" or ch in BIDI_CONTROL_CHARS or ch == "﻿":
                self._advance()
                continue
            line, col, start = self.line, self.col, self.pos

            if ch == "/" and self._peek(1) == "/":
                self._line_comment()
                continue
            if ch == "/" and self._peek(1) == "*":
                self._block_comment()
                continue

            if ch.isalpha() or ch in "_$":
                word = self._read_while(lambda c: c.isalnum() or c in "_$")
                # hex"..." / unicode"..." literals
                if word in ("hex", "unicode") and self._peek() in "\"'":
                    text = self._read_string()
                    kind = TokenKind.HEX_STRING if word == "hex" else TokenKind.UNICODE_STRING
                    self._emit(kind, text, line, col, start)
                    continue
                kind = TokenKind.KEYWORD if word in KEYWORDS else TokenKind.IDENT
                self._emit(kind, word, line, col, start)
                continue

            if ch.isdigit() or (ch == "." and self._peek(1).isdigit()):
                self._number(line, col, start)
                continue

            if ch in "\"'":
                text = self._read_string()
                self._emit(TokenKind.STRING, text, line, col, start)
                continue

            if ch in PUNCTUATION:
                self._advance()
                self._emit(TokenKind.PUNCT, ch, line, col, start)
                continue

            for op in OPERATORS:
                if src.startswith(op, self.pos):
                    self._advance(len(op))
                    self._emit(TokenKind.OPERATOR, op, line, col, start)
                    break
            else:
                # Unknown character: skip it rather than abort. Real-world code
                # occasionally contains stray unicode in identifiers/comments.
                self._advance()
        self._emit(TokenKind.EOF, "", self.line, self.col, self.pos)
        return self.tokens

    def _read_while(self, pred) -> str:
        start = self.pos
        while self.pos < len(self.src) and pred(self.src[self.pos]):
            self._advance()
        return self.src[start : self.pos]

    def _line_comment(self) -> None:
        line = self.line
        start = self.pos
        while self.pos < len(self.src) and self.src[self.pos] != "\n":
            self._advance()
        self.comments.append(Comment(self.src[start : self.pos], line, line, False))

    def _block_comment(self) -> None:
        line = self.line
        start = self.pos
        self._advance(2)
        while self.pos < len(self.src) and not self.src.startswith("*/", self.pos):
            self._advance()
        if self.pos >= len(self.src):
            raise LexerError("unterminated block comment", line, 0)
        self._advance(2)
        self.comments.append(Comment(self.src[start : self.pos], line, self.line, True))

    def _read_string(self) -> str:
        quote = self._advance()
        line, col = self.line, self.col
        out: list[str] = []
        while True:
            if self.pos >= len(self.src):
                raise LexerError("unterminated string literal", line, col)
            ch = self._advance()
            if ch == "\\":
                out.append(ch + self._advance())
                continue
            if ch == quote:
                break
            if ch == "\n":
                raise LexerError("newline in string literal", line, col)
            out.append(ch)
        return "".join(out)

    def _number(self, line: int, col: int, start: int) -> None:
        if self._peek() == "0" and self._peek(1) in "xX":
            self._advance(2)
            self._read_while(lambda c: c in "0123456789abcdefABCDEF_")
            self._emit(TokenKind.HEX_NUMBER, self.src[start : self.pos], line, col, start)
            return
        self._read_while(lambda c: c.isdigit() or c == "_")
        if self._peek() == "." and self._peek(1).isdigit():
            self._advance()
            self._read_while(lambda c: c.isdigit() or c == "_")
        if self._peek() in "eE" and (self._peek(1).isdigit() or self._peek(1) == "-"):
            self._advance()
            if self._peek() == "-":
                self._advance()
            self._read_while(str.isdigit)
        self._emit(TokenKind.NUMBER, self.src[start : self.pos], line, col, start)


def tokenize(source: str) -> tuple[list[Token], list[Comment], list[SuspiciousChar]]:
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    return tokens, lexer.comments, lexer.suspicious
