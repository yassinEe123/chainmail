from chainmail.core import ast as A
from chainmail.core.lexer import TokenKind, tokenize
from chainmail.core.parser import parse_source


def test_tokenizer_basics():
    tokens, comments, suspicious = tokenize('uint x = 0x1F + 1e18; // hi\n/* block */ "s\\"q"')
    kinds = [(t.kind, t.value) for t in tokens]
    assert (TokenKind.HEX_NUMBER, "0x1F") in kinds
    assert (TokenKind.NUMBER, "1e18") in kinds
    assert (TokenKind.STRING, 's\\"q') in kinds
    assert [c.text for c in comments] == ["// hi", "/* block */"]
    assert not suspicious


def test_tokenizer_records_bidi_characters():
    _, _, suspicious = tokenize("uint x; // ‮ evil")
    assert suspicious and suspicious[0].char == "‮"


def test_operators_longest_match():
    tokens, _, _ = tokenize("a >>>= b; c ** d; e => f")
    ops = [t.value for t in tokens if t.kind is TokenKind.OPERATOR]
    assert ops == [">>>=", "**", "=>"]


SAMPLE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {A as B} from "./A.sol";

/// @title Sample
contract Sample is Base, Other(1, 2) {
    using SafeERC20 for IERC20;
    mapping(address => mapping(uint256 => bool)) public flags;
    uint256[] public items;
    address payable immutable owner;
    struct S { uint a; bytes32 b; }
    enum E { X, Y }
    event Ev(address indexed who, uint value);
    error Bad(uint code);

    modifier only() { require(msg.sender == owner); _; }

    constructor() payable Base(msg.sender) {}

    function f(uint256 x, bytes calldata data) external only returns (uint256 r, bool) {
        (bool ok, bytes memory ret) = owner.call{value: x, gas: 5000}(data);
        unchecked { r = x ** 2 + items.length; }
        for (uint i; i < items.length; ++i) { if (i == 3) continue; else break; }
        S memory s = S({a: 1, b: bytes32(0)});
        uint[] memory arr = new uint[](3);
        x = x > 0 ? type(uint256).max : uint256(-1 * int(x));
        bytes memory part = data[4:];
        try this.g() returns (uint v) { r = v; } catch Error(string memory) {} catch (bytes memory) {}
        assembly ("memory-safe") { let y := mload(0x40) }
        emit Ev(msg.sender, 1 ether);
        if (!ok) revert Bad({code: 1});
        delete items;
        return (r, ok);
    }

    function g() external view returns (uint) { return items.length; }
    receive() external payable {}
    fallback(bytes calldata) external returns (bytes memory) { return ""; }
}

interface I { function h() external; }
library L { function k(uint a) internal pure returns (uint) { return a; } }
function free(uint a) pure returns (uint) { return a + 1; }
"""


def test_parse_full_feature_contract():
    res = parse_source(SAMPLE, "Sample.sol")
    assert res.errors == []
    unit = res.unit
    assert unit.solidity_pragma.value == "^0.8.20"
    assert [i.path for i in unit.imports] == ["./A.sol"]
    assert [c.name for c in unit.contracts] == ["Sample", "I", "L"]
    c = unit.contracts[0]
    assert c.bases == ["Base", "Other"]
    assert c.natspec.startswith("/// @title")
    assert [v.name for v in c.state_vars] == ["flags", "items", "owner"]
    assert c.state_vars[0].type_name == "mapping(address => mapping(uint256 => bool))"
    assert c.state_vars[2].is_immutable and c.state_vars[2].type_name == "address payable"
    assert [f.kind for f in c.functions] == ["constructor", "function", "function", "receive", "fallback"]
    f = c.get_function("f")
    assert f.visibility == "external" and f.modifier_names == ["only"]
    assert [p.name for p in f.returns] == ["r", None]
    assert len(unit.free_functions) == 1


def test_call_options_and_tuple_declaration():
    res = parse_source('contract C { function f(address a) external { (bool ok, ) = a.call{value: 1}(""); } }')
    stmt = res.unit.contracts[0].functions[0].body.statements[0]
    assert isinstance(stmt, A.VariableDeclarationStatement)
    assert stmt.declarations[0].name == "ok" and stmt.declarations[1] is None
    call = stmt.value
    assert isinstance(call, A.FunctionCall)
    assert set(call.options) == {"value"}
    assert isinstance(call.target, A.MemberAccess) and call.target.member == "call"


def test_operator_precedence():
    res = parse_source("contract C { function f() { x = a + b * c ** d ** e; } }")
    expr = res.unit.contracts[0].functions[0].body.statements[0].expr
    assert isinstance(expr, A.Assignment)
    add = expr.value
    assert add.op == "+" and add.right.op == "*"
    power = add.right.right
    assert power.op == "**" and power.right.op == "**"  # right associative


def test_legacy_syntax():
    src = """
    pragma solidity ^0.4.24;
    contract Old {
        function Old() public { owner = msg.sender; }
        function () payable {}
        function f() constant returns (uint) { var x = 1; if (x == 0) throw; return x; }
        function g(address a) { a.call.value(1 ether)(); }
    }
    """
    res = parse_source(src)
    assert res.errors == []
    fns = res.unit.contracts[0].functions
    assert fns[1].kind == "fallback" and fns[1].is_payable
    assert fns[2].mutability == "constant"


def test_error_recovery_keeps_other_functions():
    src = """
    contract C {
        function broken() public { x = ; y = 2; }
        function ok() public { z = 1; }
    }
    """
    res = parse_source(src)
    assert res.errors
    names = [f.name for f in res.unit.contracts[0].functions]
    assert names == ["broken", "ok"]
    assert len(res.unit.contracts[0].functions[0].body.statements) == 1  # `y = 2;` survives


def test_walk_visits_nested_nodes():
    res = parse_source("contract C { function f() { if (a) { b(); } else { while (c) { d[e] = 1; } } } }")
    body = res.unit.contracts[0].functions[0].body
    names = {n.name for n in body.walk() if isinstance(n, A.Identifier)}
    assert names == {"a", "b", "c", "d", "e"}


def test_user_defined_value_type_and_using_global():
    src = "type Price is uint128; using {add} for Price global; contract C { Price p; }"
    res = parse_source(src)
    assert res.errors == []
    assert res.unit.contracts[0].state_vars[0].type_name == "Price"
