"""Positive and negative cases for every built-in detector."""

import pytest

from chainmail.findings import Confidence, Severity

from .conftest import ids, scan

P = "pragma solidity 0.8.24;\n"

# ---------------------------------------------------------------------------
# Reentrancy
# ---------------------------------------------------------------------------


def test_reentrancy_eth_detected():
    src = (
        P
        + """
    contract V {
        mapping(address => uint) bal;
        function w() external {
            uint a = bal[msg.sender];
            (bool ok,) = msg.sender.call{value: a}("");
            require(ok);
            bal[msg.sender] = 0;
        }
    }"""
    )
    f = scan(src, "reentrancy-eth")
    assert len(f) == 1
    assert f[0].severity is Severity.HIGH and f[0].confidence is Confidence.HIGH
    assert f[0].metadata["variables"] == ["bal"]


def test_reentrancy_safe_patterns():
    src = (
        P
        + """
    contract V {
        mapping(address => uint) bal;
        modifier nonReentrant() { _; }
        function cei() external {
            uint a = bal[msg.sender];
            bal[msg.sender] = 0;
            (bool ok,) = msg.sender.call{value: a}("");
            require(ok);
        }
        function guarded() external nonReentrant {
            (bool ok,) = msg.sender.call{value: 1}("");
            require(ok);
            bal[msg.sender] = 0;
        }
        function transferStipend() external {
            payable(msg.sender).transfer(1);
            bal[msg.sender] = 0;
        }
    }"""
    )
    assert scan(src, "reentrancy-eth") == []


def test_reentrancy_through_internal_functions():
    src = (
        P
        + """
    contract V {
        mapping(address => uint) bal;
        function w() external { _pay(msg.sender); _clear(msg.sender); }
        function _pay(address to) internal { (bool ok,) = to.call{value: bal[to]}(""); require(ok); }
        function _clear(address u) internal { bal[u] = 0; }
    }"""
    )
    f = scan(src, "reentrancy-eth")
    assert len(f) == 1 and "_pay" in f[0].description and "_clear" in f[0].description


def test_reentrancy_no_eth_token_callback():
    src = (
        P
        + """
    interface IToken { function transfer(address, uint) external returns (bool); }
    contract V {
        IToken t; mapping(address => uint) owed;
        function claim() external {
            require(t.transfer(msg.sender, owed[msg.sender]));
            owed[msg.sender] = 0;
        }
        function viewOnly() external { uint b = t.balanceOf(address(this)); owed[msg.sender] = b; }
    }"""
    )
    f = scan(src, "reentrancy-no-eth")
    assert [x.location.function for x in f] == ["claim"]


# ---------------------------------------------------------------------------
# Calls
# ---------------------------------------------------------------------------


def test_unchecked_low_level_call():
    src = (
        P
        + """
    contract C {
        function bad(address a) external { a.call(""); }
        function badDecl(address a) external { (bool ok,) = a.call(""); }
        function good(address a) external { (bool ok,) = a.call(""); require(ok); }
        function good2(address a) external { (bool ok, bytes memory r) = a.call(""); _verify(ok, r); }
        function good3(address a) external returns (bool) { (bool ok,) = a.call(""); return ok; }
        function good4(address a) external { if (!a.send(1)) revert(); }
        function _verify(bool, bytes memory) internal pure {}
    }"""
    )
    f = scan(src, "unchecked-low-level-call")
    assert sorted(x.location.function for x in f) == ["bad", "badDecl"]


def test_unchecked_send():
    src = (
        P
        + "contract C { function f(address payable a) external { a.send(1); } function g(address payable a) external { require(a.send(1)); } }"
    )
    assert [x.location.function for x in scan(src, "unchecked-send")] == ["f"]


def test_unchecked_erc20_transfer():
    src = (
        P
        + """
    interface IERC20 { function transfer(address,uint) external returns (bool); function transferFrom(address,address,uint) external returns (bool); }
    interface IERC721 { function transferFrom(address,address,uint) external; }
    contract C {
        IERC20 token; IERC721 nft;
        function a(address to) external { token.transfer(to, 1); }
        function b(address to) external { require(token.transfer(to, 1), "x"); }
        function c(address to) external { bool ok = token.transfer(to, 1); require(ok); }
        function d(address to) external { nft.transferFrom(address(this), to, 1); }
        function e(address payable to) external { to.transfer(1); }
    }"""
    )
    assert [x.location.function for x in scan(src, "unchecked-erc20-transfer")] == ["a"]


def test_controlled_delegatecall():
    src = (
        P
        + """
    contract C {
        address owner; address impl;
        function exec(address t, bytes calldata d) external { (bool ok,) = t.delegatecall(d); require(ok); }
        function fixedImpl(bytes calldata d) external { (bool ok,) = impl.delegatecall(d); require(ok); }
        function admin(address t, bytes calldata d) external { require(msg.sender == owner); (bool ok,) = t.delegatecall(d); require(ok); }
    }"""
    )
    f = scan(src, "controlled-delegatecall")
    by_fn = {x.location.function: x for x in f}
    assert set(by_fn) == {"exec", "admin"}
    assert by_fn["exec"].severity is Severity.CRITICAL
    assert by_fn["admin"].severity is Severity.LOW


def test_storage_lookup_is_not_caller_controlled():
    src = (
        P
        + """
    contract C {
        mapping(uint => address) targets;
        function run(uint id, bytes calldata d) external { (bool ok,) = targets[id].delegatecall(d); require(ok); }
    }"""
    )
    assert scan(src, "controlled-delegatecall") == []


def test_arbitrary_external_call_and_send():
    src = (
        P
        + """
    contract C {
        mapping(address => uint) bal;
        function fwd(address t, bytes calldata d) external { (bool ok,) = t.call(d); require(ok); }
        function drain(address payable to) external { to.transfer(address(this).balance); }
        function withdrawTo(address payable to) external { uint a = bal[msg.sender]; bal[msg.sender] = 0; to.transfer(a); }
    }"""
    )
    assert [x.location.function for x in scan(src, "arbitrary-external-call")] == ["fwd"]
    assert [x.location.function for x in scan(src, "arbitrary-send-eth")] == ["drain"]


def test_external_call_and_msg_value_in_loop():
    src = (
        P
        + """
    contract C {
        mapping(address => uint) credit;
        function pay(address payable[] calldata to) external { for (uint i; i < to.length; i++) { to[i].transfer(1); } }
        function multi(address[] calldata u) external payable { for (uint i; i < u.length; i++) { credit[u[i]] += msg.value; } }
    }"""
    )
    assert ids(scan(src, "external-call-in-loop")) == ["external-call-in-loop"]
    assert ids(scan(src, "msg-value-in-loop")) == ["msg-value-in-loop"]


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------


def test_unprotected_selfdestruct():
    src = (
        P
        + """
    contract C {
        address owner;
        modifier onlyOwner() { require(msg.sender == owner); _; }
        function kill() external { selfdestruct(payable(msg.sender)); }
        function safeKill() external onlyOwner { selfdestruct(payable(msg.sender)); }
        function viaHelper() external { _boom(); }
        function _boom() internal { selfdestruct(payable(owner)); }
    }"""
    )
    assert sorted(x.location.function for x in scan(src, "unprotected-selfdestruct")) == ["kill", "viaHelper"]


def test_tx_origin():
    src = (
        P
        + """
    contract C {
        address owner;
        function a() external { require(tx.origin == owner); }
        function b() external { require(tx.origin == msg.sender, "no contracts"); }
        function c() external view returns (bool) { return tx.origin == address(0); }
    }"""
    )
    f = scan(src, "tx-origin-auth")
    sev = {x.location.function: x.severity for x in f}
    assert sev == {"a": Severity.HIGH, "b": Severity.LOW}


def test_unprotected_initializer():
    src = (
        P
        + """
    contract C {
        address owner; bool initialized;
        function initialize(address o) external { owner = o; }
        function init2(address o) external { require(!initialized); initialized = true; owner = o; }
        function initialize3(address o) external initializer { owner = o; }
        modifier initializer() { _; }
    }"""
    )
    f = scan(src, "unprotected-initializer")
    assert [x.location.function for x in f] == ["initialize"]


def test_missing_access_control():
    src = (
        P
        + """
    contract C {
        address public owner; address public feeRecipient; mapping(address => mapping(address => bool)) operatorApprovals; uint counter;
        modifier onlyOwner() { require(msg.sender == owner); _; }
        function setOwner(address o) external { owner = o; }
        function setFeeRecipient(address r) external { feeRecipient = r; }
        function setOwnerSafe(address o) external onlyOwner { owner = o; }
        function setOwnerInline(address o) external { if (msg.sender != owner) revert(); owner = o; }
        function approveOp(address op) external { operatorApprovals[msg.sender][op] = true; }
        function bump() external { counter++; }
    }"""
    )
    f = scan(src, "missing-access-control")
    by_fn = {x.location.function: x.severity for x in f}
    assert by_fn == {"setOwner": Severity.CRITICAL, "setFeeRecipient": Severity.HIGH}


def test_balance_check_is_not_access_control():
    src = (
        P
        + """
    contract C {
        mapping(address => uint) balances; address owner;
        function setOwner(address o) external { require(balances[msg.sender] > 0); owner = o; }
    }"""
    )
    assert ids(scan(src, "missing-access-control")) == ["missing-access-control"]


def test_role_and_mapping_based_guards():
    src = (
        P
        + """
    contract C {
        mapping(address => bool) isAdmin; address owner;
        function hasRole(bytes32, address) internal view returns (bool) { return true; }
        function a(address o) external { require(isAdmin[msg.sender]); owner = o; }
        function b(address o) external { require(hasRole(0x00, msg.sender)); owner = o; }
        function c(address o) external { _checkOwner(); owner = o; }
        function _checkOwner() internal view { require(msg.sender == owner); }
    }"""
    )
    assert scan(src, "missing-access-control") == []


def test_unprotected_mint_and_upgrade():
    src = (
        P
        + """
    contract T {
        function _mint(address, uint) internal {}
        function mint(address to, uint a) external { _mint(to, a); }
        function _authorizeUpgrade(address) internal {}
    }
    contract Safe {
        address owner;
        modifier onlyOwner() { require(msg.sender == owner); _; }
        function _mint(address, uint) internal {}
        function mint(address to, uint a) external onlyOwner { _mint(to, a); }
        function _authorizeUpgrade(address) internal onlyOwner {}
    }"""
    )
    assert [x.location.contract for x in scan(src, "unprotected-mint")] == ["T"]
    assert [x.location.contract for x in scan(src, "unprotected-upgrade")] == ["T"]


# ---------------------------------------------------------------------------
# Arithmetic
# ---------------------------------------------------------------------------


def test_integer_overflow_only_before_0_8():
    body = """
    contract C { mapping(address => uint) b;
        function f(uint v) public { b[msg.sender] += v; }
        function loop() public { for (uint i = 0; i < 10; i++) {} } }"""
    old = scan("pragma solidity ^0.6.0;\n" + body, "integer-overflow")
    assert [x.location.function for x in old] == ["f"]
    assert scan("pragma solidity ^0.8.0;\n" + body, "integer-overflow") == []
    safemath = "pragma solidity ^0.6.0;\nlibrary SafeMath {}\ncontract C { using SafeMath for uint; mapping(address => uint) b; function f(uint v) public { b[msg.sender] += v; } }"
    assert scan(safemath, "integer-overflow") == []


def test_unchecked_arithmetic():
    src = (
        P
        + """
    contract C {
        mapping(address => uint) bal;
        function a(uint x) external { unchecked { bal[msg.sender] -= x; } }
        function b(uint x) external { if (bal[msg.sender] < x) revert(); unchecked { bal[msg.sender] -= x; } }
        function c() external { for (uint i; i < 3;) { unchecked { ++i; } } }
    }"""
    )
    f = scan(src, "unchecked-arithmetic")
    assert [x.location.function for x in f] == ["a"]
    assert f[0].severity is Severity.MEDIUM


def test_divide_before_multiply():
    src = (
        P
        + """
    contract C {
        function a(uint x, uint y) external pure returns (uint) { return x / 100 * y; }
        function b(uint x, uint y) external pure returns (uint) { return x * y / 100; }
        function c(uint x, uint step) external pure returns (uint) { return x / step * step; }
        function d(uint x, uint y) external pure returns (uint) { uint q = x / 3; return q * y; }
    }"""
    )
    assert sorted(x.location.function for x in scan(src, "divide-before-multiply")) == ["a", "d"]


def test_unsafe_downcast_and_tautology():
    src = (
        P
        + """
    contract C {
        uint128 small;
        function a(uint256 x) external { small = uint128(x); }
        function b(uint64 x) external { small = uint128(x); }
        function t(uint x) external pure returns (bool) { return x >= 0; }
    }"""
    )
    assert [x.location.function for x in scan(src, "unsafe-downcast")] == ["a"]
    assert [x.location.function for x in scan(src, "tautology")] == ["t"]


# ---------------------------------------------------------------------------
# Randomness / time
# ---------------------------------------------------------------------------


def test_weak_prng():
    src = (
        P
        + """
    contract C {
        address[] players;
        function pick() external view returns (uint) { return uint(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % players.length; }
        function seed() external view returns (uint) { uint s = block.prevrandao; return s % 10; }
        function ts() external view returns (uint32) { return uint32(block.timestamp % 2**32); }
    }"""
    )
    assert sorted(x.location.function for x in scan(src, "weak-prng")) == ["pick", "seed"]


def test_timestamp_dependence():
    src = (
        P
        + """
    contract C { uint end;
        function a() external view returns (bool) { return block.timestamp == end; }
        function b() external view { require(block.timestamp > end); }
        function c() external view returns (uint) { return block.timestamp + 1; } }"""
    )
    f = scan(src, "timestamp-dependence")
    assert {x.location.function: x.severity for x in f} == {"a": Severity.MEDIUM, "b": Severity.LOW}


# ---------------------------------------------------------------------------
# Compiler / language
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pragma,expected", [("^0.8.0", 1), ("0.8.24", 0), (">=0.8.0 <0.9.0", 1)])
def test_floating_pragma(pragma, expected):
    assert len(scan(f"pragma solidity {pragma};\ncontract C {{}}", "floating-pragma")) == expected


def test_outdated_compiler_and_missing_pragma():
    assert scan("pragma solidity 0.8.24; contract C {}", "outdated-compiler") == []
    assert scan("pragma solidity 0.6.12; contract C {}", "outdated-compiler")[0].severity is Severity.LOW
    assert ids(scan("contract C {}", "missing-pragma")) == ["missing-pragma"]


def test_legacy_constructs():
    src = """
    pragma solidity ^0.4.24;
    contract Wallet {
        struct S { uint a; }
        S[] list;
        function Walet() public {}
        function f() { S s; s.a = 1; list.push(s); }
        function g() public constant returns (bytes32) { if (now == 0) throw; return sha3("x"); }
        function h(uint x) public { uint y; y =+ x; }
    }"""
    assert ids(scan(src, "constructor-name")) == ["constructor-name"]
    assert ids(scan(src, "uninitialized-storage-pointer")) == ["uninitialized-storage-pointer"]
    assert "f" in [x.location.function for x in scan(src, "default-visibility")]
    deprecated = {x.description.split("`")[1] for x in scan(src, "deprecated-constructs")}
    assert {"now", "throw", "sha3()"} <= deprecated
    assert ids(scan(src, "assignment-typo")) == ["assignment-typo"]


def test_rtlo_character():
    src = P + "contract C { // ‮\n }"
    assert ids(scan(src, "rtlo-character")) == ["rtlo-character"]


def test_assert_misuse():
    src = P + "contract C { function f(uint x) external pure { assert(x > 0); } function g() external pure { assert(1 == 1); } }"
    assert [x.location.function for x in scan(src, "assert-misuse")] == ["f"]


# ---------------------------------------------------------------------------
# Signatures & hashing
# ---------------------------------------------------------------------------

SIG = (
    P
    + """
contract C {
    address signer; mapping(address => uint) public nonces;
    function bad(uint amount, uint8 v, bytes32 r, bytes32 s) external {
        address who = ecrecover(keccak256(abi.encodePacked(amount)), v, r, s);
        require(who == signer);
    }
    function good(uint amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 h = keccak256(abi.encode(amount, nonces[msg.sender]++, block.chainid, address(this)));
        address who = ecrecover(h, v, r, s);
        require(who != address(0) && who == signer);
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0);
    }
}"""
)


def test_signature_detectors():
    assert [x.location.function for x in scan(SIG, "signature-replay")] == ["bad"]
    assert [x.location.function for x in scan(SIG, "ecrecover-zero-address")] == ["bad"]
    assert scan(SIG, "signature-malleability") == []  # half-order constant present in file
    no_check = SIG.replace("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", "1")
    assert len(scan(no_check, "signature-malleability")) == 2


def test_encode_packed_collision():
    src = (
        P
        + """
    contract C {
        function a(string calldata x, string calldata y) external pure returns (bytes32) { return keccak256(abi.encodePacked(x, y)); }
        function b(string calldata x, uint y) external pure returns (bytes32) { return keccak256(abi.encodePacked(x, y)); }
        function c(string calldata x, bytes calldata y) external pure returns (bytes32) { return keccak256(abi.encode(x, y)); }
    }"""
    )
    assert [x.location.function for x in scan(src, "encode-packed-collision")] == ["a"]


# ---------------------------------------------------------------------------
# DoS & ETH accounting
# ---------------------------------------------------------------------------


def test_unbounded_loop():
    src = (
        P
        + """
    contract C {
        address[] users; uint[3] fixedArr;
        function join() external { users.push(msg.sender); }
        function payAll() external { for (uint i; i < users.length; i++) {} }
        function fixedLoop() external { for (uint i; i < fixedArr.length; i++) {} }
    }"""
    )
    f = scan(src, "unbounded-loop")
    assert [x.location.function for x in f] == ["payAll"] and f[0].confidence is Confidence.HIGH


def test_strict_balance_equality():
    src = (
        P
        + """
    interface T { function balanceOf(address) external view returns (uint); }
    contract C { T t;
        function a() external view returns (bool) { return address(this).balance == 1 ether; }
        function b() external view returns (bool) { return t.balanceOf(address(this)) != 0; }
        function c() external view returns (bool) { return address(this).balance >= 1 ether; } }"""
    )
    assert sorted(x.location.function for x in scan(src, "strict-balance-equality")) == ["a", "b"]


def test_locked_ether():
    locked = P + "contract C { function deposit() external payable {} }"
    ok = P + "contract C { function deposit() external payable {} function w() external { payable(msg.sender).transfer(1); } }"
    unknown_base = P + "contract C is Base { function deposit() external payable {} }"
    assert ids(scan(locked, "locked-ether")) == ["locked-ether"]
    assert scan(ok, "locked-ether") == []
    assert scan(unknown_base, "locked-ether") == []


def test_msg_value_non_payable():
    src = (
        P
        + "contract C { function f() external view returns (uint) { return msg.value; } function g() external payable returns (uint) { return msg.value; } }"
    )
    assert [x.location.function for x in scan(src, "msg-value-non-payable")] == ["f"]


# ---------------------------------------------------------------------------
# DeFi
# ---------------------------------------------------------------------------

DEFI = (
    P
    + """
interface R { function swapExactTokensForTokens(uint, uint, address[] calldata, address, uint) external returns (uint[] memory);
              struct P { uint amountIn; uint amountOutMinimum; }
              function exactInputSingle(P calldata) external returns (uint); }
interface Pair { function getReserves() external view returns (uint112, uint112, uint32); }
interface Feed { function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80); }
contract C {
    R r; Pair pair; Feed feed;
    function noSlip(uint a, address[] calldata p) external { r.swapExactTokensForTokens(a, 0, p, msg.sender, block.timestamp); }
    function slip(uint a, uint minOut, address[] calldata p, uint deadline) external { r.swapExactTokensForTokens(a, minOut, p, msg.sender, deadline); }
    function v3(uint a) external { r.exactInputSingle(R.P({amountIn: a, amountOutMinimum: 0})); }
    function price() external returns (uint) { (uint112 a, uint112 b,) = pair.getReserves(); return uint(a) * 1e18 / uint(b); }
    function stale() external view returns (int256) { (, int256 answer,,,) = feed.latestRoundData(); return answer; }
    function fresh() external view returns (int256) {
        (, int256 answer,, uint256 updatedAt,) = feed.latestRoundData();
        require(answer > 0 && block.timestamp - updatedAt < 1 hours);
        return answer;
    }
}"""
)


def test_missing_slippage_and_deadline():
    assert sorted(x.location.function for x in scan(DEFI, "missing-slippage")) == ["noSlip", "v3"]
    assert [x.location.function for x in scan(DEFI, "ineffective-deadline")] == ["noSlip"]


def test_spot_oracle_and_chainlink():
    assert [x.location.function for x in scan(DEFI, "spot-price-oracle")] == ["price"]
    assert [x.location.function for x in scan(DEFI, "chainlink-stale-price")] == ["stale"]


def test_approve_race():
    bad = (
        P
        + "contract T { mapping(address => mapping(address => uint)) allowance; function approve(address s, uint v) external returns (bool) { allowance[msg.sender][s] = v; return true; } }"
    )
    good = bad.replace("}  }", "} function increaseAllowance(address, uint) external {} }")
    assert ids(scan(bad, "erc20-approve-race")) == ["erc20-approve-race"]
    good = (
        P
        + "contract T { mapping(address => mapping(address => uint)) allowance; function approve(address s, uint v) external returns (bool) { allowance[msg.sender][s] = v; return true; } function increaseAllowance(address, uint) external {} }"
    )
    assert scan(good, "erc20-approve-race") == []


# ---------------------------------------------------------------------------
# Quality & gas
# ---------------------------------------------------------------------------


def test_shadowing():
    src = (
        P
        + """
    contract Base { uint internal total; uint private secret; }
    contract D is Base { uint total; uint secret; function f(uint total2) external { uint secret2 = 1; } function g(uint x) external { uint total = x; } }"""
    )
    f = scan(src, "shadowing-state")
    titles = sorted((x.title, x.location.line) for x in f)
    assert [t for t, _ in titles].count("State variable shadowing") == 1  # private base var ignored
    assert any(t == "Local variable shadows state" for t, _ in titles)


def test_missing_zero_check_and_events():
    src = (
        P
        + """
    contract C {
        address owner; address treasury;
        modifier onlyOwner() { require(msg.sender == owner); _; }
        event T(address t);
        constructor(address o) { owner = o; }
        function setTreasury(address t) external onlyOwner { treasury = t; }
        function setTreasuryChecked(address t) external onlyOwner { require(t != address(0)); treasury = t; emit T(t); }
    }"""
    )
    assert sorted(x.location.function for x in scan(src, "missing-zero-check")) == ["constructor", "setTreasury"]
    assert [x.location.function for x in scan(src, "missing-events")] == ["setTreasury"]


def test_gas_detectors():
    src = (
        P
        + """
    contract C {
        uint fee = 3; uint immutableCandidate; uint mutableVar; uint total;
        constructor(uint x) { immutableCandidate = x; }
        function set(uint x) external { mutableVar = x + fee + immutableCandidate; }
        function sum(uint[] memory xs) public { for (uint i; i < xs.length; i++) { total += xs[i]; } }
    }"""
    )
    msgs = [x.description for x in scan(src, "constable-states")]
    assert any("`fee`" in m and "constant" in m for m in msgs)
    assert any("`immutableCandidate`" in m and "immutable" in m for m in msgs)
    assert not any("mutableVar" in m for m in msgs)
    assert [x.location.function for x in scan(src, "external-function")] == ["sum"]
    assert [x.location.function for x in scan(src, "storage-write-in-loop")] == ["sum"]


def test_unused_state_and_boolean_equality():
    src = (
        P
        + "contract C { uint private unused; uint private used; bool flag; function f() external view returns (bool) { return used > 0 && flag == true; } }"
    )
    assert [x.description for x in scan(src, "unused-state")] == ["State variable `unused` is never used."]
    assert ids(scan(src, "boolean-equality")) == ["boolean-equality"]


def test_assembly_usage():
    src = P + "contract C { function f(address t) external { assembly { let r := delegatecall(gas(), t, 0, 0, 0, 0) } } }"
    f = scan(src, "assembly-usage")
    assert f and f[0].severity is Severity.LOW and f[0].metadata["opcodes"] == ["delegatecall"]
