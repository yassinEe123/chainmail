# Detector reference

Chainmail ships **57 detectors**. Run `chainmail explain <id>` for the same information in your terminal.

Severity reflects the worst realistic impact; confidence reflects how likely a finding is a true positive. Both can be adjusted per finding by the detector (e.g. a guarded delegatecall is downgraded to *low*).

| ID | Title | Severity | Confidence | SWC | CWE |
|---|---|---|---|---|---|
| [`controlled-delegatecall`](#controlled-delegatecall) | Delegatecall to user-controlled address | critical | high | SWC-112 | CWE-829 |
| [`unprotected-mint`](#unprotected-mint) | Unprotected token minting | critical | medium | - | CWE-284 |
| [`unprotected-selfdestruct`](#unprotected-selfdestruct) | Unprotected selfdestruct | critical | high | SWC-106 | CWE-284 |
| [`unprotected-upgrade`](#unprotected-upgrade) | Unprotected proxy upgrade | critical | high | - | CWE-284 |
| [`arbitrary-external-call`](#arbitrary-external-call) | Arbitrary external call with user-supplied data | high | medium | - | CWE-20 |
| [`arbitrary-send-eth`](#arbitrary-send-eth) | Unprotected ETH transfer to arbitrary address | high | medium | SWC-105 | CWE-284 |
| [`constructor-name`](#constructor-name) | Function named like its contract | high | high | SWC-118 | CWE-665 |
| [`integer-overflow`](#integer-overflow) | Integer overflow / underflow | high | medium | SWC-101 | CWE-190 |
| [`missing-access-control`](#missing-access-control) | Sensitive state change without access control | high | medium | SWC-105 | CWE-284 |
| [`missing-slippage`](#missing-slippage) | Swap without slippage protection | high | high | - | CWE-682 |
| [`msg-value-in-loop`](#msg-value-in-loop) | msg.value used inside a loop | high | medium | - | CWE-837 |
| [`reentrancy-eth`](#reentrancy-eth) | Reentrancy with ETH transfer | high | high | SWC-107 | CWE-841 |
| [`rtlo-character`](#rtlo-character) | Right-to-left override / bidirectional character | high | high | SWC-130 | CWE-451 |
| [`signature-replay`](#signature-replay) | Signature replay | high | medium | SWC-121 | CWE-294 |
| [`spot-price-oracle`](#spot-price-oracle) | Price derived from AMM spot reserves | high | low | - | CWE-1339 |
| [`tx-origin-auth`](#tx-origin-auth) | Authorization through tx.origin | high | high | SWC-115 | CWE-477 |
| [`uninitialized-storage-pointer`](#uninitialized-storage-pointer) | Uninitialized storage pointer | high | medium | SWC-109 | CWE-824 |
| [`unprotected-initializer`](#unprotected-initializer) | Unprotected initializer | high | medium | - | CWE-665 |
| [`weak-prng`](#weak-prng) | Weak source of randomness | high | medium | SWC-120 | CWE-338 |
| [`assignment-typo`](#assignment-typo) | Suspicious `=+` / `=-` assignment | medium | medium | SWC-129 | CWE-480 |
| [`chainlink-stale-price`](#chainlink-stale-price) | Chainlink price used without freshness checks | medium | medium | - | CWE-672 |
| [`default-visibility`](#default-visibility) | Missing visibility specifier | medium | high | SWC-100 | CWE-710 |
| [`divide-before-multiply`](#divide-before-multiply) | Division before multiplication | medium | medium | - | CWE-1339 |
| [`ecrecover-zero-address`](#ecrecover-zero-address) | ecrecover result not checked against address(0) | medium | medium | - | CWE-252 |
| [`encode-packed-collision`](#encode-packed-collision) | Hash collision with abi.encodePacked | medium | medium | SWC-133 | CWE-294 |
| [`locked-ether`](#locked-ether) | Contract locks ETH | medium | high | - | CWE-404 |
| [`reentrancy-no-eth`](#reentrancy-no-eth) | Reentrancy without ETH transfer | medium | medium | SWC-107 | CWE-841 |
| [`shadowing-state`](#shadowing-state) | State variable shadowing | medium | high | SWC-119 | CWE-710 |
| [`signature-malleability`](#signature-malleability) | Raw ecrecover vulnerable to signature malleability | medium | medium | SWC-117 | CWE-347 |
| [`strict-balance-equality`](#strict-balance-equality) | Strict equality on contract balance | medium | high | SWC-132 | CWE-667 |
| [`unbounded-loop`](#unbounded-loop) | Loop over unbounded storage array | medium | medium | SWC-128 | CWE-400 |
| [`unchecked-erc20-transfer`](#unchecked-erc20-transfer) | Unchecked ERC20 transfer | medium | medium | SWC-104 | CWE-252 |
| [`unchecked-low-level-call`](#unchecked-low-level-call) | Unchecked low-level call | medium | high | SWC-104 | CWE-252 |
| [`unchecked-send`](#unchecked-send) | Unchecked send | medium | high | SWC-104 | CWE-252 |
| [`assert-misuse`](#assert-misuse) | assert() used for input validation or with side effects | low | medium | SWC-110 | CWE-670 |
| [`erc20-approve-race`](#erc20-approve-race) | ERC20 approve front-running | low | medium | SWC-114 | CWE-362 |
| [`external-call-in-loop`](#external-call-in-loop) | External call inside a loop | low | medium | SWC-113 | CWE-400 |
| [`floating-pragma`](#floating-pragma) | Floating compiler version | low | high | SWC-103 | CWE-1103 |
| [`ineffective-deadline`](#ineffective-deadline) | Swap deadline set to block.timestamp | low | high | - | CWE-682 |
| [`missing-zero-check`](#missing-zero-check) | Missing zero-address validation | low | medium | - | CWE-20 |
| [`msg-value-non-payable`](#msg-value-non-payable) | msg.value read in non-payable function | low | high | - | - |
| [`shadowing-builtin`](#shadowing-builtin) | Shadowing of a builtin symbol | low | high | SWC-119 | - |
| [`tautology`](#tautology) | Tautological or contradictory comparison | low | high | - | CWE-571 |
| [`timestamp-dependence`](#timestamp-dependence) | Block timestamp used in a condition | low | medium | SWC-116 | CWE-829 |
| [`unchecked-arithmetic`](#unchecked-arithmetic) | Arithmetic in unchecked block | low | low | SWC-101 | CWE-190 |
| [`unsafe-downcast`](#unsafe-downcast) | Unsafe integer downcast | low | medium | - | CWE-681 |
| [`assembly-usage`](#assembly-usage) | Inline assembly | info | high | - | - |
| [`boolean-equality`](#boolean-equality) | Comparison to boolean constant | info | high | - | - |
| [`deprecated-constructs`](#deprecated-constructs) | Use of deprecated Solidity constructs | info | high | SWC-111 | CWE-477 |
| [`missing-events`](#missing-events) | Privileged state change without event | info | medium | - | CWE-778 |
| [`missing-pragma`](#missing-pragma) | Missing version pragma | info | high | - | - |
| [`outdated-compiler`](#outdated-compiler) | Outdated compiler version | info | high | SWC-102 | CWE-937 |
| [`transfer-gas-stipend`](#transfer-gas-stipend) | Use of transfer()/send() with fixed gas stipend | info | high | - | CWE-655 |
| [`unused-state`](#unused-state) | Unused state variable | info | medium | - | - |
| [`constable-states`](#constable-states) | State variable could be constant or immutable | gas | high | - | - |
| [`external-function`](#external-function) | Public function could be external | gas | medium | - | - |
| [`storage-write-in-loop`](#storage-write-in-loop) | Storage variable written inside a loop | gas | medium | - | - |

## `controlled-delegatecall`

**Delegatecall to user-controlled address** - severity *critical*, confidence *high*, category *security*, SWC-112, CWE-829

`delegatecall` executes foreign code in the context of this contract (its storage, balance and `msg.sender`). If the target can be chosen by the caller, anyone can overwrite storage (e.g. the owner) or `selfdestruct` the contract - see the Parity multisig hack.

**Fix:** Only delegatecall to trusted, immutable implementation addresses, and restrict any function that changes the implementation with access control.

References: <https://swcregistry.io/docs/SWC-112>

## `unprotected-mint`

**Unprotected token minting** - severity *critical*, confidence *medium*, category *security*, CWE-284

A public function mints tokens to an arbitrary address without any access control.

**Fix:** Restrict minting to a `MINTER_ROLE`/owner, or tie it to an on-chain payment/condition.

## `unprotected-selfdestruct`

**Unprotected selfdestruct** - severity *critical*, confidence *high*, category *security*, SWC-106, CWE-284

Anyone can call a function that reaches `selfdestruct`, destroying the contract and sending its ETH to an arbitrary address.

**Fix:** Remove `selfdestruct` (deprecated by EIP-6049) or restrict it to a trusted role.

References: <https://swcregistry.io/docs/SWC-106>

## `unprotected-upgrade`

**Unprotected proxy upgrade** - severity *critical*, confidence *high*, category *security*, CWE-284

The upgrade authorization hook of a UUPS proxy (`_authorizeUpgrade`) is empty and has no access-control modifier, or an `upgradeTo*` function is public without protection. Anyone can point the proxy to malicious code.

**Fix:** Implement `_authorizeUpgrade(address) internal override onlyOwner {}`.

References: <https://docs.openzeppelin.com/contracts/5.x/api/proxy#UUPSUpgradeable-_authorizeUpgrade-address->

## `arbitrary-external-call`

**Arbitrary external call with user-supplied data** - severity *high*, confidence *medium*, category *security*, CWE-20

An unprotected function performs a low-level `call` where both the target and the calldata come from the caller. Attackers can make the contract call any function on any contract - typically `token.transferFrom(victim, attacker, amount)` against users who approved this contract.

**Fix:** Restrict the callable targets/selectors with an allow-list, or protect the function.

## `arbitrary-send-eth`

**Unprotected ETH transfer to arbitrary address** - severity *high*, confidence *medium*, category *security*, SWC-105, CWE-284

A public function without access control sends ETH to an address chosen by the caller, and the amount is not tied to the caller's own balance. Anyone can drain the contract.

**Fix:** Protect the function (e.g. `onlyOwner`) or only pay out funds owed to `msg.sender`.

References: <https://swcregistry.io/docs/SWC-105>

## `constructor-name`

**Function named like its contract** - severity *high*, confidence *high*, category *security*, SWC-118, CWE-665

Before Solidity 0.4.22 the constructor was the function bearing the contract's name. A typo or a rename turns it into a public function anyone can call to re-initialize the contract (Rubixi).

**Fix:** Use the `constructor` keyword.

References: <https://swcregistry.io/docs/SWC-118>

## `integer-overflow`

**Integer overflow / underflow** - severity *high*, confidence *medium*, category *security*, SWC-101, CWE-190

The file may be compiled with Solidity < 0.8.0, where arithmetic wraps around silently, and the contract does not use SafeMath. Balances and counters can overflow (e.g. the BEC token `batchOverflow` bug).

**Fix:** Compile with Solidity ≥ 0.8.0 (checked arithmetic by default) or use SafeMath.

References: <https://swcregistry.io/docs/SWC-101>

## `missing-access-control`

**Sensitive state change without access control** - severity *high*, confidence *medium*, category *security*, SWC-105, CWE-284

A public/external function updates a privileged state variable (owner, admin, implementation, fees, oracle, pause flag, ...) without any `msg.sender` check or access-control modifier.

**Fix:** Restrict the function with `onlyOwner`/`onlyRole` or an explicit `msg.sender` check.

## `missing-slippage`

**Swap without slippage protection** - severity *high*, confidence *high*, category *security*, CWE-682

A DEX swap is executed with a minimum output of `0`. MEV bots can sandwich the transaction and extract almost all of its value.

**Fix:** Pass a caller-provided `amountOutMin` computed off-chain from a quote with a tolerance.

## `msg-value-in-loop`

**msg.value used inside a loop** - severity *high*, confidence *medium*, category *security*, CWE-837

`msg.value` is constant during a transaction. Reusing it inside a loop (or in batched delegatecalls/multicall) credits the same ETH several times - the root cause of the Opyn and SushiSwap MISO bugs.

**Fix:** Track the remaining value in a local variable and decrease it on each iteration.

## `reentrancy-eth`

**Reentrancy with ETH transfer** - severity *high*, confidence *high*, category *security*, SWC-107, CWE-841

State is modified after an external call that forwards ETH (or all remaining gas). The callee can re-enter and drain funds before the balance bookkeeping is updated - the bug behind The DAO hack.

```solidity
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok,) = msg.sender.call{value: amount}("");   // interaction
    require(ok);
    balances[msg.sender] -= amount;                    // effect AFTER interaction
}
```

**Fix:** Apply the Checks-Effects-Interactions pattern: update all state *before* making the external call, and/or protect the function with a reentrancy guard such as OpenZeppelin's `nonReentrant`.

References: <https://swcregistry.io/docs/SWC-107>, <https://docs.soliditylang.org/en/latest/security-considerations.html#reentrancy>

## `rtlo-character`

**Right-to-left override / bidirectional character** - severity *high*, confidence *high*, category *security*, SWC-130, CWE-451

Unicode bidirectional control characters (e.g. U+202E) make the source render differently from how the compiler reads it, hiding malicious logic from reviewers ("Trojan Source").

**Fix:** Remove all bidirectional control characters from the source.

References: <https://swcregistry.io/docs/SWC-130>, <https://trojansource.codes/>

## `signature-replay`

**Signature replay** - severity *high*, confidence *medium*, category *security*, SWC-121, CWE-294

A signature is verified, but the signed message does not include a nonce (or the contract does not record used signatures), and/or does not bind the chain id and verifying contract. The same signature can be submitted again, on another chain, or to another deployment.

**Fix:** Sign EIP-712 typed data including a per-signer nonce, `block.chainid` and `address(this)`; mark nonces as used.

References: <https://swcregistry.io/docs/SWC-121>, <https://eips.ethereum.org/EIPS/eip-712>

## `spot-price-oracle`

**Price derived from AMM spot reserves** - severity *high*, confidence *low*, category *security*, CWE-1339

The price is computed from an AMM pair's instantaneous state (`getReserves`, `slot0`, or token balances of the pool). These values can be moved arbitrarily within one transaction using a flash loan, enabling price manipulation attacks (bZx, Harvest, Cream, ...).

**Fix:** Use a manipulation-resistant oracle: Chainlink, or a Uniswap TWAP over a sufficient window.

## `tx-origin-auth`

**Authorization through tx.origin** - severity *high*, confidence *high*, category *security*, SWC-115, CWE-477

`tx.origin` is the externally-owned account that started the transaction, not the immediate caller. A malicious contract the owner interacts with can pass a `tx.origin == owner` check and act on the owner's behalf (phishing).

**Fix:** Use `msg.sender` for authorization.

References: <https://swcregistry.io/docs/SWC-115>

## `uninitialized-storage-pointer`

**Uninitialized storage pointer** - severity *high*, confidence *medium*, category *security*, SWC-109, CWE-824

In Solidity < 0.5.0 a local struct/array declared without a data location defaults to `storage` and, if uninitialized, points at slot 0 - writes through it overwrite unrelated state (e.g. the owner).

**Fix:** Declare the location explicitly (`memory`), or initialize the storage pointer.

References: <https://swcregistry.io/docs/SWC-109>

## `unprotected-initializer`

**Unprotected initializer** - severity *high*, confidence *medium*, category *security*, CWE-665

An initializer-like function is public, has no `initializer` modifier and does not check whether initialization already happened. Anyone can call it (again) to take ownership - the root cause of the Parity wallet and several proxy takeovers.

**Fix:** Use OpenZeppelin's `Initializable` and mark the function `initializer`; call `_disableInitializers()` in the implementation's constructor.

References: <https://docs.openzeppelin.com/upgrades-plugins/writing-upgradeable#initializers>

## `weak-prng`

**Weak source of randomness** - severity *high*, confidence *medium*, category *security*, SWC-120, CWE-338

Randomness is derived from block attributes (`block.timestamp`, `block.prevrandao`, `blockhash`, ...). These values are public and can be predicted or influenced by validators and by contracts calling in the same block, so lotteries and mints become gameable.

```solidity
uint winner = uint(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % players.length;
```

**Fix:** Use a verifiable randomness source such as Chainlink VRF, or a commit-reveal scheme.

References: <https://swcregistry.io/docs/SWC-120>

## `assignment-typo`

**Suspicious `=+` / `=-` assignment** - severity *medium*, confidence *medium*, category *security*, SWC-129, CWE-480

`x =+ 1` assigns `+1` instead of incrementing. This is almost always a typo for `+=`/`-=`.

**Fix:** Use the compound operator (`+=`, `-=`) or add a space to make the intent explicit.

References: <https://swcregistry.io/docs/SWC-129>

## `chainlink-stale-price`

**Chainlink price used without freshness checks** - severity *medium*, confidence *medium*, category *security*, CWE-672

`latestRoundData()` is consumed without validating `updatedAt` (staleness) and/or that `answer > 0`. During outages or sequencer downtime the feed may return stale or zero prices.

**Fix:** Check `answer > 0`, `updatedAt != 0` and `block.timestamp - updatedAt <= heartbeat`; on L2s also check the sequencer uptime feed.

References: <https://docs.chain.link/data-feeds#check-the-timestamp-of-the-latest-answer>

## `default-visibility`

**Missing visibility specifier** - severity *medium*, confidence *high*, category *security*, SWC-100, CWE-710

Functions without an explicit visibility default to `public` in Solidity < 0.5.0, exposing helpers intended to be internal.

**Fix:** Always declare visibility explicitly (`external`, `public`, `internal`, `private`).

References: <https://swcregistry.io/docs/SWC-100>, <https://swcregistry.io/docs/SWC-108>

## `divide-before-multiply`

**Division before multiplication** - severity *medium*, confidence *medium*, category *security*, CWE-1339

Integer division truncates. Performing it before a multiplication amplifies the rounding error (`a / b * c` ≠ `a * c / b`), which can be exploited to skim fees or rewards.

**Fix:** Multiply first, then divide (`a * c / b`), or use `Math.mulDiv` for full precision.

## `ecrecover-zero-address`

**ecrecover result not checked against address(0)** - severity *medium*, confidence *medium*, category *security*, CWE-252

`ecrecover` returns `address(0)` for invalid signatures. If the recovered address is compared to an uninitialized signer/owner (also zero), any garbage signature is accepted.

**Fix:** Require `recovered != address(0)` or use `ECDSA.recover`, which reverts on invalid signatures.

## `encode-packed-collision`

**Hash collision with abi.encodePacked** - severity *medium*, confidence *medium*, category *security*, SWC-133, CWE-294

`abi.encodePacked` with two or more dynamic-length arguments is ambiguous: `("a", "bc")` and `("ab", "c")` produce the same bytes, so the resulting hash can collide (signature or ID forgery).

**Fix:** Use `abi.encode`, or ensure at most one dynamic argument is packed.

References: <https://swcregistry.io/docs/SWC-133>

## `locked-ether`

**Contract locks ETH** - severity *medium*, confidence *high*, category *security*, CWE-404

The contract can receive ETH (payable functions, `receive` or payable `fallback`) but has no code path that sends ETH out. Funds sent to it are locked forever.

**Fix:** Remove `payable` or add a (protected) withdrawal function.

## `reentrancy-no-eth`

**Reentrancy without ETH transfer** - severity *medium*, confidence *medium*, category *security*, SWC-107, CWE-841

State is modified after a call to an external contract (e.g. a token with hooks, an oracle or an arbitrary user-supplied address). Even without ETH, re-entering can break invariants (ERC777/ERC721 hooks, cross-function reentrancy).

**Fix:** Apply the Checks-Effects-Interactions pattern: update all state *before* making the external call, and/or protect the function with a reentrancy guard such as OpenZeppelin's `nonReentrant`.

References: <https://swcregistry.io/docs/SWC-107>, <https://docs.soliditylang.org/en/latest/security-considerations.html#reentrancy>

## `shadowing-state`

**State variable shadowing** - severity *medium*, confidence *high*, category *security*, SWC-119, CWE-710

A state variable re-declares a variable of a base contract (two storage slots, base functions keep using the old one), or a local/parameter hides a state variable.

**Fix:** Rename the variable, or remove the duplicate declaration and reuse the inherited one.

References: <https://swcregistry.io/docs/SWC-119>

## `signature-malleability`

**Raw ecrecover vulnerable to signature malleability** - severity *medium*, confidence *medium*, category *security*, SWC-117, CWE-347

`ecrecover` accepts both `(r, s, v)` and `(r, n - s, v')` for the same message. If signatures (rather than messages) are used to prevent replays, an attacker can forge a second valid signature.

**Fix:** Use OpenZeppelin `ECDSA.recover`, which rejects high-`s` signatures, and track nonces rather than signatures.

References: <https://swcregistry.io/docs/SWC-117>

## `strict-balance-equality`

**Strict equality on contract balance** - severity *medium*, confidence *high*, category *security*, SWC-132, CWE-667

The contract's ETH or token balance is compared with `==`/`!=`. Anyone can change the balance without calling the contract (forced ETH via `selfdestruct`/coinbase, direct token transfers), breaking the check forever.

**Fix:** Track deposits in a state variable, or use `>=`/`<=` comparisons.

References: <https://swcregistry.io/docs/SWC-132>

## `unbounded-loop`

**Loop over unbounded storage array** - severity *medium*, confidence *medium*, category *security*, SWC-128, CWE-400

A loop iterates over a dynamic storage array whose length can grow. Once the array is large enough the function exceeds the block gas limit and becomes permanently unusable (e.g. GovernMental).

**Fix:** Paginate the loop (start/end indices), cap the array size, or use pull-based accounting.

References: <https://swcregistry.io/docs/SWC-128>

## `unchecked-erc20-transfer`

**Unchecked ERC20 transfer** - severity *medium*, confidence *medium*, category *security*, SWC-104, CWE-252

The boolean returned by an ERC20 `transfer`/`transferFrom`/`approve` is ignored. Several widely used tokens return `false` instead of reverting, and others (e.g. USDT) return nothing at all.

**Fix:** Use OpenZeppelin's `SafeERC20` (`safeTransfer`, `safeTransferFrom`, `forceApprove`).

References: <https://github.com/d-xo/weird-erc20#missing-return-values>

## `unchecked-low-level-call`

**Unchecked low-level call** - severity *medium*, confidence *high*, category *security*, SWC-104, CWE-252

The boolean returned by `call`, `delegatecall`, `staticcall` or `callcode` is ignored. Low-level calls do not revert on failure, so execution silently continues as if the call succeeded.

```solidity
payable(to).call{value: amount}("");  // result discarded
```

**Fix:** Capture the return value and handle failure: `(bool ok, ) = target.call(data); require(ok, "call failed");` or use OpenZeppelin's `Address.functionCall`.

References: <https://swcregistry.io/docs/SWC-104>

## `unchecked-send`

**Unchecked send** - severity *medium*, confidence *high*, category *security*, SWC-104, CWE-252

`address.send()` returns `false` on failure instead of reverting, and the result is ignored.

**Fix:** Use `require(to.send(x))`, or better, a checked `call{value: x}("")`.

## `assert-misuse`

**assert() used for input validation or with side effects** - severity *low*, confidence *medium*, category *best-practice*, SWC-110, CWE-670

`assert` should only check invariants that can never be false. Failing asserts on user input signals a bug to tooling, and before 0.8.0 consumed all remaining gas.

**Fix:** Use `require`/custom errors for input validation; keep `assert` for invariants.

References: <https://swcregistry.io/docs/SWC-110>

## `erc20-approve-race`

**ERC20 approve front-running** - severity *low*, confidence *medium*, category *security*, SWC-114, CWE-362

The token's `approve` overwrites the allowance directly. A spender who sees an allowance change in the mempool can spend the old allowance and then the new one.

**Fix:** Provide `increaseAllowance`/`decreaseAllowance`, or require the allowance to be 0 before changing it.

References: <https://swcregistry.io/docs/SWC-114>

## `external-call-in-loop`

**External call inside a loop** - severity *low*, confidence *medium*, category *security*, SWC-113, CWE-400

External calls inside loops make the whole transaction fail if a single call reverts (one malicious recipient can block everyone) and may run out of gas as the loop grows.

**Fix:** Favour the pull-over-push pattern: record what each party is owed and let them withdraw.

References: <https://swcregistry.io/docs/SWC-113>

## `floating-pragma`

**Floating compiler version** - severity *low*, confidence *high*, category *best-practice*, SWC-103, CWE-1103

The pragma accepts a range of compiler versions. Deployed bytecode may be produced by a different, untested (or buggy) compiler than the one used in testing and audits.

**Fix:** Lock the pragma for deployable contracts, e.g. `pragma solidity 0.8.24;`.

References: <https://swcregistry.io/docs/SWC-103>

## `ineffective-deadline`

**Swap deadline set to block.timestamp** - severity *low*, confidence *high*, category *security*, CWE-682

Passing `block.timestamp` as the deadline always passes the check, so a pending transaction can be held by validators and executed later at a worse price.

**Fix:** Let the user provide the deadline as a function argument.

## `missing-zero-check`

**Missing zero-address validation** - severity *low*, confidence *medium*, category *security*, CWE-20

An address parameter is stored in state without checking for `address(0)`. A mistaken call can brick privileged roles or burn funds.

**Fix:** Add `require(addr != address(0))` (or a custom error) before storing the address.

## `msg-value-non-payable`

**msg.value read in non-payable function** - severity *low*, confidence *high*, category *code-quality*

`msg.value` is always zero in a non-payable public function (the call reverts otherwise). Logic depending on it is dead or indicates a missing `payable` modifier.

**Fix:** Mark the function `payable` or remove the `msg.value` logic.

## `shadowing-builtin`

**Shadowing of a builtin symbol** - severity *low*, confidence *high*, category *code-quality*, SWC-119

A variable, function or parameter is named like a Solidity builtin (`now`, `msg`, `assert`, ...).

**Fix:** Rename the declaration.

## `tautology`

**Tautological or contradictory comparison** - severity *low*, confidence *high*, category *code-quality*, CWE-571

An unsigned value is compared against zero in a way that is always true (`>= 0`) or always false (`< 0`).

**Fix:** Remove the check or fix the intended condition (e.g. `> 0`).

## `timestamp-dependence`

**Block timestamp used in a condition** - severity *low*, confidence *medium*, category *security*, SWC-116, CWE-829

Validators have a few seconds of latitude on `block.timestamp`. Strict equality checks may never be satisfied, and short time windows can be manipulated.

**Fix:** Avoid strict equality on timestamps and tolerate drift of ~15 seconds in time windows.

References: <https://swcregistry.io/docs/SWC-116>

## `unchecked-arithmetic`

**Arithmetic in unchecked block** - severity *low*, confidence *low*, category *security*, SWC-101, CWE-190

Arithmetic inside an `unchecked { }` block wraps on overflow even with Solidity ≥ 0.8. This is a common gas optimisation, but it is only safe when the bounds are proven beforehand.

**Fix:** Document why the operation cannot overflow, or move it out of the `unchecked` block.

## `unsafe-downcast`

**Unsafe integer downcast** - severity *low*, confidence *medium*, category *security*, CWE-681

Explicit conversions to a smaller integer type (e.g. `uint128(x)`) silently truncate the value - even in Solidity ≥ 0.8, which only checks arithmetic, not casts.

**Fix:** Use OpenZeppelin `SafeCast` (`x.toUint128()`) or validate the range before casting.

## `assembly-usage`

**Inline assembly** - severity *info*, confidence *high*, category *best-practice*

Inline assembly bypasses Solidity's type and memory safety checks and deserves careful manual review.

**Fix:** Keep assembly minimal, documented and covered by tests; prefer `memory-safe` blocks.

## `boolean-equality`

**Comparison to boolean constant** - severity *info*, confidence *high*, category *code-quality*

Comparing a boolean to `true`/`false` is redundant.

**Fix:** Use the boolean directly (`if (x)` / `if (!x)`).

## `deprecated-constructs`

**Use of deprecated Solidity constructs** - severity *info*, confidence *high*, category *best-practice*, SWC-111, CWE-477

The code uses constructs that are deprecated or removed in recent Solidity versions.

**Fix:** Replace each deprecated construct with its modern equivalent.

References: <https://swcregistry.io/docs/SWC-111>

## `missing-events`

**Privileged state change without event** - severity *info*, confidence *medium*, category *best-practice*, CWE-778

An access-controlled function changes configuration without emitting an event, hindering off-chain monitoring.

**Fix:** Emit an event describing the old and new values.

## `missing-pragma`

**Missing version pragma** - severity *info*, confidence *high*, category *best-practice*

The file has no `pragma solidity` directive, so any compiler version may be used.

**Fix:** Add an explicit, locked `pragma solidity` directive.

## `outdated-compiler`

**Outdated compiler version** - severity *info*, confidence *high*, category *best-practice*, SWC-102, CWE-937

The pragma allows compiler versions with known bugs or missing safety features (checked arithmetic, custom errors, `push0`).

**Fix:** Use a recent compiler (≥ 0.8.20).

References: <https://docs.soliditylang.org/en/latest/bugs.html>, <https://swcregistry.io/docs/SWC-102>

## `transfer-gas-stipend`

**Use of transfer()/send() with fixed gas stipend** - severity *info*, confidence *high*, category *best-practice*, CWE-655

`transfer` and `send` forward a hard-coded 2300 gas stipend. Gas cost changes (EIP-1884) and smart-contract wallets (Safe, account abstraction) can make these transfers fail permanently.

**Fix:** Use `call{value: amount}("")` with a reentrancy guard and check the result.

References: <https://consensys.io/diligence/blog/2019/09/stop-using-soliditys-transfer-now/>

## `unused-state`

**Unused state variable** - severity *info*, confidence *medium*, category *code-quality*

A private/internal state variable is never used. It wastes a storage slot and may hint at missing logic.

**Fix:** Remove the variable or implement the missing logic.

## `constable-states`

**State variable could be constant or immutable** - severity *gas*, confidence *high*, category *gas*

A state variable is never modified after deployment. Declaring it `constant` (literal initializer) or `immutable` (set in the constructor) saves an SLOAD (2100 gas) on every read.

**Fix:** Mark the variable `constant` or `immutable`.

## `external-function`

**Public function could be external** - severity *gas*, confidence *medium*, category *gas*

A `public` function is never called internally; declaring it `external` documents intent and, before 0.6, avoided copying calldata arrays to memory.

**Fix:** Declare the function `external`.

## `storage-write-in-loop`

**Storage variable written inside a loop** - severity *gas*, confidence *medium*, category *gas*

Writing the same storage slot on every iteration costs an SSTORE each time.

**Fix:** Accumulate in a local (memory) variable and write to storage once after the loop.
