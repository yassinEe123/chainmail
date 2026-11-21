# Chainmail

Chainmail is a static analyzer for Solidity smart contracts, written in Python.
It parses contracts directly (no `solc` needed), runs a set of vulnerability
detectors on them and outputs findings as a console report, JSON, Markdown,
HTML or SARIF.

I started it while working on smart contract security as part of my
cybersecurity studies. I wanted a tool I fully understand end to end (parser,
analysis, detectors) instead of only running existing scanners.

[![CI](https://github.com/yassinEe123/chainmail/actions/workflows/ci.yml/badge.svg)](https://github.com/yassinEe123/chainmail/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

```text
$ chainmail scan examples/contracts --min-severity high

 CRITICAL  Delegatecall to user-controlled address  [controlled-delegatecall · SWC-112 · confidence: high]
  → examples/contracts/UpgradeableWallet.sol:34:46  (UpgradeableWallet.execute)
    34 │ (bool ok, bytes memory ret) = target.delegatecall(data);
    Anyone can make `UpgradeableWallet` delegatecall into an arbitrary address `target`
    through `execute(address,bytes)`.

 HIGH  Reentrancy with ETH transfer  [reentrancy-eth · SWC-107 · confidence: high]
  → examples/contracts/ReentrancyVault.sol:29:9  (ReentrancyVault.withdrawAll)
    29 │ _send(msg.sender, amount);
    `withdrawAll()` in `ReentrancyVault` makes an external call `payable(to).call{value:
    amount}("")` (via internal call to `_send()`) and only then updates `balances` (line
    39 in `_clear()`). A malicious callee can re-enter while this state is stale.
 ...
```

## Features

- Hand-written Solidity lexer/parser (0.4.x to 0.8.x). It keeps going after syntax
  errors, so partially broken files still get analyzed.
- Inheritance resolution using C3 linearization (same order as `solc`).
- Per-function analysis: call classification, state reads/writes in order,
  taint from function parameters, access-control detection (modifiers,
  `require(msg.sender == ...)`, role checks).
- Reentrancy detection that follows internal calls (a call in `_send()` followed by
  a write in `_clear()` is reported).
- 57 detectors with severity, confidence, SWC and CWE ids. Full list in
  [docs/detectors.md](docs/detectors.md).
- Reports: console, JSON, Markdown, HTML (single file) and SARIF for GitHub code scanning.
- Inline suppressions, baseline file, YAML config, exit codes for CI.
- Custom detectors can be added as plugins.

## Install

```bash
git clone https://github.com/yassinEe123/chainmail
cd chainmail
pip install -e .
```

Python 3.10 or newer. Dependencies: `click`, `jinja2`, `pyyaml`.

## Usage

```bash
chainmail scan contracts/                                  # console output
chainmail scan contracts/ -o report.html -o report.sarif   # write report files
chainmail scan contracts/ -f json > findings.json
chainmail scan Vault.sol -d "reentrancy-*" -v              # some detectors only, show fixes
chainmail detectors                                        # list detectors
chainmail explain reentrancy-eth                           # details about one detector
chainmail outline Vault.sol                                # contracts, guards, state writes
chainmail callgraph src/ | dot -Tsvg > callgraph.svg       # call graph (Graphviz)
chainmail init                                             # create chainmail.yml
```

Exit code is `0` when nothing at or above `--fail-on` (default `high`) is found,
`1` otherwise, and `2` for usage errors.

## Detectors

| Category | Detectors |
|---|---|
| Reentrancy | `reentrancy-eth`, `reentrancy-no-eth` |
| Access control | `unprotected-selfdestruct`, `unprotected-upgrade`, `unprotected-initializer`, `unprotected-mint`, `missing-access-control`, `tx-origin-auth` |
| External calls | `controlled-delegatecall`, `arbitrary-external-call`, `arbitrary-send-eth`, `unchecked-low-level-call`, `unchecked-send`, `unchecked-erc20-transfer`, `external-call-in-loop`, `msg-value-in-loop`, `transfer-gas-stipend` |
| Arithmetic | `integer-overflow`, `unchecked-arithmetic`, `divide-before-multiply`, `unsafe-downcast`, `tautology` |
| Randomness / time | `weak-prng`, `timestamp-dependence` |
| Signatures | `signature-replay`, `signature-malleability`, `ecrecover-zero-address`, `encode-packed-collision` |
| DeFi | `missing-slippage`, `ineffective-deadline`, `spot-price-oracle`, `chainlink-stale-price`, `erc20-approve-race` |
| DoS | `unbounded-loop`, `strict-balance-equality`, `locked-ether`, `msg-value-non-payable` |
| Compiler / language | `floating-pragma`, `outdated-compiler`, `missing-pragma`, `deprecated-constructs`, `constructor-name`, `default-visibility`, `uninitialized-storage-pointer`, `rtlo-character`, `assignment-typo`, `assert-misuse` |
| Code quality | `shadowing-state`, `shadowing-builtin`, `missing-zero-check`, `missing-events`, `boolean-equality`, `unused-state`, `assembly-usage` |
| Gas | `constable-states`, `external-function`, `storage-write-in-loop` |

## Configuration

`chainmail init` creates a `chainmail.yml`. It can also be put in `.chainmail.yml`
or under `[tool.chainmail]` in `pyproject.toml`.

```yaml
detectors:
  exclude: [assembly-usage]
  severity:
    timestamp-dependence: info
min_severity: low
fail_on: high
paths:
  include_tests: false     # *.t.sol, test/, script/, mocks/ are skipped by default
  exclude: ["**/vendor/**"]
```

Suppressing a finding in the code:

```solidity
// chainmail-disable-next-line tx-origin-auth
require(tx.origin == owner);
```

`slither-disable-*` comments work too.

Baseline, to only see new issues on an existing project:

```bash
chainmail scan src/ --write-baseline chainmail-baseline.json
chainmail scan src/ --baseline chainmail-baseline.json
```

## GitHub Actions

```yaml
name: audit
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  chainmail:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: yassinEe123/chainmail@main
        with:
          path: src
          fail-on: high
```

Results show up in the Security tab (SARIF upload).

## Testing on real code

To check false positives I ran it on audited projects pulled from npm
(`scripts/benchmark.py`):

| Package | Files | Parse errors | Critical | High |
|---|---:|---:|---:|---:|
| OpenZeppelin Contracts 5 | 226 | 0 | 0 | 4 |
| OpenZeppelin Upgradeable 5 | 86 | 0 | 0 | 1 |
| Uniswap v2-core | 11 | 0 | 0 | 0 |
| Uniswap v3-core | 29 | 0 | 0 | 2 |
| Uniswap v2-periphery | 17 | 0 | 0 | 3 |
| Solmate 6 | 20 | 0 | 0 | 0 |
| Chainlink contracts 1.5 | 385 | 0 | 0 | 42 |

The remaining high findings are mostly intended designs (for example state written
after the external call in `TimelockController.execute`), the kind of thing Slither
also reports and a reviewer has to confirm by hand.

## Project structure

```
src/chainmail/
  core/         lexer, parser, AST, project model, analysis
  detectors/    detectors grouped by category
  reporters/    console, json, markdown, html, sarif
  engine.py     file discovery, running detectors, suppressions, baseline
  cli.py
examples/contracts/   vulnerable contracts used for testing + one safe one
tests/
docs/
```

More details in [docs/architecture.md](docs/architecture.md). Writing a new
detector is explained in [docs/writing-detectors.md](docs/writing-detectors.md).

## Limitations

- No compiler AST, so types are inferred on a best-effort basis.
- Inline assembly is flagged but not analyzed.
- No symbolic execution or fuzzing. It's meant to help a manual review, not replace it.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
mypy src
```

## License

MIT
