"""End-to-end expectations on the bundled example contracts."""

import pytest

from chainmail.config import Config
from chainmail.engine import Scanner
from chainmail.findings import Severity

EXPECTED = {
    "ReentrancyVault.sol": {"reentrancy-eth"},
    "Lottery.sol": {"tx-origin-auth", "weak-prng", "unbounded-loop", "timestamp-dependence", "external-call-in-loop"},
    "LegacyToken.sol": {
        "integer-overflow",
        "constructor-name",
        "missing-access-control",
        "uninitialized-storage-pointer",
        "unchecked-send",
        "assignment-typo",
        "default-visibility",
        "deprecated-constructs",
        "erc20-approve-race",
        "tautology",
    },
    "UpgradeableWallet.sol": {
        "unprotected-initializer",
        "missing-access-control",
        "controlled-delegatecall",
        "arbitrary-external-call",
        "unprotected-selfdestruct",
        "unprotected-upgrade",
    },
    "DexAggregator.sol": {
        "missing-slippage",
        "ineffective-deadline",
        "spot-price-oracle",
        "chainlink-stale-price",
        "unchecked-erc20-transfer",
        "divide-before-multiply",
        "msg-value-in-loop",
        "unsafe-downcast",
        "locked-ether",
    },
    "SignatureWallet.sol": {"signature-replay", "signature-malleability", "ecrecover-zero-address", "encode-packed-collision"},
}


@pytest.mark.parametrize("name,expected", sorted(EXPECTED.items()))
def test_example_detections(examples, name, expected):
    result = Scanner(Config()).scan_paths([examples / name])
    assert not result.detector_errors
    assert not result.parse_errors
    found = {f.detector for f in result.findings}
    missing = expected - found
    assert not missing, f"missing detections: {missing}"


def test_safe_vault_is_clean(examples):
    result = Scanner(Config()).scan_paths([examples / "SafeVault.sol"])
    serious = [f for f in result.findings if f.severity >= Severity.LOW]
    assert serious == [], [(f.detector, f.description) for f in serious]


def test_withdraw_safe_not_flagged(examples):
    result = Scanner(Config()).scan_paths([examples / "ReentrancyVault.sol"])
    flagged = {f.location.function for f in result.findings if f.detector == "reentrancy-eth"}
    assert flagged == {"withdraw", "withdrawAll"}
