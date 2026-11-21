// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract UpgradeableWallet is UUPSUpgradeable {
    address public owner;
    address public feeRecipient;
    uint256 public feeBps;
    bool public paused;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // VULNERABLE: anyone can (re)initialize and become owner
    function initialize(address _owner) external {
        owner = _owner;
        feeBps = 30;
    }

    // VULNERABLE: missing access control on privileged setter
    function setFeeRecipient(address recipient) external {
        feeRecipient = recipient;
    }

    function setFee(uint256 bps) external onlyOwner {
        feeBps = bps;
    }

    // VULNERABLE: anyone can make the wallet delegatecall arbitrary code
    function execute(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "failed");
        return ret;
    }

    // VULNERABLE: arbitrary call with arbitrary data
    function forward(address target, bytes calldata data) external payable {
        (bool ok, ) = target.call{value: msg.value}(data);
        require(ok);
    }

    // VULNERABLE: anyone can destroy the contract
    function kill(address payable to) external {
        selfdestruct(to);
    }

    // VULNERABLE: empty upgrade authorization
    function _authorizeUpgrade(address) internal override {}
}
