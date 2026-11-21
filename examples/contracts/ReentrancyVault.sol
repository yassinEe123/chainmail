// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title Vulnerable ETH vault (classic DAO-style reentrancy)
contract ReentrancyVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    event Deposited(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // VULNERABLE: interaction before effects
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }

    // VULNERABLE: state update hidden in an internal helper
    function withdrawAll() external {
        uint256 amount = balances[msg.sender];
        _send(msg.sender, amount);
        _clear(msg.sender);
    }

    function _send(address to, uint256 amount) internal {
        (bool ok, ) = payable(to).call{value: amount}("");
        require(ok);
    }

    function _clear(address user) internal {
        balances[user] = 0;
    }

    // SAFE: checks-effects-interactions
    function withdrawSafe(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
