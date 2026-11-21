// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @notice Reference implementation that follows best practices.
contract SafeVault is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    IERC20 public immutable asset;
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public withdrawFeeBps;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event FeeUpdated(uint256 oldFee, uint256 newFee);

    error ZeroAmount();
    error FeeTooHigh();

    constructor(IERC20 _asset) Ownable(msg.sender) {
        asset = _asset;
    }

    function deposit(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        shares[msg.sender] += amount;
        totalShares += amount;
        asset.safeTransferFrom(msg.sender, address(this), amount);
        emit Deposit(msg.sender, amount);
    }

    function withdraw(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        shares[msg.sender] -= amount;
        totalShares -= amount;
        uint256 fee = amount * withdrawFeeBps / 10_000;
        asset.safeTransfer(msg.sender, amount - fee);
        emit Withdraw(msg.sender, amount);
    }

    function setWithdrawFee(uint256 bps) external onlyOwner {
        if (bps > 500) revert FeeTooHigh();
        emit FeeUpdated(withdrawFeeBps, bps);
        withdrawFeeBps = bps;
    }
}
