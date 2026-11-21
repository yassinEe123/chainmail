// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

interface IUniswapV2Router {
    function swapExactTokensForTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external returns (uint[] memory);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 ts);
}

interface AggregatorV3Interface {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract DexAggregator {
    IUniswapV2Router public immutable router;
    IUniswapV2Pair public pair;
    AggregatorV3Interface public feed;
    IERC20 public token;
    mapping(address => uint256) public credits;
    uint128 public lastPrice;

    constructor(IUniswapV2Router _router, IUniswapV2Pair _pair, AggregatorV3Interface _feed, IERC20 _token) {
        router = _router;
        pair = _pair;
        feed = _feed;
        token = _token;
    }

    function swap(address tokenIn, uint256 amountIn, address[] calldata path) external {
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenIn).approve(address(router), amountIn);
        router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, block.timestamp);
    }

    function spotPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return uint256(r1) * 1e18 / uint256(r0);
    }

    function borrowLimit(address user) external view returns (uint256) {
        return credits[user] * spotPrice() / 1e18;
    }

    function oraclePrice() public returns (uint256) {
        (, int256 answer, , , ) = feed.latestRoundData();
        lastPrice = uint128(uint256(answer));
        return uint256(answer);
    }

    function fee(uint256 amount, uint256 bps) external pure returns (uint256) {
        return amount / 10000 * bps;
    }

    function batchDeposit(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            credits[users[i]] += msg.value;
        }
    }

    function payout(address to, uint256 amount) external {
        token.transfer(to, amount);
    }
}
