// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

contract Lottery {
    address public owner;
    address payable[] public players;
    uint256 public ticketPrice = 0.1 ether;
    uint256 public endTime;

    constructor(uint256 duration) {
        owner = msg.sender;
        endTime = block.timestamp + duration;
    }

    function enter() external payable {
        require(msg.value == ticketPrice, "wrong price");
        players.push(payable(msg.sender));
    }

    function pickWinner() external {
        require(tx.origin == owner, "not owner");
        require(block.timestamp >= endTime, "not ended");
        uint256 index = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, players.length))) % players.length;
        players[index].transfer(address(this).balance);
        delete players;
    }

    function refundAll() external {
        require(msg.sender == owner);
        for (uint256 i = 0; i < players.length; i++) {
            players[i].transfer(ticketPrice);
        }
    }

    function isLastSecond() external view returns (bool) {
        return block.timestamp == endTime;
    }
}
