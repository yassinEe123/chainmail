pragma solidity ^0.4.24;

contract LegacyToken {
    mapping(address => uint) balances;
    mapping(address => mapping(address => uint)) public allowed;
    uint public totalSupply;
    address owner;

    struct Lock { uint amount; uint until; }
    Lock[] locks;

    function LegacyTokn() public {
        owner = msg.sender;
        totalSupply = 1000000;
        balances[msg.sender] = totalSupply;
    }

    function transfer(address to, uint value) public returns (bool) {
        require(balances[msg.sender] - value >= 0);
        balances[msg.sender] -= value;
        balances[to] += value;
        return true;
    }

    function batchTransfer(address[] receivers, uint value) public {
        uint amount = receivers.length * value;
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        for (uint i = 0; i < receivers.length; i++) {
            balances[receivers[i]] += value;
        }
    }

    function approve(address spender, uint value) public returns (bool) {
        allowed[msg.sender][spender] = value;
        return true;
    }

    function lockTokens(uint amount) public {
        Lock l;
        l.amount = amount;
        l.until = now + 1 years;
        locks.push(l);
    }

    function payout(address to) {
        if (msg.sender != owner) throw;
        to.send(this.balance);
    }

    function bonus(uint x) public {
        balances[msg.sender] =+ x;
    }

    function hash(string a, string b) public constant returns (bytes32) {
        return sha3(a, b);
    }
}
