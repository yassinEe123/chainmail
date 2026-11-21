// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract SignatureWallet {
    address public signer;
    mapping(bytes32 => bool) public usedHashes;

    constructor(address _signer) {
        signer = _signer;
    }

    // VULNERABLE: no nonce, malleable, zero-address not checked
    function withdraw(address payable to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(to, amount));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered == signer, "bad sig");
        (bool ok, ) = to.call{value: amount}("");
        require(ok);
    }

    // VULNERABLE: ambiguous packed encoding
    function register(string calldata name, string calldata domain) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(name, domain));
    }

    receive() external payable {}
}
