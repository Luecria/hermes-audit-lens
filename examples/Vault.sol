// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Demo contract for audit-lens: three real bugs, on purpose.
/// Do not deploy this contract. It exists so the plugin has something
/// to find in the demo.
contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // BUG 1: reentrancy — ether leaves before the balance is updated.
    // BUG 2: tx.origin used for authorization.
    function withdraw(uint256 amount) external {
        require(tx.origin == msg.sender, "only EOA");
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
        require(ok, "transfer failed");
    }

    // BUG 3: low-level call return value ignored.
    function rescue(address to, uint256 amount) external {
        to.call{value: amount}("");
    }
}
