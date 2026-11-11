// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Demo contract for audit-lens: the fixed version of Vault.sol.
/// Checks-effects-interactions, msg.sender auth, checked call return,
/// nonReentrant guard. audit-lens should report no High/Medium findings.
contract SecureVault {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
