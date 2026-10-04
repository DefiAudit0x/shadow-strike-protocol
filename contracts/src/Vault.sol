// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

/// @notice Intentionally vulnerable demo vault — reentrancy via
/// checks-effects-interactions violation in withdraw(). Lab use only.
/// This mirrors shadow_strike/execution/mock_executor.py's
/// VulnerableVault so the same AttackScenario can be run against
/// either the mock (instant, offline) or this real contract (via
/// `forge test`, once Foundry + an RPC are available).
contract Vault {
    mapping(address => uint256) public deposits;

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    /// @dev VULNERABLE: sends ETH before zeroing the internal balance.
    /// A malicious `msg.sender` whose receive() calls back into
    /// withdraw() will be paid out multiple times before this
    /// function's own `deposits[msg.sender] = 0` ever executes.
    function withdraw() external {
        uint256 amount = deposits[msg.sender];
        require(amount > 0, "nothing to withdraw");

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        deposits[msg.sender] = 0;   // <-- too late
    }

    receive() external payable {}
}
