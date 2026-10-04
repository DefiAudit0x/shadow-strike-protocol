// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

/// @notice Same interface as Vault.sol, correct checks-effects-interactions
/// ordering. Run the identical AttackScenario against this contract to
/// prove the fix actually holds — "ATTACK FAILED" here is the point.
contract SafeVault {
    mapping(address => uint256) public deposits;

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = deposits[msg.sender];
        require(amount > 0, "nothing to withdraw");

        deposits[msg.sender] = 0;   // effects BEFORE interaction — fixed

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}
