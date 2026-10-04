// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {Vault} from "../src/Vault.sol";
import {SafeVault} from "../src/SafeVault.sol";
import {MaliciousReceiver_demo} from "../src/attackers/MaliciousReceiver_demo.sol";

/// @notice Hand-written reference test (no fork needed — deploys locally).
/// Run with: forge test --match-contract VaultReentrancyTest -vvvv
/// This is the "ground truth" the Shadow Strike-generated .t.sol files
/// should agree with for the bundled demo scenario.
contract VaultReentrancyTest is Test {
    Vault vault;
    SafeVault safeVault;
    MaliciousReceiver_demo attacker;
    MaliciousReceiver_demo attackerVsSafe;

    address victim = address(0xBEEF);

    function setUp() public {
        vault = new Vault();
        safeVault = new SafeVault();
        attacker = new MaliciousReceiver_demo(address(vault));
        attackerVsSafe = new MaliciousReceiver_demo(address(safeVault));

        vm.deal(victim, 10 ether);
        vm.prank(victim);
        vault.deposit{value: 10 ether}();

        vm.deal(victim, 10 ether);
        vm.prank(victim);
        safeVault.deposit{value: 10 ether}();

        vm.deal(address(attacker), 1 ether);
        vm.deal(address(attackerVsSafe), 1 ether);
    }

    function test_reentrancy_drains_vulnerable_vault() public {
        uint256 before = address(attacker).balance;

        vm.prank(address(this));
        attacker.attack{value: 1 ether}();

        uint256 after_ = address(attacker).balance;
        emit log_named_uint("attacker_before", before);
        emit log_named_uint("attacker_after", after_);

        // attacker deposited 1 ETH but drained the whole vault (11 ETH
        // total deposited: 10 from victim + 1 from attacker)
        assertGt(after_ - before, 1 ether, "attack should have extracted more than the 1 ETH deposited");
        assertEq(address(vault).balance, 0, "vault should be fully drained");
    }

    function test_safevault_resists_same_attack() public {
        vm.prank(address(this));
        vm.expectRevert(); // second reentrant withdraw() call reverts: deposits[attacker] already 0
        attackerVsSafe.attack{value: 1 ether}();
    }
}
