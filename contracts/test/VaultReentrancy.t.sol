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
        uint256 attackerBefore = address(attacker).balance;
        uint256 vaultBefore = address(vault).balance;   // 11 ETH: 10 victim + 1 attacker's own deposit

        vm.prank(address(this));
        attacker.attack{value: 1 ether}();

        uint256 attackerAfter = address(attacker).balance;
        uint256 vaultAfter = address(vault).balance;
        emit log_named_uint("attacker_before", attackerBefore);
        emit log_named_uint("attacker_after", attackerAfter);
        emit log_named_uint("vault_before", vaultBefore);
        emit log_named_uint("vault_after", vaultAfter);

        // MaliciousReceiver_demo caps reentry at MAX_REENTRIES = 3 (a
        // deliberate gas/safety bound on the attacker contract itself,
        // not a property of the Vault bug) — so this drains 4 x 1 ETH
        // (1 initial withdraw() + 3 reentrant ones), NOT the vault's
        // entire 11 ETH balance. Asserting a full drain to zero was
        // simply wrong; what the bug actually guarantees is: the
        // attacker profits well beyond their own 1 ETH deposit, and
        // the vault loses funds belonging to OTHER depositors (the
        // victim's 10 ETH), not just the attacker's own stake.
        assertGt(attackerAfter - attackerBefore, 1 ether,
            "attacker should have extracted more than the 1 ETH they deposited");
        assertLt(vaultAfter, vaultBefore - 1 ether,
            "vault should have lost MORE than just the attacker's own 1 ETH deposit "
            "(i.e. the victim's funds were touched too)");
    }

    function test_safevault_resists_same_attack() public {
        vm.prank(address(this));
        vm.expectRevert(); // second reentrant withdraw() call reverts: deposits[attacker] already 0
        attackerVsSafe.attack{value: 1 ether}();
    }
}
