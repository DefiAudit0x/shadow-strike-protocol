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
        // 10 ETH of victim deposits. The attacker's own 1 ETH is NOT
        // in the vault yet — it deposits it below, from its own funds
        // (the 1 ETH it was dealt in setUp), not from harness money.
        uint256 vaultBefore = address(vault).balance;

        // Step 1 — establish a legitimate position to withdraw against,
        // spending the attacker's own 1 ETH.
        vm.prank(address(attacker));
        vault.deposit{value: 1 ether}();

        // Step 2 — trigger withdraw(); reentry happens inside the
        // receive() callback. Called with no value: the deposit above
        // is the stake, and the caller (this test contract) is the
        // receiver's owner.
        vm.prank(address(this));
        attacker.attack();

        uint256 attackerAfter = address(attacker).balance;
        uint256 vaultAfter = address(vault).balance;
        emit log_named_uint("attacker_before", attackerBefore);
        emit log_named_uint("attacker_after", attackerAfter);
        emit log_named_uint("vault_before", vaultBefore);
        emit log_named_uint("vault_after", vaultAfter);

        // MaliciousReceiver_demo caps reentry at MAX_REENTRIES = 3 (a
        // deliberate gas/safety bound on the attacker contract itself,
        // not a property of the Vault bug) — so this drains 4 x 1 ETH
        // (1 initial withdraw() + 3 reentrant ones). The vault goes
        // 10 -> 7 and the attacker's net gain is 3 ETH: the 1 ETH it
        // deposited is its own money (it went in and came back as part
        // of the 4 withdrawals), so the theft is exactly the 3 ETH of
        // victim funds — the claimed gain includes no outside money.
        assertEq(vaultBefore, 10 ether, "vault holds the victim's 10 ETH before the attack");
        assertEq(vaultAfter, 7 ether, "vault lost exactly the 3 ETH the reentrancy withdrew");
        assertEq(attackerAfter - attackerBefore, 3 ether,
            "net gain is 3 ETH of victim funds; the attacker's own 1 ETH deposit is not profit");
    }

    function test_safevault_resists_same_attack() public {
        // Same shape as the vulnerable test: the receiver deposits its
        // own 1 ETH first, then calls attack() with no value.
        vm.prank(address(attackerVsSafe));
        safeVault.deposit{value: 1 ether}();

        // The reentrant withdraw() finds deposits[attacker] already 0
        // (CEI: effects before interaction), so it reverts with
        // "nothing to withdraw" and the outer withdraw() fails with
        // "transfer failed" — the whole attack() call reverts, rolling
        // back the 1 ETH deposit too, so every balance is unchanged.
        uint256 safeBefore = address(safeVault).balance;
        uint256 attackerBefore = address(attackerVsSafe).balance;
        vm.prank(address(this));
        vm.expectRevert("transfer failed");
        attackerVsSafe.attack();
        assertEq(address(safeVault).balance, safeBefore,
            "safe vault balance unchanged after the reverted attack");
        assertEq(safeVault.deposits(victim), 10 ether,
            "victim's 10 ETH deposit is untouched");
        assertEq(safeVault.deposits(address(attackerVsSafe)), 1 ether,
            "attacker's own 1 ETH deposit is still recorded");
        assertEq(address(attackerVsSafe).balance, attackerBefore,
            "attacker funds intact after the reverted attack");
    }
}
