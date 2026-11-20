// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

/// @notice Calls used by the bundled reentrancy scenario.
interface IVault {
    function deposit() external payable;
    function withdraw() external;
}
