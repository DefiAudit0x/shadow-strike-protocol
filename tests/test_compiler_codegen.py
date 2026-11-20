"""Regressions for the scenario-to-Solidity boundary (E01–E06)."""
from __future__ import annotations

import inspect
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from shadow_strike.core.models import (
    AttackerModel,
    AttackScenario,
    InitialState,
    ShadowStrikeValidationError,
    SuccessCondition,
    TransactionStep,
)
from shadow_strike.execution.compiler import ScenarioCompiler

ADDRESS = "0x" + "1" * 40


def scenario(**changes):
    fields = {
        "scenario_id": "codegen", "vulnerability_class": "reentrancy", "target_protocol": "custom",
        "hypothesis": "Exercise compiler output", "attacker": AttackerModel(initial_eth=2),
        "initial_state": InitialState(fork_url="", fork_block=0, target_contracts={"custom": ADDRESS}),
        "steps": [TransactionStep(1, "attacker", "custom", "ping()")],
        "success_conditions": [SuccessCondition("attacker.eth_balance_after >= 0", "observation")],
    }
    fields.update(changes)
    return AttackScenario(**fields)


@pytest.mark.parametrize("keyword", ["contract", "function", "mapping", "address", "uint256", "bytes32"])
def test_e01_keyword_alias_rejected(keyword):
    data = scenario()
    data.initial_state.target_contracts = {keyword: ADDRESS}
    data.steps[0].target = keyword
    with pytest.raises(ShadowStrikeValidationError, match="Reserved Solidity identifier"):
        ScenarioCompiler().compile(data)


@pytest.mark.parametrize("keyword", ["contract", "function", "mapping", "address"])
def test_e01_keyword_method_rejected(keyword):
    data = scenario()
    data.steps[0].function = keyword + "()"
    with pytest.raises(ShadowStrikeValidationError, match="Reserved Solidity identifier"):
        ScenarioCompiler().compile(data)


def test_e02_abi_typed_literals():
    data = scenario(steps=[TransactionStep(
        1, "attacker", "custom", "submit(string,address,uint256,bool,int8,bytes,bytes2)",
        ['hello "world"', ADDRESS, "42", True, -7, "0x00ff", "0xabcd"],
    )])
    source = ScenarioCompiler().compile(data)
    assert ('custom.submit("hello \\x22world\\x22", address(0x00' + ADDRESS[2:]
            + '), uint256(42), true, int8(-7), hex"00ff", hex"abcd");') in source
    assert "string calldata, address, uint256, bool, int8, bytes calldata, bytes2" in source


@pytest.mark.parametrize(("abi_type", "value"), [
    ("uint8", 256), ("uint8", -1), ("int8", -129), ("bool", 1), ("bytes2", "0x01"),
    ("uint256", 1.5), ("address", "attacker; revert()"), ("string", 4),
])
def test_e02_invalid_typed_values_rejected(abi_type, value):
    data = scenario(steps=[TransactionStep(1, "attacker", "custom", f"submit({abi_type})", [value])])
    with pytest.raises(ShadowStrikeValidationError):
        ScenarioCompiler().compile(data)


def test_e02_argument_count_rejected():
    data = scenario(steps=[TransactionStep(1, "attacker", "custom", "submit(uint256)", [])])
    with pytest.raises(ShadowStrikeValidationError, match="argument count"):
        ScenarioCompiler().compile(data)


def test_e03_custom_target_has_generated_interface(tmp_path):
    data = scenario()
    source = ScenarioCompiler().compile(data)
    assert "interface IShadowStrike_custom { function ping() external payable; }" in source
    assert "IShadowStrike_custom custom;" in source
    assert "address custom;" not in source
    assert "custom.ping();" in source
    # With the supplied toolchain environment, also compile all regression shapes.
    if os.environ.get("FOUNDRY_SOLC"):
        root = Path(__file__).resolve().parents[1]
        shutil.copytree(root / "contracts/src", tmp_path / "contracts/src")
        shutil.copy(root / "foundry.toml", tmp_path / "foundry.toml")
        compiler = ScenarioCompiler()
        out = tmp_path / "contracts/test/generated"
        compiler.compile_to_file(data, out)
        typed = scenario(scenario_id="typed", steps=[TransactionStep(
            1, "attacker", "custom", "submit(string,address,uint256,bool,int8,bytes,bytes2)",
            ["hello", ADDRESS, 42, False, -7, "0x00ff", "0xabcd"],
        )])
        compiler.compile_to_file(typed, out)
        funded = scenario(scenario_id="funded")
        funded.initial_state.balances = {"custom": 10}
        funded.attacker.initial_tokens = {"custom": 100}
        funded.initial_state.custom_setup_calls = [TransactionStep(0, "attacker", "custom", "init()")]
        compiler.compile_to_file(funded, out, attacker_contract_name="MaliciousReceiver_demo")
        result = subprocess.run(
            ["forge", "build", "--root", str(tmp_path), "--offline"],
            capture_output=True, text=True, timeout=120, check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr


def test_e03_explicit_bundled_interface_preserved():
    source = ScenarioCompiler(target_types={"custom": "IVault"}).compile(scenario(
        steps=[TransactionStep(1, "attacker", "custom", "deposit()", value_eth=1)],
    ))
    assert 'import {IVault} from "../../src/interfaces/IVault.sol";' in source
    assert "IVault custom;" in source
    assert "custom.deposit{value: 1 ether}();" in source


def test_e04_documented_storage_access_mechanism():
    doc = inspect.getdoc(ScenarioCompiler.compile)
    assert "written storage slot identifiers and counts" in doc
    assert "No\nbefore/after storage values or full state diff are captured" in doc
    source = ScenarioCompiler().compile(scenario())
    assert "vm.record();" in source
    assert "vm.accesses(address(custom))" in source
    assert 'emit log_named_bytes32("custom_written_slot", _customWrites[i])' in source
    assert "vm.load(" not in source
    unrecorded = ScenarioCompiler().compile(scenario(), record_state_diff=False)
    assert "vm.record();" not in unrecorded
    assert "vm.accesses(" not in unrecorded


@pytest.mark.parametrize("tokens", [100, 100.0])
def test_e05_setup_balances_and_token_seeding(tokens):
    data = scenario()
    data.initial_state.custom_setup_calls = [TransactionStep(
        0, "attacker", "custom", "initialize(uint256)", [5], value_eth=1,
    )]
    data.initial_state.balances = {"custom": 10, "attacker": 4}
    data.attacker.initial_tokens = {"custom": tokens}
    source = ScenarioCompiler().compile(data)
    setup = source.split("function setUp() public {", 1)[1].split("function test_", 1)[0]
    assert "custom.initialize{value: 1 ether}(uint256(5));" in setup
    assert "vm.deal(attacker, 2 ether);" in setup
    assert "vm.deal(address(attacker), 4 ether);" in setup
    assert "vm.deal(address(custom), 10 ether);" in setup
    assert "deal(address(custom), address(attacker), uint256(100));" in setup
    assert setup.index("vm.deal(address(custom)") < setup.index("custom.initialize")
    assert setup.index("vm.prank(address(attacker))") < setup.index("custom.initialize")


@pytest.mark.parametrize("bound", [0, 3, 7])
def test_e06_reentry_bound_controls_generated_receiver(bound):
    data = scenario(attacker_max_reentries=bound)
    source = ScenarioCompiler().compile(data, attacker_contract_name="MaliciousReceiver_demo")
    assert f"attacker = new MaliciousReceiver_demo(address(custom), {bound});" in source
    assert "MAX_REENTRIES = maxReentries;" in source
    assert "reentryCount < MAX_REENTRIES" in source
    assert "reentryCount += 1;" in source


def test_e06_shared_path_deploys_bounded_receiver():
    data = scenario(attacker_max_reentries=3, steps=[
        TransactionStep(1, "attacker", "custom", "deposit()", value_eth=1),
        TransactionStep(2, "attacker", "attacker", "attack()"),
    ])
    source = ScenarioCompiler().compile(data)
    assert "attacker = new ShadowStrikeBoundedReceiver(address(custom), 3);" in source
    assert "reentryCount < MAX_REENTRIES" in source
    assert "attacker.attack();" in source


def test_7b_entitlement_follows_balances_override():
    """CodeRabbit follow-up on PR #29 (Fix 7b): the emitted entitlement must
    follow the attacker's effective funding when initial_state.balances
    overrides initial_eth — otherwise the Foundry path funds the attacker
    with the override but judges it against initial_eth."""
    data = scenario(initial_state=InitialState(
        fork_url="", fork_block=0, target_contracts={"custom": ADDRESS},
        balances={"attacker": 3.0},
    ))
    source = ScenarioCompiler().compile(data)
    assert 'emit log_named_uint("ss.attacker.legitimate_entitlement", 3.0 ether);' in source
