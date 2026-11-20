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


def test_k01_k02_k03_regenerated_artifact_runs_end_to_end(tmp_path):
    """K01/K02/K03: a regenerated reentrancy artifact from a placeholder-vault
    scenario must compile in forge and complete the scenario with the
    expected balance movements.

    K01: the emitted imports must use ../../src/... (a single-../ import
    does not resolve from contracts/test/generated/ — the 4 stale files
    removed in this fix broke `forge build` exactly this way).
    K02: the placeholder vault address must be replaced by a deployed
    local Vault seeded from the scenario's balances.
    K03: the attack() entry-point call must not be pranked as the
    receiver (its owner check would reject it), so the scenario runs.
    On the old generator this test fails three ways: the source keeps
    the placeholder, attack() is pranked (forge test reverts "not
    owner"), and the profit assertion fails.
    """
    if not os.environ.get("FOUNDRY_SOLC"):
        pytest.skip("needs the Foundry toolchain (FOUNDRY_SOLC)")
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge binary not on PATH")
    root = Path(__file__).resolve().parents[1]
    shutil.copytree(root / "contracts/src", tmp_path / "contracts/src")
    shutil.copy(root / "foundry.toml", tmp_path / "foundry.toml")
    data = scenario(
        scenario_id="k02k03",
        attacker=AttackerModel(initial_eth=1.0),
        initial_state=InitialState(
            fork_url="", fork_block=0,
            target_contracts={"vault": "0x1111111111111111111111111111111111111111"},
            balances={"vault": 9.0},
        ),
        steps=[
            TransactionStep(1, "attacker", "vault", "deposit()", value_eth=0.9),
            TransactionStep(2, "attacker", "attacker", "attack()"),
        ],
        success_conditions=[SuccessCondition(
            "attacker.eth_balance_after - attacker.eth_balance_before"
            " > attacker.legitimate_entitlement", "observation",
        )],
    )
    compiler = ScenarioCompiler(target_types={"vault": "IVault"})
    out = tmp_path / "contracts/test/generated"
    path = compiler.compile_to_file(data, out, attacker_contract_name="MaliciousReceiver_demo")
    source = path.read_text()
    # K01: no single-../ import can be produced.
    assert '"../interfaces/' not in source and '"../src/attackers/' not in source
    assert '"../../src/interfaces/IVault.sol"' in source
    # The demo receiver is defined inline by the template when it is the
    # bounded receiver (so no attacker import is emitted for this name);
    # the K01 guard is that every emitted import uses ../../.
    assert "contract MaliciousReceiver_demo {" in source
    # K02: the placeholder is replaced by a deployed Vault.
    assert "0x1111111111111111111111111111111111111111" not in source
    assert "new Vault()" in source
    assert '"../../src/Vault.sol"' in source
    # K03: the deposit step is pranked as the receiver (needed), but the
    # attack() entry-point call is not.
    assert source.count("vm.prank(address(attacker));") == 1
    lines = source.splitlines()
    attack_at = next(i for i, line in enumerate(lines) if "attacker.attack();" in line)
    assert "vm.prank" not in lines[attack_at - 1]
    build = subprocess.run(
        [forge, "build", "--root", str(tmp_path), "--offline"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    run = subprocess.run(
        [forge, "test", "--root", str(tmp_path), "--offline",
         "--match-contract", "ShadowStrike_k02k03", "-vv"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    logs = {}
    for line in run.stdout.splitlines():
        line = line.strip()
        for key in ("attacker_eth_before", "attacker_eth_after"):
            if line.startswith(key + ":"):
                logs[key] = int(line.split(":", 1)[1].strip())
    assert set(logs) == {"attacker_eth_before", "attacker_eth_after"}, run.stdout
    # 1.0 ETH start, 0.9 deposited, 4 x 0.9 withdrawn: 3.7 after, +2.7 net.
    assert logs["attacker_eth_before"] == 10 ** 18
    assert logs["attacker_eth_after"] == 37 * 10 ** 17
    assert logs["attacker_eth_after"] - logs["attacker_eth_before"] == 27 * 10 ** 17


def test_k11b_address_keyed_balance_seeds_deployed_vault():
    """11b (CodeRabbit, Minor): a balance keyed by a replaced target's
    placeholder address must fund the deployed Vault, not the dead
    placeholder. Fails on the Fix 11 code (the deal goes to 0x1111...)."""
    data = scenario(
        scenario_id="k11baddr",
        initial_state=InitialState(
            fork_url="", fork_block=0,
            target_contracts={"vault": "0x1111111111111111111111111111111111111111"},
            balances={"0x1111111111111111111111111111111111111111": 9},
        ),
        steps=[TransactionStep(1, "attacker", "vault", "deposit()", value_eth=0.9)],
    )
    source = ScenarioCompiler(target_types={"vault": "IVault"}).compile(
        data, attacker_contract_name="MaliciousReceiver_demo")
    assert "vm.deal(address(vault), 9 ether);" in source
    assert "0x1111111111111111111111111111111111111111" not in source


def test_k11b_unrelated_caller_keeps_prank():
    """11b (CodeRabbit, Major): an attack() step whose caller is an
    unrelated address keeps its configured prank — the call must still
    fail the receiver's owner check (and an expected_revert scenario
    must still revert). Fails on the Fix 11 code (the prank is skipped
    for every attack() call)."""
    data = scenario(
        scenario_id="k11bcaller",
        initial_state=InitialState(
            fork_url="", fork_block=0,
            target_contracts={"vault": "0x1111111111111111111111111111111111111111"},
            balances={"vault": 9.0},
        ),
        steps=[TransactionStep(
            1, "0x2222222222222222222222222222222222222222", "attacker", "attack()")],
    )
    source = ScenarioCompiler(target_types={"vault": "IVault"}).compile(
        data, attacker_contract_name="MaliciousReceiver_demo")
    lines = source.splitlines()
    attack_at = next(i for i, line in enumerate(lines) if "attacker.attack();" in line)
    # The configured caller is preserved: the line before attack() is a
    # prank for the unrelated address (the emitted literal is the
    # zero-padded form of 0x2222...), not for the receiver.
    assert "vm.prank" in lines[attack_at - 1]
    assert "2222222222222222222222222222222222222222" in lines[attack_at - 1]
    assert "address(attacker)" not in lines[attack_at - 1]


def test_k11b_nonzero_value_attack_funded_by_receiver(tmp_path):
    """11b (CodeRabbit, Major): an attack() step with value must be
    funded from the receiver's own balance, not the test contract's —
    the generator splits it into a receiver-funded deposit, then calls
    attack() with no value. Fails on the Fix 11 code (the value stays
    on the attack call, which the test contract — holding no ETH —
    cannot fund, so the forge test reverts)."""
    if not os.environ.get("FOUNDRY_SOLC"):
        pytest.skip("needs the Foundry toolchain (FOUNDRY_SOLC)")
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge binary not on PATH")
    root = Path(__file__).resolve().parents[1]
    shutil.copytree(root / "contracts/src", tmp_path / "contracts/src")
    shutil.copy(root / "foundry.toml", tmp_path / "foundry.toml")
    data = scenario(
        scenario_id="k11bvalue",
        attacker=AttackerModel(initial_eth=1.0),
        initial_state=InitialState(
            fork_url="", fork_block=0,
            target_contracts={"vault": "0x1111111111111111111111111111111111111111"},
            balances={"vault": 9.0},
        ),
        steps=[TransactionStep(1, "attacker", "attacker", "attack()", value_eth=0.9)],
        success_conditions=[SuccessCondition(
            "attacker.eth_balance_after - attacker.eth_balance_before"
            " > attacker.legitimate_entitlement", "observation",
        )],
    )
    compiler = ScenarioCompiler(target_types={"vault": "IVault"})
    out = tmp_path / "contracts/test/generated"
    path = compiler.compile_to_file(data, out, attacker_contract_name="MaliciousReceiver_demo")
    source = path.read_text()
    # No value on the attack call itself; the stake is a separate
    # deposit from the receiver's own balance.
    assert "attacker.attack{value:" not in source
    assert "vault.deposit{value: 0.9 ether}();" in source
    lines = source.splitlines()
    deposit_at = next(i for i, line in enumerate(lines)
                      if "vault.deposit{value: 0.9 ether}();" in line)
    assert "vm.prank(address(attacker));" in lines[deposit_at - 1]
    run = subprocess.run(
        [forge, "test", "--root", str(tmp_path), "--offline",
         "--match-contract", "ShadowStrike_k11bvalue", "-vv"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    logs = {}
    for line in run.stdout.splitlines():
        line = line.strip()
        for key in ("attacker_eth_before", "attacker_eth_after"):
            if line.startswith(key + ":"):
                logs[key] = int(line.split(":", 1)[1].strip())
    assert set(logs) == {"attacker_eth_before", "attacker_eth_after"}, run.stdout
    # 1.0 ETH start, 0.9 deposited from the receiver's own balance,
    # 4 x 0.9 withdrawn: 3.7 after, +2.7 net — no test-contract money.
    assert logs["attacker_eth_before"] == 10 ** 18
    assert logs["attacker_eth_after"] == 37 * 10 ** 17
    assert logs["attacker_eth_after"] - logs["attacker_eth_before"] == 27 * 10 ** 17


def test_k11c_synthesized_interface_declares_split_deposit(tmp_path):
    """11c (CodeRabbit, Major): the 11b value split emits a deposit call
    on the primary target — when that target has no target_types, its
    synthesized interface is built only from steps that target it
    directly, so an attack-only scenario leaves the interface empty and
    the generated test cannot compile. The interface must declare
    deposit(). Fails on the 11b code (forge build fails: deposit is not
    a member of the empty synthesized interface)."""
    if not os.environ.get("FOUNDRY_SOLC"):
        pytest.skip("needs the Foundry toolchain (FOUNDRY_SOLC)")
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge binary not on PATH")
    root = Path(__file__).resolve().parents[1]
    shutil.copytree(root / "contracts/src", tmp_path / "contracts/src")
    shutil.copy(root / "foundry.toml", tmp_path / "foundry.toml")
    data = scenario(
        scenario_id="k11ciface",
        attacker=AttackerModel(initial_eth=1.0),
        initial_state=InitialState(
            fork_url="", fork_block=0,
            target_contracts={"custom": "0x1111111111111111111111111111111111111111"},
            balances={},
        ),
        steps=[TransactionStep(1, "attacker", "attacker", "attack()", value_eth=0.9)],
    )
    # No target_types: the target interface is synthesized.
    path = ScenarioCompiler().compile_to_file(
        data, tmp_path / "contracts/test/generated",
        attacker_contract_name="MaliciousReceiver_demo")
    source = path.read_text()
    assert "interface IShadowStrike_custom { function deposit() external payable; }" in source
    assert "custom.deposit{value: 0.9 ether}();" in source
    build = subprocess.run(
        [forge, "build", "--root", str(tmp_path), "--offline"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert build.returncode == 0, build.stdout + build.stderr


def test_k11c_expected_revert_value_attack_is_atomic(tmp_path):
    """11c (CodeRabbit, Minor): an attack() step with value AND
    expected_revert must stay one atomic call — splitting the deposit
    out would commit it even when attack() reverts (and could fail
    outside the expected-revert scope). The generator keeps the value
    on attack() and funds the test contract with exactly the stake
    (it rolls back with the revert; no gain is measured for a reverted
    step). Fails on the 11b code (the deposit is split out before
    expectRevert is armed). Verified by source + forge build: a forge
    RUN is not constructible here — the vulnerable Vault never reverts
    a value-bearing attack (its reentry guard stops the drain when the
    vault is empty, so the call succeeds), and SafeVault has no
    generator-deployable interface — so the runtime atomicity rests on
    the single-call form itself (a revert rolls back the whole call,
    including the inner deposit)."""
    if not os.environ.get("FOUNDRY_SOLC"):
        pytest.skip("needs the Foundry toolchain (FOUNDRY_SOLC)")
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge binary not on PATH")
    root = Path(__file__).resolve().parents[1]
    shutil.copytree(root / "contracts/src", tmp_path / "contracts/src")
    shutil.copy(root / "foundry.toml", tmp_path / "foundry.toml")
    data = scenario(
        scenario_id="k11catomic",
        attacker=AttackerModel(initial_eth=1.0),
        initial_state=InitialState(
            fork_url="", fork_block=0,
            target_contracts={"vault": "0x1111111111111111111111111111111111111111"},
            balances={},
        ),
        steps=[TransactionStep(
            1, "attacker", "attacker", "attack()", value_eth=0.9, expected_revert=True)],
        success_conditions=[SuccessCondition(
            "attacker.eth_balance_after == attacker.eth_balance_before", "observation")],
    )
    compiler = ScenarioCompiler(target_types={"vault": "IVault"})
    out = tmp_path / "contracts/test/generated"
    path = compiler.compile_to_file(data, out, attacker_contract_name="MaliciousReceiver_demo")
    source = path.read_text()
    assert "vm.deal(address(this), 0.9 ether);" in source
    assert "attacker.attack{value: 0.9 ether}();" in source
    assert "vault.deposit{value: 0.9 ether}();" not in source
    build = subprocess.run(
        [forge, "build", "--root", str(tmp_path), "--offline"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert build.returncode == 0, build.stdout + build.stderr
