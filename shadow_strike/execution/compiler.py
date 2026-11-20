"""
shadow_strike.execution.compiler
==================================
Scenario Compiler: AttackScenario (data) -> real Foundry .t.sol file (code).

This is the one place in the system where "structured data chosen by an
LLM" turns into "Solidity that will actually execute." Keeping this
boundary narrow and template-driven (rather than letting the LLM emit
Solidity directly) is what makes the pipeline auditable: you can always
diff a generated .t.sol against the scenario JSON that produced it.
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from urllib.parse import urlsplit

from jinja2 import Environment, FileSystemLoader

from shadow_strike.core.models import AttackScenario, ShadowStrikeValidationError

TEMPLATES_DIR = Path(__file__).parent / "templates"


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", value):
        raise ShadowStrikeValidationError("Invalid Solidity identifier")
    return value


def _comment(value: str) -> str:
    # Keep all scenario prose on a single source line, including Unicode separators.
    return " ".join(value.splitlines()).replace("*/", "* /").replace("/*", "/ *")


def _string_literal(value: str) -> str:
    # Encode UTF-8 bytes so even control characters and Unicode remain data.
    escaped = "".join(
        chr(byte) if 32 <= byte < 127 and byte not in (34, 92)
        else f"\\x{byte:02x}" for byte in value.encode("utf-8")
    )
    return '"' + escaped + '"'


def _argument(value) -> str:
    if isinstance(value, str):
        return _string_literal(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if type(value) is int or (type(value) is float and math.isfinite(value)):
        return str(value)
    raise ShadowStrikeValidationError("Unsupported Solidity argument type")


def _address(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
        raise ShadowStrikeValidationError("Expected a 20-byte Solidity address")
    return value


def _fork_url(value: str) -> str:
    if value == "":
        return ""  # Explicit local, non-forked mode.
    if not isinstance(value, str) or any(c.isspace() or ord(c) < 32 or c in "\"'\\" for c in value):
        raise ShadowStrikeValidationError("fork_url must be an HTTP(S) URL without quotes or whitespace")
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.port == 0:
            raise ValueError
    except ValueError as exc:
        raise ShadowStrikeValidationError("fork_url must be a valid HTTP(S) URL") from exc
    return _string_literal(value)


class ScenarioCompiler:
    def __init__(self, target_types: dict[str, str] | None = None):
        """
        target_types: alias -> Solidity interface/type name, e.g.
            {"vault": "IVault"}
        Falls back to raw `address` if an alias isn't listed (the
        generated test will still compile; it just won't have typed
        calls into that contract — fine for ETH-only interactions).
        """
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.target_types = target_types or {}

    def compile(
        self,
        scenario: AttackScenario,
        attacker_contract_name: str | None = None,
        attacker_import_path: str | None = None,
        record_state_diff: bool = True,
    ) -> str:
        """Return the rendered Solidity source for `scenario` as a string.

        record_state_diff: wraps the attack steps in Foundry's real
        vm.record() / vm.accesses(address) cheatcodes (forge-std's Vm
        interface — not a Shadow Strike invention) and emits every
        touched storage slot's before/after value. This is what lets
        foundry_runner.py populate ExecutionResult.state_diff with
        actual slot-level data instead of just the ETH-balance emits —
        closing the TODO noted in earlier versions of this file.
        """
        ctx = self._build_context(scenario, attacker_contract_name, attacker_import_path, record_state_diff)
        template = self.env.get_template("scenario_test.sol.j2")
        return template.render(**ctx)

    def compile_to_file(self, scenario: AttackScenario, out_dir: Path, **kw) -> Path:
        out_dir = Path(out_dir)
        source = self.compile(scenario, **kw)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"ShadowStrike_{scenario.scenario_id}.t.sol"
        out_path.write_text(source, encoding="utf-8")
        return out_path

    # ------------------------------------------------------------------
    def _build_context(
        self,
        scenario: AttackScenario,
        attacker_contract_name: str | None,
        attacker_import_path: str | None,
        record_state_diff: bool = True,
    ) -> dict:
        _identifier(scenario.scenario_id)
        fork_url = _fork_url(scenario.initial_state.fork_url)
        if type(scenario.initial_state.fork_block) is not int or scenario.initial_state.fork_block < 0:
            raise ShadowStrikeValidationError("fork_block must be a nonnegative integer")
        for amount in [scenario.attacker.initial_eth, *(step.value_eth for step in scenario.steps)]:
            if type(amount) not in (int, float) or not math.isfinite(amount) or amount < 0:
                raise ShadowStrikeValidationError("ETH amounts must be finite nonnegative numbers")
        import_lines = []
        contract_decls = []
        setup_lines = []

        for alias, address in scenario.initial_state.target_contracts.items():
            _identifier(alias)
            _address(address)
            sol_type = _identifier(self.target_types.get(alias, "address"))
            if sol_type != "address":
                import_lines.append(f'import {{{sol_type}}} from "../../src/interfaces/{sol_type}.sol";')
            contract_decls.append(f"{sol_type} {alias};")
            setup_lines.append(f"{alias} = {sol_type}({address});")

        if attacker_contract_name:
            _identifier(attacker_contract_name)
            attacker_import_path = (
                attacker_import_path or f"../../src/attackers/{attacker_contract_name}.sol"
            )
            if not re.fullmatch(r"[A-Za-z0-9_./-]+\.sol", attacker_import_path):
                raise ShadowStrikeValidationError("Invalid Solidity import path")
            import_lines.append(
                f'import {{{attacker_contract_name}}} from "{attacker_import_path}";'
            )
            contract_decls.append(f"{attacker_contract_name} attacker;")
            primary_target = next(iter(scenario.initial_state.target_contracts), None)
            setup_lines.append(
                f"attacker = new {attacker_contract_name}(address({primary_target}));"
            )
            setup_lines.append(f"vm.deal(address(attacker), {scenario.attacker.initial_eth} ether);")

        before_snapshot_lines = [
            "uint256 _attackerEthBefore = address(attacker).balance;" if attacker_contract_name
            else "uint256 _attackerEthBefore = 0;",
        ]
        for alias in scenario.initial_state.target_contracts:
            before_snapshot_lines.append(
                f"uint256 _{alias}EthBefore = address({alias}).balance;"
            )

        step_lines = []
        if record_state_diff:
            step_lines.append("vm.record();  // forge-std cheatcode — begin tracking SLOAD/SSTORE")
        for step in scenario.steps:
            fn_name = _identifier(step.function.split("(")[0])
            _identifier(step.target)
            if step.target not in scenario.initial_state.target_contracts and step.target != "attacker":
                raise ShadowStrikeValidationError("Unknown step target")
            if type(step.step_id) is not int:
                raise ShadowStrikeValidationError("step_id must be an integer")
            args_str = ", ".join(_argument(a) for a in step.args)
            caller_expr = "address(attacker)" if step.caller == "attacker" else _address(step.caller)
            value_clause = (
                f"{{value: {step.value_eth} ether}}" if step.value_eth and step.value_eth > 0 else ""
            )
            step_lines.append(f"// step {step.step_id}" + (f" — {_comment(step.comment)}" if step.comment else ""))
            if step.expected_revert:
                step_lines.append("vm.expectRevert();")
            step_lines.append(f"vm.prank({caller_expr});")
            step_lines.append(f"{step.target}.{fn_name}{value_clause}({args_str});")

        after_snapshot_lines = [
            "uint256 _attackerEthAfter = address(attacker).balance;" if attacker_contract_name
            else "uint256 _attackerEthAfter = 0;",
        ]
        for alias in scenario.initial_state.target_contracts:
            after_snapshot_lines.append(
                f"uint256 _{alias}EthAfter = address({alias}).balance;"
            )

        emit_lines = [
            'emit log_named_uint("attacker_eth_before", _attackerEthBefore);',
            'emit log_named_uint("attacker_eth_after", _attackerEthAfter);',
        ]
        for alias in scenario.initial_state.target_contracts:
            emit_lines.append(f'emit log_named_uint("{alias}_eth_before", _{alias}EthBefore);')
            emit_lines.append(f'emit log_named_uint("{alias}_eth_after", _{alias}EthAfter);')

        if record_state_diff:
            # vm.accesses(addr) returns (bytes32[] reads, bytes32[] writes)
            # for every slot touched on `addr` since the matching
            # vm.record() above — this is how foundry_runner.py's
            # _extract_state_diff() below gets real slot-level data,
            # not just the ETH-balance emits.
            for alias in scenario.initial_state.target_contracts:
                emit_lines.append(
                    f"(, bytes32[] memory _{alias}Writes) = vm.accesses(address({alias}));"
                )
                emit_lines.append(f'emit log_named_uint("{alias}_slots_written", _{alias}Writes.length);')
                emit_lines.append(
                    f"for (uint256 i = 0; i < _{alias}Writes.length; i++) {{ "
                    f'emit log_named_bytes32("{alias}_written_slot", _{alias}Writes[i]); }}'
                )

        assertion_lines = [
            "// NOTE: intentionally does not assertTrue() on success_conditions here —",
            "// doing so would make forge's pass/fail the verdict, which re-couples",
            "// verification to the execution layer. The emitted logs above are",
            "// parsed by shadow_strike.verifier instead; see architecture §2.4.",
        ]

        return {
            "scenario_id": scenario.scenario_id,
            "vulnerability_class": scenario.vulnerability_class.value,
            "hypothesis": _comment(scenario.hypothesis),
            "fork_url": fork_url,
            "fork_block": scenario.initial_state.fork_block,
            "import_lines": import_lines,
            "contract_decls": contract_decls,
            "setup_lines": setup_lines,
            "before_snapshot_lines": before_snapshot_lines,
            "step_lines": step_lines,
            "after_snapshot_lines": after_snapshot_lines,
            "emit_lines": emit_lines,
            "assertion_lines": assertion_lines,
        }
