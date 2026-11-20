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

# Solidity 0.8 keywords, reserved words, and elementary type names.
_RESERVED = {
    'abstract', 'address', 'after', 'alias', 'anonymous', 'apply', 'as', 'assembly', 'auto', 'bool',
    'break', 'byte', 'bytes', 'calldata', 'case', 'catch', 'constant', 'constructor', 'continue',
    'contract', 'copyof', 'default', 'define', 'delete', 'do', 'else', 'emit', 'enum', 'error', 'ether',
    'event', 'external', 'fallback', 'false', 'final', 'fixed', 'for', 'from', 'function', 'gwei',
    'hex', 'if', 'immutable', 'implements', 'import', 'in', 'indexed', 'inline', 'int', 'interface',
    'internal', 'is', 'let', 'library', 'macro', 'mapping', 'match', 'memory', 'modifier', 'mutable',
    'new', 'null', 'of', 'override', 'partial', 'payable', 'pragma', 'private', 'promise', 'public',
    'pure', 'receive', 'reference', 'relocatable', 'return', 'returns', 'revert', 'sealed', 'seconds',
    'sizeof', 'static', 'storage', 'string', 'struct', 'super', 'supports', 'switch', 'this', 'throw',
    'true', 'try', 'tuple', 'type', 'typedef', 'typeof', 'ufixed', 'uint', 'unchecked', 'unicode',
    'using', 'var', 'view', 'virtual', 'weeks', 'wei', 'while', 'years'
}
_RESERVED.update(f"{prefix}{bits}" for prefix in ("uint", "int") for bits in range(8, 257, 8))
_RESERVED.update(f"bytes{size}" for size in range(1, 33))

TEMPLATES_DIR = Path(__file__).parent / "templates"


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", value):
        raise ShadowStrikeValidationError("Invalid Solidity identifier")
    if value in _RESERVED or re.fullmatch(r"u?fixed[0-9]+x[0-9]+", value):
        raise ShadowStrikeValidationError("Reserved Solidity identifier")
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


def _abi_types(signature: str) -> tuple[str, list[str]]:
    match = re.fullmatch(r"([A-Za-z_$][A-Za-z0-9_$]*)\(([^()]*)\)", signature)
    if not match:
        raise ShadowStrikeValidationError("Unsupported Solidity function signature")
    name = _identifier(match[1])
    types = match[2].split(",") if match[2] else []
    for abi_type in types:
        if not re.fullmatch(r"string|address|bool|bytes(?:[1-9]|[12][0-9]|3[0-2])?|u?int(?:[0-9]+)?", abi_type):
            raise ShadowStrikeValidationError(f"Unsupported ABI type: {abi_type}")
        if abi_type.startswith(("uint", "int")):
            bits = int(re.sub(r"^u?int", "", abi_type) or "256")
            if bits not in range(8, 257, 8):
                raise ShadowStrikeValidationError("Invalid ABI integer width")
    return name, types


def _argument(value, abi_type: str) -> str:
    if abi_type == "string" and isinstance(value, str):
        return _string_literal(value)
    if abi_type == "address":
        # The leading zero prevents Solidity's address-checksum literal heuristic.
        return f"address(0x00{_address(value)[2:]})"
    if abi_type == "bool" and type(value) is bool:
        return "true" if value else "false"
    if abi_type.startswith(("uint", "int")):
        bits = int(re.sub(r"^u?int", "", abi_type) or "256")
        signed = abi_type.startswith("int")
        if isinstance(value, str) and re.fullmatch(r"-?(?:0x[0-9a-fA-F]+|[0-9]+)", value):
            value = int(value, 16 if "0x" in value else 10)
        minimum = -(2 ** (bits - 1)) if signed else 0
        maximum = 2 ** (bits - 1) if signed else 2 ** bits
        if type(value) is int and minimum <= value < maximum:
            return f"{abi_type}({value})"
    if abi_type.startswith("bytes") and isinstance(value, str):
        size = abi_type[5:]
        if re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value) and (not size or len(value[2:]) == int(size) * 2):
            return f'hex"{value[2:]}"'
    raise ShadowStrikeValidationError(f"Invalid argument for ABI type {abi_type}")


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
        Unlisted targets receive a generated interface from their call signatures.
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

        record_state_diff: use vm.record() / vm.accesses(address) to emit
        written storage slot identifiers and counts for each target. No
        before/after storage values or full state diff are captured. ETH
        balance snapshots and optional public getter observations are separate.
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
        all_steps = scenario.initial_state.custom_setup_calls + scenario.steps
        interfaces = []
        import_lines = []
        contract_decls = []
        setup_lines = []

        for alias, address in scenario.initial_state.target_contracts.items():
            _identifier(alias)
            _address(address)
            sol_type = self.target_types.get(alias)
            if sol_type:
                _identifier(sol_type)
                import_lines.append(f'import {{{sol_type}}} from "../../src/interfaces/{sol_type}.sol";')
            else:
                sol_type = f"IShadowStrike_{alias}"
                methods = set()
                for step in all_steps:
                    if step.target == alias:
                        name, types = _abi_types(step.function)
                        params = ", ".join(t + (" calldata" if t in ("string", "bytes") else "")
                                           for t in types)
                        methods.add(f"function {name}({params}) external payable;")
                interfaces.append(f"interface {sol_type} {{ " + " ".join(sorted(methods)) + " }")
            contract_decls.append(f"{sol_type} {alias};")
            if address.lower() == "0x" + "1" * 40 and sol_type == "IVault":
                # K02: the placeholder address is undeployed — bind a
                # real local Vault instead. The scenario's balances seed
                # its reserve (the vm.deal loop below), so a generated
                # test executes end-to-end against a real contract.
                import_lines.append('import {Vault} from "../../src/Vault.sol";')
                setup_lines.append(f"{alias} = {sol_type}(address(new Vault()));")
            else:
                setup_lines.append(f"{alias} = {sol_type}({_argument(address, 'address')});")

        bounded_receiver = attacker_contract_name == "MaliciousReceiver_demo" or (
            not attacker_contract_name and scenario.vulnerability_class.value == "reentrancy"
            and any(step.target == "attacker" and step.function == "attack()" for step in all_steps)
        )
        if bounded_receiver and not attacker_contract_name:
            attacker_contract_name = "ShadowStrikeBoundedReceiver"
        if type(scenario.attacker_max_reentries) is not int or scenario.attacker_max_reentries < 0:
            raise ShadowStrikeValidationError("attacker_max_reentries must be a nonnegative integer")
        if attacker_contract_name:
            _identifier(attacker_contract_name)
            attacker_import_path = (
                attacker_import_path or f"../../src/attackers/{attacker_contract_name}.sol"
            )
            if not re.fullmatch(r"[A-Za-z0-9_./-]+\.sol", attacker_import_path):
                raise ShadowStrikeValidationError("Invalid Solidity import path")
            if not bounded_receiver:
                import_lines.append(f'import {{{attacker_contract_name}}} from "{attacker_import_path}";')
            receiver_type = attacker_contract_name
            contract_decls.append(f"{receiver_type} attacker;")
            primary_target = next(iter(scenario.initial_state.target_contracts), None)
            setup_lines.append(
                f"attacker = new {receiver_type}(address({primary_target})"
                + (f", {scenario.attacker_max_reentries}" if bounded_receiver else "") + ");"
            )
            setup_lines.append(f"vm.deal(address(attacker), {scenario.attacker.initial_eth} ether);")

        if not attacker_contract_name:
            contract_decls.append("address attacker;")
            setup_lines.extend(['attacker = makeAddr("attacker");',
                                f"vm.deal(attacker, {scenario.attacker.initial_eth} ether);"])

        def account(alias: str) -> str:
            if alias in scenario.initial_state.target_contracts or alias == "attacker":
                return f"address({alias})"
            return _argument(alias, "address")

        for alias, amount in scenario.initial_state.balances.items():
            if type(amount) not in (int, float) or not math.isfinite(amount) or amount < 0:
                raise ShadowStrikeValidationError("ETH amounts must be finite nonnegative numbers")
            setup_lines.append(f"vm.deal({account(alias)}, {amount} ether);")
        for token, amount in scenario.attacker.initial_tokens.items():
            # forge-std's ERC20 deal seeds base units without assuming a mint API.
            if type(amount) is float and math.isfinite(amount) and amount.is_integer():
                amount = int(amount)
            encoded = _argument(amount, "uint256")
            setup_lines.append(f"deal({account(token)}, address(attacker), {encoded});")

        def render_step(step) -> list[str]:
            fn_name, types = _abi_types(step.function)
            _identifier(step.target)
            if step.target not in scenario.initial_state.target_contracts and step.target != "attacker":
                raise ShadowStrikeValidationError("Unknown step target")
            if type(step.step_id) is not int:
                raise ShadowStrikeValidationError("step_id must be an integer")
            if len(types) != len(step.args):
                raise ShadowStrikeValidationError("ABI argument count mismatch")
            args_str = ", ".join(_argument(a, t) for a, t in zip(step.args, types))
            if type(step.value_eth) not in (int, float) or not math.isfinite(step.value_eth) or step.value_eth < 0:
                raise ShadowStrikeValidationError("ETH amounts must be finite nonnegative numbers")
            caller_expr = "address(attacker)" if step.caller == "attacker" else _argument(step.caller, "address")
            value_clause = f"{{value: {step.value_eth} ether}}" if step.value_eth else ""
            lines = [f"// step {step.step_id}" + (f" — {_comment(step.comment)}" if step.comment else "")]
            if step.expected_revert:
                lines.append("vm.expectRevert();")
            # K03: a step calling the receiver contract's attack() entry
            # point must come from the test contract, which deployed the
            # receiver and is its owner — pranking as the receiver trips
            # the receiver's owner check ("not owner") and the call can
            # never run. Other steps keep their prank (e.g. a deposit
            # that must credit the receiver's address).
            if not (step.target == "attacker" and fn_name == "attack" and attacker_contract_name):
                lines.append(f"vm.prank({caller_expr});")
            if step.target == "attacker" and not attacker_contract_name:
                payload = _string_literal(step.function) + (", " + args_str if args_str else "")
                # Keep each result scoped so repeated step IDs in setup cannot collide.
                lines.append(f"{{ (bool ok,) = attacker.call{value_clause}(abi.encodeWithSignature({payload})); "
                             + ("ok; }" if step.expected_revert else 'require(ok, "scenario call failed"); }'))
            else:
                lines.append(f"{step.target}.{fn_name}{value_clause}({args_str});")
            return lines

        for step in scenario.initial_state.custom_setup_calls:
            setup_lines.extend(render_step(step))

        before_snapshot_lines = [
            "uint256 _attackerEthBefore = address(attacker).balance;" if attacker_contract_name
            else "uint256 _attackerEthBefore = attacker.balance;",
        ]
        for alias in scenario.initial_state.target_contracts:
            before_snapshot_lines.append(
                f"uint256 _{alias}EthBefore = address({alias}).balance;"
            )

        step_lines = []
        if record_state_diff:
            step_lines.append("vm.record();  // forge-std cheatcode — begin tracking SLOAD/SSTORE")
        for step in scenario.steps:
            step_lines.extend(render_step(step))

        after_snapshot_lines = [
            "uint256 _attackerEthAfter = address(attacker).balance;" if attacker_contract_name
            else "uint256 _attackerEthAfter = attacker.balance;",
        ]
        for alias in scenario.initial_state.target_contracts:
            after_snapshot_lines.append(
                f"uint256 _{alias}EthAfter = address({alias}).balance;"
            )

        # Effective starting funding: initial_state.balances overrides replace
        # initial_eth for the vm.deal funding above, so the emitted entitlement
        # must follow the override (same rule as MockExecutor).
        effective_attacker_eth = scenario.initial_state.balances.get(
            "attacker", scenario.attacker.initial_eth)
        emit_lines = [
            'emit log_named_uint("attacker_eth_before", _attackerEthBefore);',
            'emit log_named_uint("attacker_eth_after", _attackerEthAfter);',
        ]
        emit_lines.extend([
            'emit log_named_address("ss.attacker.address", address(attacker));',
            f'emit log_named_uint("ss.attacker.legitimate_entitlement", {effective_attacker_eth} ether);',
        ])
        for alias in scenario.initial_state.target_contracts:
            for field, getters in {
                "owner": ("owner()",),
                "last_caller": ("last_caller()", "lastCaller()"),
                "replay_count": ("replay_count()", "replayCount()"),
                "victim_shares": ("victim_shares()", "victimShares()"),
                "attacker_balance": ("attacker_balance()", "attackerBalance()"),
            }.items():
                for getter in getters:
                    emit_lines.append(
                        f'_emitState(address({alias}), "ss.{alias}.{field}", "{getter}", '
                        f'{str(field in ("owner", "last_caller")).lower()});'
                    )
            emit_lines.append(f'emit log_named_uint("{alias}_eth_before", _{alias}EthBefore);')
            emit_lines.append(f'emit log_named_uint("{alias}_eth_after", _{alias}EthAfter);')

        if record_state_diff:
            # vm.accesses reports accessed slots, not their before/after values.
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
            "interface_lines": interfaces,
            "bounded_receiver": bounded_receiver,
            "receiver_type": attacker_contract_name,
            "contract_decls": contract_decls,
            "setup_lines": setup_lines,
            "before_snapshot_lines": before_snapshot_lines,
            "step_lines": step_lines,
            "after_snapshot_lines": after_snapshot_lines,
            "emit_lines": emit_lines,
            "assertion_lines": assertion_lines,
        }
