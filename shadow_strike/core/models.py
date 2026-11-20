"""
shadow_strike.core.models
==========================
Scenario schema — the single data contract every other layer speaks.

Design note: this is implemented with stdlib `dataclasses` + manual
validation rather than Pydantic, so the *core engine runs with zero
external dependencies* (important for a security tool: fewer deps =
smaller supply-chain surface, and it means this reference
implementation runs anywhere Python 3.10+ runs, with no `pip install`
required).

The optional API defines its own request models; the dataclasses here
remain the canonical scenario schema.
"""

from __future__ import annotations

import json
import math
import re
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class ShadowStrikeValidationError(ValueError):
    """Raised when a scenario fails structural validation.

    Hit this = the scenario never reaches the Execution Engine. This is
    the enforcement point for principle #3 in the architecture doc:
    'no scenario, no matter who/what authored it, reaches EVM execution
    unvalidated.'
    """


class VulnerabilityClass(str, Enum):
    REENTRANCY = "reentrancy"
    ORACLE_MANIPULATION = "oracle_manipulation"
    FLASH_LOAN = "flash_loan"
    ACCESS_CONTROL = "access_control"
    PRICE_MANIPULATION = "price_manipulation"
    SIGNATURE_REPLAY = "signature_replay"
    ACCOUNTING = "accounting"
    INITIALIZATION = "initialization"
    UPGRADEABILITY = "upgradeability"
    CROSS_CONTRACT = "cross_contract"
    ECONOMIC = "economic"


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def _validate_number(value: Any, name: str, *, integer: bool = False, nonnegative: bool = True) -> None:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or (isinstance(value, float) and not math.isfinite(value))):
        raise ShadowStrikeValidationError(f"{name} must be a finite number")
    if integer and not isinstance(value, int):
        raise ShadowStrikeValidationError(f"{name} must be an integer")
    if nonnegative and value < 0:
        raise ShadowStrikeValidationError(f"{name} cannot be negative")


def _validate_balances(balances: Any, name: str) -> None:
    if not isinstance(balances, dict):
        raise ShadowStrikeValidationError(f"{name} must be a mapping")
    for alias, value in balances.items():
        _validate_number(value, f"{name}[{alias!r}]")


def _valid_signature(signature: Any) -> bool:
    if not isinstance(signature, str):
        return False
    # Tokenize the shape, preserving tuple and array types without attempting
    # ABI type resolution or argument validation (the execution layer's job).
    tokens = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*|[0-9]+|[(),\[\]]", signature)
    if "".join(tokens) != signature or not tokens or not re.fullmatch(
        r"[A-Za-z_$][A-Za-z0-9_$]*", tokens[0]
    ):
        return False
    position = 1
    # Each frame is a parameter list: True means a type is required next.
    if position >= len(tokens) or tokens[position] != "(":
        return False
    position += 1
    frames = [False]
    while position < len(tokens):
        token = tokens[position]
        if token == ")":
            if frames[-1] or (len(frames) > 1 and tokens[position - 1] == "("):
                return False
            frames.pop()
            position += 1
            if not frames:
                return position == len(tokens)
        elif token == ",":
            if frames[-1] or tokens[position - 1] == "(":
                return False
            frames[-1] = True
            position += 1
            continue
        elif token == "(" or re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", token):
            if not frames[-1] and tokens[position - 1] != "(":
                return False
            frames[-1] = False
            position += 1
            if token == "(":
                frames.append(False)
                continue
        else:
            return False
        # Array suffixes can follow a simple type or a completed tuple.
        while position < len(tokens) and tokens[position] == "[":
            position += 1
            if position < len(tokens) and tokens[position].isdigit():
                position += 1
            if position >= len(tokens) or tokens[position] != "]":
                return False
            position += 1
    return False


@dataclass
class AttackerModel:
    address: str = "attacker"
    initial_eth: float = 0.0
    initial_tokens: dict[str, float] = field(default_factory=dict)
    controlled_contracts: list[str] = field(default_factory=list)

    def __post_init__(self):
        _validate_number(self.initial_eth, "attacker.initial_eth")
        _validate_balances(self.initial_tokens, "attacker.initial_tokens")


@dataclass
class TransactionStep:
    step_id: int
    caller: str
    target: str
    function: str
    args: list[Any] = field(default_factory=list)
    value_eth: float = 0.0
    expected_revert: bool = False
    comment: str | None = None

    def __post_init__(self):
        _validate_number(self.step_id, "step_id", integer=True, nonnegative=False)
        if not _valid_signature(self.function):
            raise ShadowStrikeValidationError(
                f"step {self.step_id}: function must be a full signature "
                f"like 'withdraw(uint256)', got {self.function!r}"
            )
        _validate_number(self.value_eth, f"step {self.step_id}: value_eth")


@dataclass
class InitialState:
    fork_url: str
    fork_block: int
    target_contracts: dict[str, str] = field(default_factory=dict)
    balances: dict[str, float] = field(default_factory=dict)
    custom_setup_calls: list[TransactionStep] = field(default_factory=list)

    def __post_init__(self):
        _validate_number(self.fork_block, "fork_block", integer=True)
        _validate_balances(self.balances, "initial_state.balances")
        if not self.target_contracts:
            raise ShadowStrikeValidationError("initial_state.target_contracts cannot be empty")


@dataclass
class SuccessCondition:
    expression: str
    description: str

    def __post_init__(self):
        if not isinstance(self.expression, str):
            raise ShadowStrikeValidationError("success condition expression must be a string")
        if not self.expression.strip():
            raise ShadowStrikeValidationError("success condition expression cannot be empty")


@dataclass
class AttackScenario:
    vulnerability_class: VulnerabilityClass
    target_protocol: str
    hypothesis: str
    attacker: AttackerModel
    initial_state: InitialState
    steps: list[TransactionStep]
    success_conditions: list[SuccessCondition]
    scenario_id: str = field(default_factory=lambda: _new_id("scn"))
    assumptions: list[str] = field(default_factory=list)
    invariants_under_test: list[str] = field(default_factory=list)
    max_retries: int = 3
    # Reentry depth the mock executor's attacker uses. The critic's
    # "increase_max_reentries" adjustment raises this on the next attempt;
    # the mock reads it when constructing the attacker (Part 9).
    attacker_max_reentries: int = 3

    # ---- validation -----------------------------------------------------
    def __post_init__(self):
        try:
            self.vulnerability_class = VulnerabilityClass(self.vulnerability_class)
        except (TypeError, ValueError) as e:
            raise ShadowStrikeValidationError(
                f"invalid vulnerability_class: {self.vulnerability_class!r}"
            ) from e
        if not self.steps:
            raise ShadowStrikeValidationError(
                f"scenario {self.scenario_id}: must have at least one TransactionStep "
                "(a hypothesis with no steps is not a scenario, it's a guess)"
            )
        if not self.success_conditions:
            raise ShadowStrikeValidationError(
                f"scenario {self.scenario_id}: must declare at least one success_condition "
                "— otherwise 'the attack worked' can never be verified, only asserted"
            )
        step_ids = [s.step_id for s in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ShadowStrikeValidationError(f"scenario {self.scenario_id}: duplicate step_id values")
        _validate_number(self.max_retries, "max_retries", integer=True)
        _validate_number(self.attacker_max_reentries, "attacker_max_reentries", integer=True)

    # ---- (de)serialization -----------------------------------------------
    def to_dict(self) -> dict:
        d = asdict(self)
        d["vulnerability_class"] = self.vulnerability_class.value
        return d

    def to_json(self, **kw) -> str:
        kw["allow_nan"] = False
        try:
            return json.dumps(self.to_dict(), default=str, **kw)
        except ValueError as e:
            raise ShadowStrikeValidationError(f"scenario cannot be serialized as JSON: {e}") from e

    @classmethod
    def from_dict(cls, d: dict) -> AttackScenario:
        if not isinstance(d, dict):
            raise ShadowStrikeValidationError("scenario must be a mapping")
        d = dict(d)
        for name in (
            "vulnerability_class", "target_protocol", "hypothesis", "attacker",
            "initial_state", "steps", "success_conditions",
        ):
            if name not in d:
                raise ShadowStrikeValidationError(f"missing required field: {name}")
        try:
            d["attacker"] = AttackerModel(**d["attacker"])
            init_state = dict(d["initial_state"])
            init_state["custom_setup_calls"] = [
                TransactionStep(**s) for s in init_state.get("custom_setup_calls", [])
            ]
            d["initial_state"] = InitialState(**init_state)
            d["steps"] = [TransactionStep(**s) for s in d["steps"]]
            d["success_conditions"] = [SuccessCondition(**s) for s in d["success_conditions"]]
            return cls(**d)
        except ShadowStrikeValidationError:
            raise
        except (TypeError, ValueError, KeyError) as e:
            raise ShadowStrikeValidationError(f"invalid scenario structure: {e}") from e

    @classmethod
    def from_json(cls, s: str) -> AttackScenario:
        return cls.from_dict(json.loads(s))


@dataclass
class ExecutionResult:
    scenario_id: str
    reverted: bool
    revert_reason: str | None
    state_vars: dict[str, Any]           # nested condition context; ETH balances (see execution/STATE_PROTOCOL.md)
    state_diff: dict[str, Any]
    call_trace: list[dict]
    raw_logs: list[str] = field(default_factory=list)
    engine: str = "unknown"              # "foundry" | "mock" — always stamped, never silent

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class VerificationResult:
    scenario_id: str
    verified: bool
    condition_results: list[dict]
    invariant_violations: list[str]
    proof_artifact: dict
    verdict: str = "inconclusive"

    def to_dict(self) -> dict:
        return asdict(self)
