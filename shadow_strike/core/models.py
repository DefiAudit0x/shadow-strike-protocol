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

A drop-in Pydantic v2 version (`shadow_strike.core.pydantic_models`)
is provided separately for teams that want JSON-schema export / FastAPI
integration — same field names, same semantics, so scenarios produced
by one are readable by the other.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
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


@dataclass
class AttackerModel:
    address: str = "attacker"
    initial_eth: float = 0.0
    initial_tokens: dict[str, float] = field(default_factory=dict)
    controlled_contracts: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.initial_eth < 0:
            raise ShadowStrikeValidationError("attacker.initial_eth cannot be negative")


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
        if "(" not in self.function or not self.function.endswith(")"):
            raise ShadowStrikeValidationError(
                f"step {self.step_id}: function must be a full signature "
                f"like 'withdraw(uint256)', got {self.function!r}"
            )
        if self.value_eth < 0:
            raise ShadowStrikeValidationError(f"step {self.step_id}: value_eth cannot be negative")


@dataclass
class InitialState:
    fork_url: str
    fork_block: int
    target_contracts: dict[str, str] = field(default_factory=dict)
    balances: dict[str, float] = field(default_factory=dict)
    custom_setup_calls: list[TransactionStep] = field(default_factory=list)

    def __post_init__(self):
        if self.fork_block < 0:
            raise ShadowStrikeValidationError("fork_block cannot be negative")
        if not self.target_contracts:
            raise ShadowStrikeValidationError("initial_state.target_contracts cannot be empty")


@dataclass
class SuccessCondition:
    expression: str
    description: str

    def __post_init__(self):
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

    # ---- validation -----------------------------------------------------
    def __post_init__(self):
        if isinstance(self.vulnerability_class, str):
            self.vulnerability_class = VulnerabilityClass(self.vulnerability_class)
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
        if self.max_retries < 0:
            raise ShadowStrikeValidationError("max_retries cannot be negative")

    # ---- (de)serialization -----------------------------------------------
    def to_dict(self) -> dict:
        d = asdict(self)
        d["vulnerability_class"] = self.vulnerability_class.value
        return d

    def to_json(self, **kw) -> str:
        return json.dumps(self.to_dict(), default=str, **kw)

    @classmethod
    def from_dict(cls, d: dict) -> "AttackScenario":
        d = dict(d)
        d["attacker"] = AttackerModel(**d["attacker"])
        init_state = dict(d["initial_state"])
        init_state["custom_setup_calls"] = [
            TransactionStep(**s) for s in init_state.get("custom_setup_calls", [])
        ]
        d["initial_state"] = InitialState(**init_state)
        d["steps"] = [TransactionStep(**s) for s in d["steps"]]
        d["success_conditions"] = [SuccessCondition(**s) for s in d["success_conditions"]]
        return cls(**d)

    @classmethod
    def from_json(cls, s: str) -> "AttackScenario":
        return cls.from_dict(json.loads(s))


@dataclass
class ExecutionResult:
    scenario_id: str
    reverted: bool
    revert_reason: str | None
    state_vars: dict[str, Any]           # flattened variables available to success_conditions
    state_diff: dict[str, Any]
    call_trace: list[dict]
    gas_used: int
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

    def to_dict(self) -> dict:
        return asdict(self)
