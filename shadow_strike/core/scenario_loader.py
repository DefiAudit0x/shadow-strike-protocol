"""
shadow_strike.core.scenario_loader
=====================================
The hand-authoring path for vulnerability classes with no automatic
scenario_planner builder (accounting, upgradeability, cross_contract,
economic — see attack_library/*/meta.yaml "roadmap" notes for why
those specifically resist genericization).

A researcher writes the scenario shape in YAML (same fields as
AttackScenario, just as data a human can read/review/diff in a PR
instead of Python); this loader validates it through the exact same
AttackScenario.__post_init__ path everything else goes through — no
separate, weaker validation path for hand-authored scenarios.

Once loaded, a hand-authored scenario runs through compiler.py /
mock_executor.py / foundry_runner.py / verifier.py identically to a
planner-generated one — the rest of the pipeline cannot tell the
difference, by design.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from shadow_strike.core.models import (
    AttackerModel,
    AttackScenario,
    InitialState,
    SuccessCondition,
    TransactionStep,
)


class ScenarioFileError(ValueError):
    """Raised for YAML syntax, structure, type, and scenario validation errors.

    File I/O errors retain their original exception types.
    """


def load_scenario_yaml(path: str | Path) -> AttackScenario:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ScenarioFileError(f"{path}: invalid YAML: {e}") from e

    if not isinstance(raw, dict):
        raise ScenarioFileError(f"{path}: top level must be a mapping, got {type(raw).__name__}")

    unknown = raw.keys() - AttackScenario.__dataclass_fields__.keys()
    if unknown:
        raise ScenarioFileError(f"{path}: unknown top-level field(s): {sorted(unknown, key=str)}")

    required_top = {"vulnerability_class", "target_protocol", "hypothesis", "initial_state", "steps", "success_conditions"}
    missing = required_top - raw.keys()
    if missing:
        raise ScenarioFileError(f"{path}: missing required field(s): {sorted(missing)}")

    try:
        attacker = AttackerModel(**raw.get("attacker", {}))

        init_raw = dict(raw["initial_state"])
        init_raw["custom_setup_calls"] = [
            TransactionStep(**s) for s in init_raw.get("custom_setup_calls", [])
        ]
        initial_state = InitialState(**init_raw)

        steps = [TransactionStep(**s) for s in raw["steps"]]
        success_conditions = [SuccessCondition(**s) for s in raw["success_conditions"]]

        scenario = AttackScenario(
            vulnerability_class=raw["vulnerability_class"],
            target_protocol=raw["target_protocol"],
            hypothesis=raw["hypothesis"],
            attacker=attacker,
            initial_state=initial_state,
            steps=steps,
            success_conditions=success_conditions,
            scenario_id=raw.get("scenario_id") or AttackScenario.__dataclass_fields__["scenario_id"].default_factory(),
            assumptions=raw.get("assumptions", []),
            invariants_under_test=raw.get("invariants_under_test", []),
            max_retries=raw.get("max_retries", 3),
            attacker_max_reentries=raw.get("attacker_max_reentries", 3),
        )
    except (TypeError, ValueError, KeyError, AttributeError) as e:
        # TypeError catches "unexpected keyword argument" from a typo'd
        # field name in the YAML — surfaced as a ScenarioFileError too,
        # not a raw Python traceback a researcher has to decode.
        raise ScenarioFileError(f"{path}: {e}") from e

    return scenario


def save_scenario_yaml(scenario: AttackScenario, path: str | Path) -> Path:
    """Round-trip the other direction — useful for turning a
    planner-generated scenario into a YAML file a human can then hand-edit
    and check into version control alongside the finding it produced."""
    path = Path(path)
    data = scenario.to_dict()
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path
