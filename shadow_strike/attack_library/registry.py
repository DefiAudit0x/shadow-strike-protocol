"""
shadow_strike.attack_library.registry
=======================================
Loads one `meta.yaml` per vulnerability-class subfolder and exposes it
as a plain dict. Adding a new attack class = adding a new folder with
a meta.yaml + attacker template — nothing in the core engine changes.
"""

from __future__ import annotations

from pathlib import Path
import yaml

LIBRARY_ROOT = Path(__file__).parent


class AttackLibrary:
    def __init__(self, root: Path | None = None):
        self.root = root or LIBRARY_ROOT
        self._cache: dict[str, dict] = {}
        self._load_all()

    def _load_all(self) -> None:
        for sub in sorted(self.root.iterdir()):
            meta_path = sub / "meta.yaml"
            if sub.is_dir() and meta_path.exists():
                with open(meta_path, encoding="utf-8") as f:
                    meta = yaml.safe_load(f)
                meta["_dir"] = str(sub)
                self._cache[meta["vulnerability_class"]] = meta

    def available_classes(self) -> list[str]:
        return sorted(self._cache.keys())

    def get(self, vulnerability_class: str) -> dict:
        if vulnerability_class not in self._cache:
            raise KeyError(
                f"no attack-library entry for {vulnerability_class!r}. "
                f"available: {self.available_classes()}"
            )
        return self._cache[vulnerability_class]

    def attacker_template_path(self, vulnerability_class: str) -> Path:
        meta = self.get(vulnerability_class)
        return Path(meta["_dir"]) / meta["attacker_template"]

    def heuristic_patterns(self, vulnerability_class: str) -> list[dict]:
        return self.get(vulnerability_class).get("heuristic_source_patterns", [])

    def default_invariants(self, vulnerability_class: str) -> list[str]:
        return self.get(vulnerability_class).get("default_invariants", [])

    def default_success_conditions(self, vulnerability_class: str) -> list[dict]:
        return self.get(vulnerability_class).get("default_success_conditions", [])
