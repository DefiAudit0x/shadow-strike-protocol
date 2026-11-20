import ast
import unittest
from contextlib import redirect_stdout
from io import StringIO

import yaml

from shadow_strike.attack_library.registry import LIBRARY_ROOT, AttackLibrary
from shadow_strike.cli import cmd_library
from shadow_strike.core.safe_eval import EMITTABLE_STATE_NAMES, safe_eval


class TestAttackLibraryDefaults(unittest.TestCase):
    def test_library_has_no_unsupported_attacker_templates(self):
        library = AttackLibrary()
        self.assertEqual(len(library.available_classes()), 11)
        self.assertEqual(list(LIBRARY_ROOT.rglob("*.sol.j2")), [])
        self.assertFalse(hasattr(library, "attacker_template_path"))
        for vulnerability_class in library.available_classes():
            with self.subTest(vulnerability_class=vulnerability_class):
                self.assertNotIn("attacker_template", library.get(vulnerability_class))

    def test_library_cli_lists_metadata_without_template_claims(self):
        output = StringIO()
        with redirect_stdout(output):
            cmd_library(None)
        lines = output.getvalue().splitlines()
        library = AttackLibrary()
        self.assertEqual(len(lines), len(library.available_classes()))
        self.assertNotIn("template=", output.getvalue())
        for line, vulnerability_class in zip(lines, library.available_classes()):
            self.assertEqual(line.split()[0], vulnerability_class)
            self.assertIn(library.get(vulnerability_class)["display_name"], line)

    def test_all_defaults_use_emittable_state(self):
        paths = sorted(LIBRARY_ROOT.glob("*/meta.yaml"))
        self.assertEqual(len(paths), 11)
        target_alias = "sample_target"
        context = {
            "attacker": {
                "eth_balance_before": 1.0,
                "eth_balance_after": 2.0,
                "legitimate_entitlement": 1.0,
            },
            target_alias: {"last_caller": "deployer"},
        }
        for path in paths:
            meta = yaml.safe_load(path.read_text(encoding="utf-8"))
            expressions = meta["default_invariants"] + [
                condition["expression"] for condition in meta["default_success_conditions"]
            ]
            allowed_names = EMITTABLE_STATE_NAMES
            if path.parent.name == "access_control":
                # This builder already resolves {target} to the primary alias.
                allowed_names = {name.replace("{target}", target_alias) for name in allowed_names}
            for expression in expressions:
                with self.subTest(path=path, expression=expression):
                    resolved = expression
                    if path.parent.name == "access_control":
                        resolved = resolved.replace("{target}", target_alias)
                    nodes = list(ast.walk(ast.parse(resolved, mode="eval")))
                    self.assertFalse(any(isinstance(node, ast.Call) for node in nodes))
                    attribute_bases = {node.value for node in nodes if isinstance(node, ast.Attribute)}
                    names = {
                        ast.unparse(node)
                        for node in nodes
                        if isinstance(node, (ast.Name, ast.Attribute)) and node not in attribute_bases
                    }
                    self.assertEqual(names - allowed_names, set())
                    safe_eval(resolved, context)
