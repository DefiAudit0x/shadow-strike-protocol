"""
shadow_strike.core.safe_eval
=============================
A restricted expression evaluator for `success_conditions` and
`invariants_under_test`.

Why this file exists: those expressions can originate from an LLM
(scenario_planner_node). Never, under any circumstance, feed that
string to Python's `eval()` — that is arbitrary code execution gated
only by prompt-injection resistance, which is not a security boundary.

Instead we parse the expression into an AST and walk it ourselves,
allowlisting exactly: numeric/bool/string literals, name lookups
against a fixed context dict, attribute access (dotted names, e.g.
`attacker.eth_balance_after`), comparisons, boolean ops, and the four
arithmetic operators. Anything else (calls, imports, comprehensions,
subscripts, lambdas, walrus, ...) is rejected before it ever runs.
"""

from __future__ import annotations

import ast
from typing import Any

# Catalog for auditing library defaults, based on execution/STATE_PROTOCOL.md
# and the mock and Foundry state emitters. A {target} field is available only
# when the scenario's target emits it and its builder binds that placeholder.
EMITTABLE_STATE_NAMES = frozenset({
    "attacker.eth_balance_before",
    "attacker.eth_balance_after",
    "attacker.legitimate_entitlement",
    "{target}.eth_balance_before",
    "{target}.eth_balance_after",
    "{target}.owner",
    "{target}.last_caller",
    "{target}.replay_count",
    "{target}.victim_shares",
    "{target}.attacker_balance",
    "{target}.initialized",
    "{target}.privileged_state",
    "{target}.unique_signatures_used",
    "{target}.total_assets",
    "{target}.total_shares",
    "{target}.implementation",
})

_ALLOWED_BINOPS = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow, ast.FloorDiv)
_ALLOWED_CMPOPS = (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE)
_ALLOWED_BOOLOPS = (ast.And, ast.Or)
_ALLOWED_UNARYOPS = (ast.UAdd, ast.USub, ast.Not)


class UnsafeExpressionError(ValueError):
    """Raised when an expression contains a node outside the allowlist."""


def _resolve_dotted(node: ast.AST, context: dict[str, Any]) -> Any:
    """Resolve Name / Attribute chains like `attacker.eth_balance_after`
    against a flat or nested dict context."""
    if isinstance(node, ast.Name):
        if node.id.startswith("_"):
            raise UnsafeExpressionError("private identifiers are not allowed")
        if node.id not in context:
            raise UnsafeExpressionError(f"unknown identifier: {node.id!r}")
        return context[node.id]
    if isinstance(node, ast.Attribute):
        if node.attr.startswith("_"):
            raise UnsafeExpressionError("private attributes are not allowed")
        base = _resolve_dotted(node.value, context)
        if isinstance(base, dict):
            if node.attr not in base:
                raise UnsafeExpressionError(f"unknown attribute: .{node.attr}")
            return base[node.attr]
        if hasattr(base, node.attr):
            return getattr(base, node.attr)
        raise UnsafeExpressionError(f"unknown attribute: .{node.attr}")
    raise UnsafeExpressionError(f"cannot resolve identifier node: {ast.dump(node)}")


def _eval_node(node: ast.AST, context: dict[str, Any]) -> Any:
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, context)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float, bool, str)) or node.value is None:
            return node.value
        raise UnsafeExpressionError(f"disallowed constant type: {type(node.value)}")
    if isinstance(node, (ast.Name, ast.Attribute)):
        return _resolve_dotted(node, context)
    if isinstance(node, ast.BinOp):
        if not isinstance(node.op, _ALLOWED_BINOPS):
            raise UnsafeExpressionError(f"disallowed binary operator: {type(node.op).__name__}")
        left = _eval_node(node.left, context)
        right = _eval_node(node.right, context)
        return _apply_binop(node.op, left, right)
    if isinstance(node, ast.UnaryOp):
        if not isinstance(node.op, _ALLOWED_UNARYOPS):
            raise UnsafeExpressionError(f"disallowed unary operator: {type(node.op).__name__}")
        val = _eval_node(node.operand, context)
        if isinstance(node.op, ast.UAdd):
            return +val
        if isinstance(node.op, ast.USub):
            return -val
        return not val
    if isinstance(node, ast.BoolOp):
        if not isinstance(node.op, _ALLOWED_BOOLOPS):
            raise UnsafeExpressionError("disallowed boolean operator")
        values = [_eval_node(v, context) for v in node.values]
        return all(values) if isinstance(node.op, ast.And) else any(values)
    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, context)
        result = True
        for op, comparator in zip(node.ops, node.comparators):
            if not isinstance(op, _ALLOWED_CMPOPS):
                raise UnsafeExpressionError(f"disallowed comparison operator: {type(op).__name__}")
            right = _eval_node(comparator, context)
            result = result and _apply_cmp(op, left, right)
            left = right
        return result
    raise UnsafeExpressionError(f"disallowed expression node: {type(node).__name__}")


def _apply_binop(op: ast.AST, left, right):
    if isinstance(op, ast.Add):
        return left + right
    if isinstance(op, ast.Sub):
        return left - right
    if isinstance(op, ast.Mult):
        return left * right
    if isinstance(op, ast.Div):
        return left / right
    if isinstance(op, ast.Mod):
        return left % right
    if isinstance(op, ast.Pow):
        if abs(right) > 12:
            raise UnsafeExpressionError("exponent too large (DoS guard)")
        return left ** right
    if isinstance(op, ast.FloorDiv):
        return left // right
    raise UnsafeExpressionError("unreachable")


def _apply_cmp(op: ast.AST, left, right) -> bool:
    if isinstance(op, ast.Eq):
        return left == right
    if isinstance(op, ast.NotEq):
        return left != right
    if isinstance(op, ast.Lt):
        return left < right
    if isinstance(op, ast.LtE):
        return left <= right
    if isinstance(op, ast.Gt):
        return left > right
    if isinstance(op, ast.GtE):
        return left >= right
    raise UnsafeExpressionError("unreachable")


def safe_eval(expression: str, context: dict[str, Any]) -> Any:
    """Evaluate `expression` against `context` with no ambient authority:
    no builtins, no imports, no attribute access outside the context dict,
    no function calls of any kind."""
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as e:
        raise UnsafeExpressionError(f"syntax error in expression: {e}") from e
    return _eval_node(tree, context)


if __name__ == "__main__":
    ctx = {
        "attacker": {"eth_balance_before": 1.0, "eth_balance_after": 11.0},
        "vault": {"balance_before": 100.0, "balance_after": 90.0},
    }
    assert safe_eval("attacker.eth_balance_after - attacker.eth_balance_before > 0", ctx) is True
    assert safe_eval("vault.balance_after < vault.balance_before", ctx) is True
    try:
        safe_eval("__import__('os').system('echo pwned')", ctx)
        raise SystemExit("SECURITY BUG: unsafe expression was not rejected")
    except UnsafeExpressionError:
        pass
    print("safe_eval self-test: OK")
