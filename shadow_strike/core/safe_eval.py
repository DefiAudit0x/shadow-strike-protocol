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
`attacker.eth_balance_after`), comparisons, boolean ops, and the seven
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


_MAX_STRING = 65536
_MAX_BITS = 4096


def _bounded(value):
    if type(value) not in (int, float, bool, str, type(None)):
        raise UnsafeExpressionError("only primitive context values are allowed")
    if type(value) is str and len(value) > _MAX_STRING:
        raise UnsafeExpressionError("string resource limit exceeded")
    if type(value) is int and value.bit_length() > _MAX_BITS:
        raise UnsafeExpressionError("integer resource limit exceeded")
    return value


def _resolve_dotted(node: ast.AST, context: dict[str, Any]) -> Any:
    """Resolve public names against flat or nested plain dictionaries."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        raise UnsafeExpressionError("cannot resolve identifier")
    parts.append(node.id)
    parts.reverse()
    if any(part.startswith("_") for part in parts):
        raise UnsafeExpressionError("private identifiers are not allowed")
    value = context
    for index, part in enumerate(parts):
        if type(value) is not dict:
            raise UnsafeExpressionError("attribute access requires a plain dictionary")
        dotted = ".".join(parts[index:])
        if dotted in value:
            return _bounded(value[dotted])
        if part not in value:
            raise UnsafeExpressionError(f"unknown identifier: {part!r}")
        value = value[part]
    return _bounded(value)


def _eval_node(node: ast.AST, context: dict[str, Any]) -> Any:
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, context)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float, bool, str)) or node.value is None:
            return _bounded(node.value)
        raise UnsafeExpressionError(f"disallowed constant type: {type(node.value)}")
    if isinstance(node, (ast.Name, ast.Attribute)):
        return _resolve_dotted(node, context)
    if isinstance(node, ast.BinOp):
        if not isinstance(node.op, _ALLOWED_BINOPS):
            raise UnsafeExpressionError(f"disallowed binary operator: {type(node.op).__name__}")
        left = _eval_node(node.left, context)
        right = _eval_node(node.right, context)
        return _bounded(_apply_binop(node.op, left, right))
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
        for operand in node.values:
            value = bool(_eval_node(operand, context))
            if isinstance(node.op, ast.And) and not value:
                return False
            if isinstance(node.op, ast.Or) and value:
                return True
        return isinstance(node.op, ast.And)
    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, context)
        for op, comparator in zip(node.ops, node.comparators):
            if not isinstance(op, _ALLOWED_CMPOPS):
                raise UnsafeExpressionError(f"disallowed comparison operator: {type(op).__name__}")
            right = _eval_node(comparator, context)
            if not _apply_cmp(op, left, right):
                return False
            left = right
        return True
    raise UnsafeExpressionError(f"disallowed expression node: {type(node).__name__}")


def _apply_binop(op: ast.AST, left, right):
    if (isinstance(op, ast.Add) and type(left) is str and type(right) is str
            and len(left) + len(right) > _MAX_STRING):
        raise UnsafeExpressionError("string resource limit exceeded")
    if isinstance(op, ast.Mult):
        string, count = (left, right) if type(left) is str else (right, left)
        if (type(string) is str and type(count) in (int, bool)
                and len(string) * max(0, count) > _MAX_STRING):
            raise UnsafeExpressionError("string resource limit exceeded")
    if isinstance(op, ast.Mod) and type(left) is str:
        raise UnsafeExpressionError("string formatting is not allowed")
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
        if (type(left) in (int, bool) and type(right) in (int, bool) and right > 0
                and abs(left).bit_length() * right > _MAX_BITS):
            raise UnsafeExpressionError("integer power resource limit exceeded")
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
    if type(context) is not dict:
        raise UnsafeExpressionError("context must be a plain dictionary")
    if len(expression) > 8192:
        raise UnsafeExpressionError("expression length resource limit exceeded")
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as e:
        raise UnsafeExpressionError(f"syntax error in expression: {e}") from e
    pending = [(tree, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > 1024 or depth > 64:
            raise UnsafeExpressionError("AST resource limit exceeded")
        pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
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
