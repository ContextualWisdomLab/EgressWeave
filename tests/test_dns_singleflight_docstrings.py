"""Documentation contracts for DNS single-flight production helpers."""

from __future__ import annotations

import ast
from pathlib import Path

VALIDATION_SOURCE = Path("src/egressweave/validation.py")


def test_dns_singleflight_worker_has_beginner_readable_docstring() -> None:
    """Keep the resolver worker helper understandable at the production boundary."""
    module = ast.parse(VALIDATION_SOURCE.read_text(encoding="utf-8"))
    worker = next(
        node
        for node in ast.walk(module)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "resolve_on_worker"
    )

    docstring = ast.get_docstring(worker)
    assert docstring is not None
    normalized = docstring.lower()
    assert "resolver" in normalized or "address" in normalized
    assert "shared" in normalized
