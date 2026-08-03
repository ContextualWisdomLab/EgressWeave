"""Repository-level quality contracts for a fully typed and documented package."""

from __future__ import annotations

import ast
from pathlib import Path


def test_all_source_definitions_have_docstrings() -> None:
    missing: list[str] = []
    for path in sorted(Path("src/egressweave").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if ast.get_docstring(tree) is None:
            missing.append(f"{path}: module")
        for node in ast.walk(tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if ast.get_docstring(node) is None:
                    missing.append(f"{path}:{node.lineno}: {node.name}")

    assert missing == []


def test_pep_561_marker_is_packaged_with_source() -> None:
    assert Path("src/egressweave/py.typed").is_file()
