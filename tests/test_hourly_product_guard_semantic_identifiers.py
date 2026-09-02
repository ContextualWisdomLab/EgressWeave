"""Executable naming contract for the autonomous product guard command seam."""

from __future__ import annotations

import ast
from pathlib import Path


def test_command_runner_uses_semantic_identifiers() -> None:
    """Require command-execution identifiers to encode their bounded meaning."""

    guard_source_path = (
        Path(__file__).resolve().parents[1] / "scripts" / "ci" / "hourly_product_guard.py"
    )
    guard_source_text = guard_source_path.read_text(encoding="utf-8")
    guard_syntax_tree = ast.parse(guard_source_text)
    function_definitions = {
        syntax_node.name: syntax_node
        for syntax_node in ast.walk(guard_syntax_tree)
        if isinstance(syntax_node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    assert "_run" not in function_definitions
    assert "_run_command" in function_definitions

    command_function = function_definitions["_run_command"]
    parameter_names = [
        function_argument.arg
        for function_argument in (
            *command_function.args.posonlyargs,
            *command_function.args.args,
            *command_function.args.kwonlyargs,
        )
    ]
    assert parameter_names == [
        "command_arguments",
        "working_directory",
        "command_environment",
        "text_mode",
        "check_result",
    ]
