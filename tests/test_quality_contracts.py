"""Repository-level regression tests for coverage and documentation contracts."""

from __future__ import annotations

import ast
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src" / "egressweave"
PYPROJECT_PATH = REPOSITORY_ROOT / "pyproject.toml"
CI_WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
CI_REQUIREMENTS_PATH = REPOSITORY_ROOT / "requirements-ci.txt"
COVERAGE_WHEEL_URL = (
    "https://files.pythonhosted.org/packages/37/e7/"
    "7069b3d6c018917f49ba2e1c5fb910e498c7fefa3a1b78cb1b79e61ff45d/"
    "coverage-7.15.3-py3-none-any.whl"
)
COVERAGE_WHEEL_SHA256 = (
    "da78fa6fc7dafe4212839173133ee85afcf42c5cd5f3e47fa7c1c210453b445e"
)


def _load_pyproject() -> dict[str, object]:
    """Parse and return the repository's authoritative TOML configuration."""
    with PYPROJECT_PATH.open("rb") as pyproject_file:
        return tomllib.load(pyproject_file)


def _documented_definitions(source_path: Path) -> list[tuple[str, ast.AST]]:
    """Return production definitions whose docstrings are part of the contract."""
    source = source_path.read_text(encoding="utf-8")
    module = ast.parse(source, filename=str(source_path))
    definitions: list[tuple[str, ast.AST]] = [("<module>", module)]

    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            definitions.append((node.name, node))
            continue
        if not isinstance(node, ast.ClassDef):
            continue

        definitions.append((node.name, node))
        for member in node.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                definitions.append((f"{node.name}.{member.name}", member))
    return definitions


def test_every_shipped_module_class_function_and_method_has_a_docstring() -> None:
    """Keep production APIs and internals readable without source archaeology."""
    missing: list[str] = []
    for source_path in sorted(SOURCE_ROOT.glob("*.py")):
        relative_path = source_path.relative_to(REPOSITORY_ROOT).as_posix()
        for qualified_name, definition in _documented_definitions(source_path):
            if ast.get_docstring(definition, clean=False) is None:
                missing.append(f"{relative_path}:{qualified_name}")

    assert missing == [], "Missing production docstrings:\n" + "\n".join(missing)


def test_pyproject_enforces_complete_statement_and_branch_coverage() -> None:
    """Require one canonical 100% production coverage configuration."""
    pyproject = _load_pyproject()
    coverage = pyproject["tool"]["coverage"]

    assert coverage["run"] == {
        "branch": True,
        "source_dirs": ["src/egressweave", "scripts/ci"],
    }
    assert coverage["report"] == {
        "fail_under": 100,
        "show_missing": True,
        "skip_empty": True,
    }


def test_test_extra_declares_the_supported_coverage_tool() -> None:
    """Make the quality command reproducible for contributors outside CI."""
    pyproject = _load_pyproject()
    test_dependencies = pyproject["project"]["optional-dependencies"]["test"]

    assert "coverage>=7.15.3,<8" in test_dependencies


def test_ci_installs_the_attested_hash_locked_coverage_wheel() -> None:
    """Keep CI measurement code on the reviewed, immutable artifact."""
    requirements = CI_REQUIREMENTS_PATH.read_text(encoding="utf-8")

    assert f"coverage @ {COVERAGE_WHEEL_URL}" in requirements
    assert f"--hash=sha256:{COVERAGE_WHEEL_SHA256}" in requirements


def test_ci_runs_tests_under_the_complete_coverage_gate() -> None:
    """Prevent the matrix from silently reverting to unmeasured pytest runs."""
    workflow = CI_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "coverage run -m pytest -q" in workflow
    assert "coverage report -m" in workflow
    assert "- run: pytest -q" not in workflow
