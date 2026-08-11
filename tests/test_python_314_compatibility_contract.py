"""Contracts for the repository's supported Python 3.14 compatibility evidence."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
PYPROJECT_PATH = REPOSITORY_ROOT / "pyproject.toml"
README_PATH = REPOSITORY_ROOT / "README.md"


def _read(path: Path) -> str:
    """Return one repository text file as UTF-8."""
    return path.read_text(encoding="utf-8")


def test_ci_executes_complete_quality_contract_on_python_314() -> None:
    """Require Python 3.14 to execute the same complete CI lane as earlier versions."""
    workflow = _read(CI_WORKFLOW_PATH)

    assert 'python-version: ["3.10", "3.11", "3.12", "3.13", "3.14"]' in workflow
    assert "coverage run -m pytest -q" in workflow
    assert "coverage report -m" in workflow
    assert "python scripts/ci/hourly_product_guard.py self-test" in workflow
    assert "python -m compileall -q src tests scripts" in workflow


def test_package_metadata_advertises_python_314_only_when_ci_covers_it() -> None:
    """Keep package classifiers synchronized with the interpreter matrix."""
    pyproject = _read(PYPROJECT_PATH)

    assert '"Programming Language :: Python :: 3.14"' in pyproject


def test_buyer_runtime_compatibility_names_python_314() -> None:
    """Keep buyer-facing compatibility claims aligned with hosted evidence."""
    readme = _read(README_PATH)

    assert "Python 3.10–3.14" in readme
