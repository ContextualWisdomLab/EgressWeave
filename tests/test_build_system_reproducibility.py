"""Regression contracts for isolated PEP 517 build-tool identity."""

from __future__ import annotations

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT_PATH = REPOSITORY_ROOT / "pyproject.toml"
RELEASE_REQUIREMENTS_PATH = REPOSITORY_ROOT / "requirements-release.txt"
REVIEWED_HATCHLING_VERSION = "1.31.0"


def test_pep517_build_isolation_uses_the_reviewed_hatchling_version() -> None:
    """Keep isolated source builds on the same reviewed backend as release builds."""
    with PYPROJECT_PATH.open("rb") as pyproject_file:
        build_system = tomllib.load(pyproject_file)["build-system"]

    assert build_system["build-backend"] == "hatchling.build"
    assert build_system["requires"] == [f"hatchling=={REVIEWED_HATCHLING_VERSION}"]

    release_requirements = RELEASE_REQUIREMENTS_PATH.read_text(encoding="utf-8")
    assert f"hatchling-{REVIEWED_HATCHLING_VERSION}-py3-none-any.whl" in release_requirements
