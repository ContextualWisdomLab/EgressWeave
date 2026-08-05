"""Regression tests for executable-lock parity in release SBOM evidence."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "generate_release_sbom.py"
MANIFEST_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "release_runtime_dependencies.json"
LOCK_PATH = REPOSITORY_ROOT / "requirements-ci.txt"


def _load_generator():
    """Load the repository-local SBOM generator without importing EgressWeave."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_generate_release_sbom_lock_safety",
        GENERATOR_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_runtime_lock_extras_fail_closed(tmp_path: Path) -> None:
    """Reject extras that can activate dependencies omitted from the reviewed graph."""
    generator = _load_generator()
    lock_content = LOCK_PATH.read_text(encoding="utf-8")
    assert "anyio==4.14.2" in lock_content
    drifted_lock = lock_content.replace(
        "anyio==4.14.2",
        "anyio[trio]==4.14.2",
        1,
    )
    lock_path = tmp_path / "requirements-ci.txt"
    lock_path.write_text(drifted_lock, encoding="utf-8")

    with pytest.raises(SystemExit, match="must not use extras"):
        generator.validate_runtime_lock(MANIFEST_PATH, lock_path)
