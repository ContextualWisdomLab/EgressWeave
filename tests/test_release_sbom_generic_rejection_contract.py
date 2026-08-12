"""Test-first contract for generic release-artifact rejection diagnostics."""

from __future__ import annotations

import importlib.util
import tarfile
from pathlib import Path
from types import ModuleType

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "generate_release_sbom.py"
GENERIC_REJECTION = "release artifact failed verification"


def _load_generator() -> ModuleType:
    """Load the standalone SBOM generator without importing EgressWeave."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_generate_release_sbom_generic_rejection",
        GENERATOR_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_sdist_physical_member_rejection_is_generic(tmp_path: Path) -> None:
    """Do not disclose which archive-safety rule rejected an untrusted member."""
    generator = _load_generator()
    sdist = tmp_path / "unsafe-link.tar.gz"
    member = tarfile.TarInfo("egressweave-0.3.0/link")
    member.type = tarfile.SYMTYPE
    member.linkname = "target"
    member.size = 0
    with tarfile.open(sdist, mode="w:gz") as archive:
        archive.addfile(member)

    with sdist.open("rb") as stream, pytest.raises(SystemExit) as rejection:
        generator._preflight_sdist_members(stream)

    assert str(rejection.value) == GENERIC_REJECTION
