"""Regression coverage for ZIP64-locator signature bytes in wheel comments."""

from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path
from types import ModuleType

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "generate_release_sbom.py"
MANIFEST_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "release_runtime_dependencies.json"


def _load_generator() -> ModuleType:
    """Load the standalone release SBOM generator from the repository tree."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_generate_release_sbom_zip64_comment",
        GENERATOR_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _metadata() -> bytes:
    """Return minimal wheel metadata matching the reviewed runtime manifest."""
    return (
        b"Metadata-Version: 2.4\n"
        b"Name: egressweave\n"
        b"Version: 0.3.0\n"
        b"License-Expression: Apache-2.0\n"
        b"Requires-Dist: httpcore<2.0,>=1.0\n"
        b"Requires-Dist: httpx<0.29,>=0.28\n"
        b"Requires-Dist: idna<4,>=3.18\n\n"
    )


def _write_locator_shaped_comment_wheel(path: Path) -> None:
    """Write a standard non-ZIP64 wheel whose final member comment mimics a locator."""
    member = zipfile.ZipInfo("egressweave-0.3.0.dist-info/METADATA")
    member.comment = b"PK\x06\x07" + (b"x" * 16)
    assert len(member.comment) == 20
    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(member, _metadata())


def test_standard_wheel_allows_locator_shaped_final_member_comment(tmp_path: Path) -> None:
    """Treat ZIP64 locator bytes as structure only when framing proves a locator exists."""
    generator = _load_generator()
    wheel = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    _write_locator_shaped_comment_wheel(wheel)

    assert generator.build_sbom(wheel, MANIFEST_PATH)["bomFormat"] == "CycloneDX"
