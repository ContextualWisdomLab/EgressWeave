"""Focused tests for release-tag and changelog binding in the verifier."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "verify_distribution.py"


def _load_verifier():
    """Load the non-packaged release verifier from its repository path."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_verify_distribution",
        VERIFIER_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_release_ref_requires_exact_version_tag(tmp_path: Path) -> None:
    """Reject a published release whose tag does not equal v<project.version>."""
    verifier = _load_verifier()
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "## [Unreleased]\n\n## [0.3.0] - 2026-08-04\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="release tag must equal"):
        verifier._verify_release_ref("v0.2.0", "0.3.0", changelog)


def test_release_ref_requires_a_dated_version_section(tmp_path: Path) -> None:
    """Reject a matching tag when the changelog does not declare the release."""
    verifier = _load_verifier()
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("## [Unreleased]\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="lacks a dated release section"):
        verifier._verify_release_ref("v0.3.0", "0.3.0", changelog)


def test_release_ref_rejects_unreleased_entries(tmp_path: Path) -> None:
    """Prevent publishing current code under an older already-documented version."""
    verifier = _load_verifier()
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "## [Unreleased]\n\n### Added\n- not moved yet\n\n"
        "## [0.3.0] - 2026-08-04\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="Unreleased section is not empty"):
        verifier._verify_release_ref("v0.3.0", "0.3.0", changelog)


def test_release_ref_accepts_an_empty_unreleased_section(tmp_path: Path) -> None:
    """Accept an exact tag only after every release note is dated and moved."""
    verifier = _load_verifier()
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "## [Unreleased]\n\n## [0.3.0] - 2026-08-04\n",
        encoding="utf-8",
    )

    verifier._verify_release_ref("v0.3.0", "0.3.0", changelog)


def test_archive_selection_rejects_additional_publishable_files(tmp_path: Path) -> None:
    """Prevent an unreviewed second distribution from reaching the publisher glob."""
    verifier = _load_verifier()
    canonical_wheel = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    canonical_sdist = tmp_path / "egressweave-0.3.0.tar.gz"
    canonical_wheel.touch()
    canonical_sdist.touch()
    (tmp_path / "unexpected-9.9.9-py3-none-any.whl").touch()

    with pytest.raises(SystemExit, match="unexpected distribution archives"):
        verifier._select_archives(tmp_path, "egressweave", "0.3.0")
