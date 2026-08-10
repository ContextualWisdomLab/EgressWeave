"""Focused tests for release-tag and changelog binding in the verifier."""

from __future__ import annotations

import hashlib
import importlib.util
import io
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


def test_archive_selection_rejects_oversized_distribution_before_parser(
    tmp_path: Path,
) -> None:
    """Reject an oversized canonical archive before ZIP or tar parsing can start."""
    verifier = _load_verifier()
    canonical_wheel = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    canonical_sdist = tmp_path / "egressweave-0.3.0.tar.gz"
    canonical_wheel.write_bytes(b"wheel")
    with canonical_sdist.open("wb") as sdist_file:
        sdist_file.truncate(256 * 1024 * 1024 + 1)

    assert verifier.MAX_DISTRIBUTION_BYTES == 256 * 1024 * 1024
    with pytest.raises(SystemExit, match="distribution archive exceeds"):
        verifier._select_archives(tmp_path, "egressweave", "0.3.0")


def test_distribution_digest_reads_only_bounded_chunks() -> None:
    """Hash a distribution without issuing an unbounded binary read."""
    verifier = _load_verifier()
    payload = b"a" * (1_048_576 + 17)

    class GuardedReader(io.BytesIO):
        """Reject any read that is unbounded or larger than the release budget."""

        def read(self, size: int = -1) -> bytes:
            assert 0 < size <= 1_048_576
            return super().read(size)

    class GuardedPath:
        """Provide only the binary-open surface required by the digest helper."""

        def open(self, mode: str) -> GuardedReader:
            assert mode == "rb"
            return GuardedReader(payload)

    assert verifier.HASH_CHUNK_SIZE == 1_048_576
    assert verifier._sha256_file(GuardedPath()) == hashlib.sha256(payload).hexdigest()


def test_checksum_writer_never_uses_path_read_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep checksum generation streaming even for large distribution artifacts."""
    verifier = _load_verifier()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    sdist_path = tmp_path / "egressweave-0.3.0.tar.gz"
    wheel_payload = b"wheel-bytes"
    sdist_payload = b"sdist-bytes"
    wheel_path.write_bytes(wheel_payload)
    sdist_path.write_bytes(sdist_payload)

    def reject_read_bytes(self: Path) -> bytes:
        raise AssertionError(f"unbounded read_bytes() used for {self.name}")

    monkeypatch.setattr(Path, "read_bytes", reject_read_bytes)

    checksum_path = verifier._write_sha256sums(
        tmp_path,
        (wheel_path, sdist_path),
    )

    assert checksum_path.read_text(encoding="ascii") == (
        f"{hashlib.sha256(wheel_payload).hexdigest()}  {wheel_path.name}\n"
        f"{hashlib.sha256(sdist_payload).hexdigest()}  {sdist_path.name}\n"
    )
