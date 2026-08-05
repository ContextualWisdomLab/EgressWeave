"""Regression tests for bounded sealed-evidence parsing failures."""

from __future__ import annotations

from pathlib import Path

import pytest

from egressweave import release_evidence


def test_checksum_snapshot_never_uses_an_unbounded_path_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a post-hash oversized checksum before any unbounded path read."""
    checksum = tmp_path / "SHA256SUMS"
    checksum.write_text("", encoding="ascii")
    original_hash = release_evidence._sha256_file
    original_read_bytes = Path.read_bytes
    hash_calls = 0

    def hash_then_replace(
        path: Path,
        *,
        maximum_bytes: int,
        label: str,
    ) -> str:
        """Replace the checksum after its first bounded descriptor hash."""
        nonlocal hash_calls
        digest = original_hash(path, maximum_bytes=maximum_bytes, label=label)
        if path == checksum and hash_calls == 0:
            checksum.write_bytes(b"x" * (release_evidence.MAX_CHECKSUM_BYTES + 1))
        hash_calls += 1
        return digest

    def reject_unbounded_read(path: Path) -> bytes:
        """Expose any path-wide read performed after the oversized swap."""
        if path == checksum and path.stat().st_size > release_evidence.MAX_CHECKSUM_BYTES:
            raise AssertionError("oversized checksum reached an unbounded path read")
        return original_read_bytes(path)

    monkeypatch.setattr(release_evidence, "_sha256_file", hash_then_replace)
    monkeypatch.setattr(Path, "read_bytes", reject_unbounded_read)

    with pytest.raises(SystemExit, match="safety bound"):
        release_evidence._load_checksums(checksum, set())


def test_deeply_nested_json_is_masked_by_the_strict_evidence_boundary(
    tmp_path: Path,
) -> None:
    """Normalize parser recursion failure instead of leaking an exception."""
    sbom = tmp_path / "deep.cdx.json"
    sbom.write_text("[" * 10_000 + "0" + "]" * 10_000, encoding="utf-8")

    with pytest.raises(SystemExit, match="not strict JSON"):
        release_evidence._load_strict_json(sbom)
