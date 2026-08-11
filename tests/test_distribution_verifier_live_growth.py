"""Regressions for live distribution growth during release verification."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "verify_distribution.py"


def _load_verifier():
    """Load the credential-free distribution verifier from its repository path."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_verify_distribution_live_growth",
        VERIFIER_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_live_archive_growth_never_reaches_the_parser_view(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not expose bytes appended after the accepted archive-size snapshot."""
    verifier = _load_verifier()
    accepted_limit = 64
    monkeypatch.setattr(verifier, "MAX_DISTRIBUTION_BYTES", accepted_limit)
    archive_path = tmp_path / "egressweave-0.3.0.tar.gz"
    archive_path.write_bytes(b"a" * accepted_limit)

    observed = b""
    with (
        pytest.raises(SystemExit, match="distribution archive exceeds"),
        verifier._open_stable_distribution(archive_path) as archive_file,
        archive_path.open("ab") as mutator,
    ):
        mutator.write(b"b" * accepted_limit)
        mutator.flush()

        archive_file.seek(0)
        observed = archive_file.read()

    assert len(observed) <= accepted_limit


def test_same_size_archive_mutation_is_rejected_after_snapshot(tmp_path: Path) -> None:
    """Reject in-place same-size mutation after the immutable parser snapshot."""
    verifier = _load_verifier()
    archive_path = tmp_path / "egressweave-0.3.0.tar.gz"
    original = b"a" * 64
    replacement = b"b" * 64
    archive_path.write_bytes(original)

    observed = b""
    with (
        pytest.raises(SystemExit, match="distribution archive is missing or unsafe"),
        verifier._open_stable_distribution(archive_path) as archive_file,
        archive_path.open("r+b") as mutator,
    ):
        observed = archive_file.read()
        mutator.seek(0)
        mutator.write(replacement)
        mutator.flush()

    assert observed == original
    assert archive_path.read_bytes() == replacement
