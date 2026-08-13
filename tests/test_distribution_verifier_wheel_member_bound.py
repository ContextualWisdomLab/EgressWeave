"""Regression coverage for bounded wheel member verification."""

from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "verify_distribution.py"
VERSION = "0.3.0"
DIST_INFO = f"egressweave-{VERSION}.dist-info"
PROJECT = {
    "name": "egressweave",
    "version": VERSION,
    "requires-python": ">=3.10",
    "license": "Apache-2.0",
}
REQUIRED_WHEEL_PATHS = {
    "egressweave/__init__.py": b"",
    "egressweave/py.typed": b"",
    "egressweave/schemas/decision-evidence-v1.schema.json": b"{}",
    f"{DIST_INFO}/METADATA": (
        b"Metadata-Version: 2.4\n"
        b"Name: egressweave\n"
        b"Version: 0.3.0\n"
        b"Requires-Python: >=3.10\n"
        b"License-Expression: Apache-2.0\n"
        b"License-File: LICENSE\n\n"
    ),
    f"{DIST_INFO}/WHEEL": b"Wheel-Version: 1.0\nTag: py3-none-any\n",
    f"{DIST_INFO}/RECORD": b"",
    f"{DIST_INFO}/licenses/LICENSE": b"Apache License\n",
}


def _load_verifier():
    """Load the non-packaged distribution verifier from the repository tree."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_verify_distribution_wheel_bound",
        VERIFIER_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _write_wheel(path: Path, extra_member_count: int = 0) -> None:
    """Write one canonical tiny wheel plus a requested count of zero-byte members."""
    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in REQUIRED_WHEEL_PATHS.items():
            archive.writestr(name, payload)
        for index in range(extra_member_count):
            archive.writestr(f"egressweave/bounded-member-{index:04d}.txt", b"")


def _write_wheel_with_member_comment(path: Path) -> None:
    """Write a standard non-ZIP64 wheel whose final member has a ZIP-signature comment."""
    entries = list(REQUIRED_WHEEL_PATHS.items())
    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in entries[:-1]:
            archive.writestr(name, payload)
        name, payload = entries[-1]
        member = zipfile.ZipInfo(name)
        member.comment = b"comment-PK\x06\x07-tail"
        archive.writestr(member, payload)


def test_wheel_verifier_preflights_member_budget_before_zipfile_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Require bounded central-directory admission before ``ZipFile`` construction."""
    verifier = _load_verifier()
    wheel_path = tmp_path / f"egressweave-{VERSION}-py3-none-any.whl"
    _write_wheel(wheel_path)
    preflight_called = False

    def record_preflight(stream) -> None:
        nonlocal preflight_called
        preflight_called = True
        stream.seek(0)

    monkeypatch.setattr(
        verifier,
        "_preflight_wheel_members",
        record_preflight,
        raising=False,
    )
    original_zipfile = zipfile.ZipFile

    class GuardedZipFile(original_zipfile):
        """Reject standard ZIP parsing unless the verifier first admitted the budget."""

        def __init__(self, *args, **kwargs) -> None:
            assert preflight_called, "ZipFile materialized members before bounded preflight"
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(zipfile, "ZipFile", GuardedZipFile)

    digest = verifier._verify_wheel(wheel_path, PROJECT)

    assert len(digest) == 64


def test_wheel_verifier_rejects_over_budget_central_directory(tmp_path: Path) -> None:
    """Reject an over-budget canonical wheel before semantic ``ZipInfo`` allocation."""
    verifier = _load_verifier()
    wheel_path = tmp_path / f"egressweave-{VERSION}-py3-none-any.whl"
    budget = 4096
    _write_wheel(
        wheel_path,
        extra_member_count=budget - len(REQUIRED_WHEEL_PATHS) + 1,
    )

    with pytest.raises(SystemExit, match="wheel member limit"):
        verifier._verify_wheel(wheel_path, PROJECT)


def test_wheel_verifier_allows_zip64_signature_bytes_inside_member_comment(
    tmp_path: Path,
) -> None:
    """Treat ZIP64 locator bytes as structure only at the locator's exact position."""
    verifier = _load_verifier()
    wheel_path = tmp_path / f"egressweave-{VERSION}-py3-none-any.whl"
    _write_wheel_with_member_comment(wheel_path)

    digest = verifier._verify_wheel(wheel_path, PROJECT)

    assert len(digest) == 64


def test_wheel_member_budget_is_explicit_and_reviewable() -> None:
    """Keep the publication verifier's central-directory object budget stable."""
    verifier = _load_verifier()

    assert verifier.MAX_WHEEL_MEMBERS == 4096
