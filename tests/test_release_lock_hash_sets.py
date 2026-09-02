"""Regression contracts for portable multi-artifact hash locks."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "generate_release_sbom.py"
MANIFEST_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "release_runtime_dependencies.json"
LOCK_PATH = REPOSITORY_ROOT / "requirements-ci.txt"


def _load_generator():
    """Load the repository SBOM generator without packaging it."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_release_lock_hash_sets",
        GENERATOR_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_runtime_lock_accepts_distinct_platform_hashes(tmp_path: Path) -> None:
    """Preserve every exact artifact hash attached to one pinned version."""
    generator = _load_generator()
    first_digest = "a" * 64
    second_digest = "b" * 64
    lock_path = tmp_path / "requirements-ci.txt"
    lock_path.write_text(
        "tool==1.2.3 "
        f"--hash=sha256:{first_digest} "
        f"--hash=sha256:{second_digest}\n",
        encoding="utf-8",
    )

    assert generator._load_runtime_lock(lock_path) == {
        "tool": {
            "version": "1.2.3",
            "sha256": (first_digest, second_digest),
            "marker": None,
        }
    }


def test_runtime_lock_rejects_duplicate_artifact_hashes(tmp_path: Path) -> None:
    """Reject duplicate evidence within one package hash set."""
    generator = _load_generator()
    digest = "a" * 64
    lock_path = tmp_path / "requirements-ci.txt"
    lock_path.write_text(
        f"tool==1.2.3 --hash=sha256:{digest} --hash=sha256:{digest}\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="duplicate SHA-256"):
        generator._load_runtime_lock(lock_path)


def test_runtime_manifest_accepts_its_digest_among_platform_hashes(
    tmp_path: Path,
) -> None:
    """Bind runtime evidence to one reviewed digest in a portable hash set."""
    generator = _load_generator()
    lock_text = LOCK_PATH.read_text(encoding="utf-8")
    needle = (
        "anyio==4.14.2 \\\n"
        "    --hash=sha256:"
        "9f505dda5ac9f0c8309b5e8bd445a8c2bf7246f3ce950121e45ea15bc41d1494"
    )
    replacement = needle + " \\\n    --hash=sha256:" + ("f" * 64)
    assert lock_text.count(needle) == 1
    portable_lock = tmp_path / "requirements-ci.txt"
    portable_lock.write_text(
        lock_text.replace(needle, replacement, 1),
        encoding="utf-8",
    )

    generator.validate_runtime_lock(MANIFEST_PATH, portable_lock)


def test_runtime_manifest_rejects_absent_digest_from_platform_hashes(
    tmp_path: Path,
) -> None:
    """Reject a hash set that omits the exact reviewed runtime artifact digest."""
    generator = _load_generator()
    lock_text = LOCK_PATH.read_text(encoding="utf-8")
    needle = (
        "anyio==4.14.2 \\\n"
        "    --hash=sha256:"
        "9f505dda5ac9f0c8309b5e8bd445a8c2bf7246f3ce950121e45ea15bc41d1494"
    )
    replacement = (
        "anyio==4.14.2 \\\n"
        "    --hash=sha256:"
        + ("e" * 64)
        + " \\\n    --hash=sha256:"
        + ("f" * 64)
    )
    assert lock_text.count(needle) == 1
    portable_lock = tmp_path / "requirements-ci.txt"
    portable_lock.write_text(
        lock_text.replace(needle, replacement, 1),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="does not match the hash-locked runtime subset"):
        generator.validate_runtime_lock(MANIFEST_PATH, portable_lock)
