"""Define the public shape for sealed release evidence verification."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def build_evidence_manifest(
    evidence_dir: Path,
    *,
    repository: str,
    source_sha: str,
) -> dict[str, Any]:
    """Return a placeholder manifest until the test-first verifier is implemented."""
    del evidence_dir, repository, source_sha
    return {}


def write_evidence_manifest(manifest: dict[str, Any], output_path: Path) -> None:
    """Refuse output until the test-first verifier is implemented."""
    del manifest, output_path
    raise NotImplementedError


def main() -> int:
    """Refuse CLI execution until the test-first verifier is implemented."""
    raise NotImplementedError
