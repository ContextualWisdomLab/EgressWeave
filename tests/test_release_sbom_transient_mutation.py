"""Regression proof for transient in-place release-wheel mutation."""

from __future__ import annotations

import importlib.util
import io
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "generate_release_sbom.py"
MANIFEST_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "release_runtime_dependencies.json"


def _load_generator() -> ModuleType:
    """Load the standalone SBOM generator without importing the package."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_generate_release_sbom_transient_mutation",
        GENERATOR_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _metadata(version: str) -> bytes:
    """Return valid metadata whose version field can change without changing size."""
    return (
        "Metadata-Version: 2.4\n"
        "Name: egressweave\n"
        f"Version: {version}\n"
        "License-Expression: Apache-2.0\n"
        "Requires-Dist: httpx>=0.28,<0.29\n"
        "Requires-Dist: httpcore>=1.0,<2.0\n"
        "Requires-Dist: idna>=3.18,<4\n\n"
    ).encode()


def _wheel_bytes(version: str) -> bytes:
    """Return deterministic same-shape wheel bytes for one metadata version."""
    output = io.BytesIO()
    member = zipfile.ZipInfo(
        "egressweave-0.3.0.dist-info/METADATA",
        date_time=(1980, 1, 1, 0, 0, 0),
    )
    member.compress_type = zipfile.ZIP_STORED
    with zipfile.ZipFile(output, mode="w") as archive:
        archive.writestr(member, _metadata(version))
    return output.getvalue()


def test_transient_same_size_wheel_bytes_cannot_escape_digest_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail closed if parser-visible bytes differ from the digest-bound artifact."""
    generator = _load_generator()
    wheel_path = tmp_path / "egressweave-0.3.0-py3-none-any.whl"
    accepted_bytes = _wheel_bytes("0.3.0")
    transient_bytes = _wheel_bytes("9.9.9")
    assert len(accepted_bytes) == len(transient_bytes)
    wheel_path.write_bytes(accepted_bytes)

    original_preflight = generator._preflight_wheel_members
    original_parse_metadata = generator._parse_metadata
    active_stream = None
    swapped = False
    restored = False

    def swap_after_preflight(stream) -> None:
        nonlocal active_stream, swapped
        original_preflight(stream)
        active_stream = stream
        wheel_path.write_bytes(transient_bytes)
        stream.seek(0, 2)
        stream.seek(0)
        swapped = True

    def restore_after_transient_parse(payload: bytes, source: str):
        nonlocal restored
        parsed = original_parse_metadata(payload, source)
        assert parsed["Version"] == "9.9.9"
        wheel_path.write_bytes(accepted_bytes)
        assert active_stream is not None
        active_stream.seek(0, 2)
        active_stream.seek(0)
        restored = True
        return parsed

    monkeypatch.setattr(generator, "_preflight_wheel_members", swap_after_preflight)
    monkeypatch.setattr(generator, "_parse_metadata", restore_after_transient_parse)

    with pytest.raises(SystemExit, match="changed during verification"):
        generator.build_sbom(wheel_path, MANIFEST_PATH)

    assert swapped is True
    assert restored is True
    assert wheel_path.read_bytes() == accepted_bytes
