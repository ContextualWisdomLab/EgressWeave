"""Regression tests for the attestable SBOM immutable write snapshot."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = (
    REPOSITORY_ROOT / "scripts" / "ci" / "generate_attestable_release_sbom.py"
)


def _load_generator():
    """Load the repository-only attestation compatibility generator."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_generate_attestable_release_sbom_snapshot_boundary",
        GENERATOR_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _attestable_document(generator) -> dict[str, object]:
    """Return one minimal valid document with a content-bound serial number."""
    document: dict[str, object] = {
        "$schema": generator.CYCLONEDX_SCHEMA,
        "bomFormat": generator.CYCLONEDX_FORMAT,
        "specVersion": generator.CYCLONEDX_SPEC_VERSION,
        "version": generator.CYCLONEDX_DOCUMENT_VERSION,
        "metadata": {"component": {"name": "egressweave"}},
    }
    document["serialNumber"] = generator._serial_number(document)
    return document


def test_writer_serializes_a_detached_exact_document_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep caller mutation after validation from changing emitted evidence."""
    generator = _load_generator()
    document = _attestable_document(generator)
    output_path = tmp_path / "snapshot.cdx.json"

    def write_sbom(candidate: dict[str, object], target: Path) -> None:
        """Mutate caller state before serializing the supplied writer value."""
        metadata = document["metadata"]
        assert isinstance(metadata, dict)
        component = metadata["component"]
        assert isinstance(component, dict)
        component["name"] = "mutated-after-validation"
        target.write_text(
            json.dumps(candidate, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

    monkeypatch.setattr(
        generator,
        "_load_foundation_generator",
        lambda: SimpleNamespace(write_sbom=write_sbom),
    )

    generator.write_attestable_sbom(document, output_path)

    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert written["metadata"]["component"]["name"] == "egressweave"
    serial_number = written.pop("serialNumber")
    assert serial_number == generator._serial_number(written)


def test_writer_masks_runtime_failure_during_snapshot_serialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail closed with stable text when concurrent mutation breaks encoding."""
    generator = _load_generator()
    document = _attestable_document(generator)
    output_path = tmp_path / "runtime-error.cdx.json"

    def fail_serialization(*args: object, **kwargs: object) -> str:
        """Model the runtime error raised by mutation during dict iteration."""
        raise RuntimeError("dictionary changed size during iteration")

    monkeypatch.setattr(generator.json, "dumps", fail_serialization)

    with pytest.raises(
        SystemExit,
        match="release SBOM foundation must produce strict JSON evidence",
    ):
        generator.write_attestable_sbom(document, output_path)
    assert not output_path.exists()
