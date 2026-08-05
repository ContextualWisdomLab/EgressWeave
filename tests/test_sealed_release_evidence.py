"""Compact complete-branch tests for the sealed release-evidence verifier."""
from __future__ import annotations

import json
import runpy
import sys
import uuid
from pathlib import Path

import pytest

from test_sealed_release_evidence_source_identity import (
    REPOSITORY,
    SOURCE_SHA,
    _build,
    _checksums,
    _evidence,
    _sbom,
)

from egressweave import release_evidence as v

SCRIPT = Path(v.__file__).resolve()


def _paths(root: Path) -> dict[str, Path]:
    """Return the canonical fixture paths created by the shared helper."""
    wheel = root / "egressweave-0.3.0-py3-none-any.whl"
    sdist = root / "egressweave-0.3.0.tar.gz"
    return {
        "wheel": wheel,
        "sdist": sdist,
        "wheel_sbom": root / f"{wheel.name}.cdx.json",
        "sdist_sbom": root / f"{sdist.name}.cdx.json",
        "identity": root / "SOURCE_IDENTITY.json",
        "checksum": root / "SHA256SUMS",
    }


def test_cli_and_module_entrypoint_are_deterministic(tmp_path: Path, monkeypatch) -> None:
    """Exercise normal CLI output, inside-set refusal, and direct module execution."""
    root = tmp_path / "evidence"
    _evidence(root)
    outputs = [tmp_path / "one.json", tmp_path / "two.json"]
    for output in outputs:
        monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--evidence-dir", str(root), "--repository", REPOSITORY, "--source-sha", SOURCE_SHA, "--output", str(output)])
        assert v.main() == 0
    assert outputs[0].read_bytes() == outputs[1].read_bytes()
    monkeypatch.setattr(sys, "argv", [*sys.argv[:-1], str(root / "inside.json")])
    with pytest.raises(SystemExit, match="outside the verified set"):
        v.main()
    output = tmp_path / "module.json"
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--evidence-dir", str(root), "--repository", REPOSITORY, "--source-sha", SOURCE_SHA, "--output", str(output)])
    with pytest.raises(SystemExit, match="0"):
        runpy.run_path(str(SCRIPT), run_name="__main__")


def test_hash_and_directory_failure_branches(tmp_path: Path, monkeypatch) -> None:
    """Normalize file errors and reject malformed direct-child evidence sets."""
    missing = tmp_path / "missing"
    with pytest.raises(SystemExit, match="unreadable"):
        v._sha256_file(missing, maximum_bytes=1, label="file")
    real = tmp_path / "real"
    real.mkdir()
    original_iterdir = Path.iterdir
    monkeypatch.setattr(Path, "iterdir", lambda p: (_ for _ in ()).throw(OSError()) if p == real else original_iterdir(p))
    with pytest.raises(SystemExit, match="directory is unreadable"):
        v._select_evidence_paths(real)
    monkeypatch.setattr(Path, "iterdir", original_iterdir)
    (real / "child").mkdir()
    with pytest.raises(SystemExit, match="regular direct-child"):
        v._select_evidence_paths(real)
    (real / "child").rmdir()
    (real / "egressweave-0.3.0-py3-none-any.whl").write_bytes(b"x")
    with pytest.raises(SystemExit, match="exactly one canonical"):
        v._select_evidence_paths(real)
    (real / "egressweave-0.4.0.tar.gz").write_bytes(b"x")
    with pytest.raises(SystemExit, match="versions do not match"):
        v._select_evidence_paths(real)


def test_cardinality_and_checksum_fail_closed(tmp_path: Path, monkeypatch) -> None:
    """Exercise exact set and canonical checksum rejection branches."""
    root = tmp_path / "evidence"
    paths = _evidence(root)
    (root / "extra").write_text("x")
    with pytest.raises(SystemExit, match="cardinality mismatch"):
        _build(root)
    (root / "extra").unlink()
    checksum = paths["checksum"]
    checksum.write_bytes(b"\xff")
    with pytest.raises(SystemExit, match="canonical ASCII"):
        v._load_checksums(checksum, set())
    line = f"{'0' * 64}  file.whl"
    for text in (line, line + "\r\n"):
        checksum.write_bytes(text.encode())
        with pytest.raises(SystemExit, match="trailing newline"):
            v._load_checksums(checksum, {"file.whl"})
    cases = [
        (line + "\n" + line + "\n", "duplicate", {"file.whl"}),
        (line + "\n", "exact evidence payload", {"file.whl", "other.whl"}),
        (f"{'0' * 64}  ../escape\n", "noncanonical", set()),
    ]
    for text, message, names in cases:
        checksum.write_text(text)
        with pytest.raises(SystemExit, match=message):
            v._load_checksums(checksum, names)
    checksum.write_text(line + "\n")
    original_open = Path.open
    monkeypatch.setattr(Path, "open", lambda p, *a, **k: (_ for _ in ()).throw(OSError()) if p == checksum else original_open(p, *a, **k))
    with pytest.raises(SystemExit, match="unreadable"):
        v._load_checksums(checksum, {"file.whl"})


def test_digest_mismatch_and_strict_json_helpers(tmp_path: Path) -> None:
    """Reject stale checksums, ambiguous SBOM JSON, and non-mapping values."""
    root = tmp_path / "evidence"
    _evidence(root)
    paths = _paths(root)
    paths["wheel"].write_bytes(b"changed")
    with pytest.raises(SystemExit, match="digest mismatch"):
        _build(root)
    for index, text in enumerate(('{"x":1,"x":2}', '{"x":NaN}', "[]")):
        path = tmp_path / f"{index}.json"
        path.write_text(text)
        with pytest.raises(SystemExit):
            v._load_strict_json(path)
    with pytest.raises(SystemExit, match="outside strict JSON"):
        v._canonical_pre_serial_digest({"bad": object()})
    with pytest.raises(SystemExit, match="must be a JSON object"):
        v._require_mapping([], label="value")


@pytest.mark.parametrize(
    ("change", "message", "resign"),
    [
        (lambda d: d.__setitem__("specVersion", "1.6"), "exact CycloneDX", False),
        (lambda d: d.__setitem__("version", True), "non-integer", False),
        (lambda d: d.pop("serialNumber"), "lacks a serial", False),
        (lambda d: d.__setitem__("serialNumber", "bad"), "invalid serial", False),
        (lambda d: d.__setitem__("serialNumber", "urn:uuid:" + d["serialNumber"].split(":", 2)[2].upper()), "noncanonical UUID", False),
        (lambda d: d.__setitem__("serialNumber", "urn:uuid:00000000-0000-5000-0000-000000000000"), "RFC UUID variant", False),
        (lambda d: d.__setitem__("serialNumber", "urn:uuid:00000000-0000-4000-8000-000000000000"), "UUID version 5", False),
        (lambda d: d.__setitem__("metadata", []), "metadata must be", True),
        (lambda d: d["metadata"].__setitem__("component", []), "root component", True),
        (lambda d: d["metadata"]["component"].__setitem__("name", "x"), "package name", True),
        (lambda d: d["metadata"]["component"].__setitem__("version", "x"), "package version", True),
        (lambda d: d["metadata"]["component"].__setitem__("purl", "x"), "package URL", True),
        (lambda d: d["metadata"]["component"].__setitem__("hashes", []), "root hash", True),
        (lambda d: d["metadata"]["component"].__setitem__("properties", {}), "root properties", True),
        (lambda d: d["metadata"]["component"].__setitem__("properties", [None]), "filename binding", True),
    ],
)
def test_each_sbom_profile_rejection(tmp_path: Path, change, message: str, resign: bool) -> None:
    """Cover each independent exact-profile and root-binding rejection."""
    root = tmp_path / "evidence"
    _evidence(root)
    paths = _paths(root)
    document = json.loads(paths["wheel_sbom"].read_text())
    change(document)
    if resign and "serialNumber" in document:
        document.pop("serialNumber")
        document["serialNumber"] = _serial(document)
    paths["wheel_sbom"].write_text(json.dumps(document))
    _checksums(root)
    with pytest.raises(SystemExit, match=message):
        _build(root)


def _serial(document: dict) -> str:
    """Recompute a valid test serial after mutation."""
    import hashlib
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'https://github.com/ContextualWisdomLab/EgressWeave/sbom/sha256/' + digest)}"


def test_content_identity_and_root_reference_are_independent(tmp_path: Path) -> None:
    """Reject copied UUID identity and a valid SBOM that binds different bytes."""
    root = tmp_path / "evidence"
    _evidence(root)
    paths = _paths(root)
    document = json.loads(paths["wheel_sbom"].read_text())
    document["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_DNS, 'wrong')}"
    paths["wheel_sbom"].write_text(json.dumps(document))
    _checksums(root)
    with pytest.raises(SystemExit, match="content-bound identity"):
        _build(root)
    paths["wheel_sbom"].write_text(json.dumps(_sbom(paths["wheel"].name, "0" * 64)))
    _checksums(root)
    with pytest.raises(SystemExit, match="root reference"):
        _build(root)


def test_checksum_order_and_source_shape_are_exact(tmp_path: Path) -> None:
    """Reject filename-order drift and malformed caller source identities."""
    checksum = tmp_path / "SHA256SUMS"
    checksum.write_text(f"{'0' * 64}  z\n{'0' * 64}  a\n")
    with pytest.raises(SystemExit, match="sorted by filename"):
        v._load_checksums(checksum, {"a", "z"})
    root = tmp_path / "evidence"
    _evidence(root)
    with pytest.raises(SystemExit, match="40 lowercase hexadecimal"):
        _build(root, source_sha="A" * 40)
