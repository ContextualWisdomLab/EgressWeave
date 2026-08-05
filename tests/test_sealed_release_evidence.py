"""Tests for fail-closed sealed release evidence verification."""

from __future__ import annotations

import hashlib
import importlib
import json
import runpy
import sys
import uuid
from pathlib import Path
from typing import Any, Callable

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "src/egressweave/release_evidence.py"
REPOSITORY = "ContextualWisdomLab/EgressWeave"
SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"
VERSION = "0.3.0"
Mutator = Callable[[dict[str, Any]], None]


def _module():
    """Return the shipped verifier module."""
    return importlib.import_module("egressweave.release_evidence")


def _digest(path: Path) -> str:
    """Return one fixture digest."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _serial(document: dict[str, Any]) -> str:
    """Derive the expected content-bound UUIDv5 independently."""
    canonical = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    prefix = "https://github.com/ContextualWisdomLab/EgressWeave/sbom/sha256/"
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, prefix + digest)}"


def _sbom(filename: str, digest: str) -> dict[str, Any]:
    """Return one valid CycloneDX fixture."""
    document: dict[str, Any] = {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "bom-ref": f"urn:egressweave:artifact:sha256:{digest}",
                "name": "egressweave",
                "version": VERSION,
                "purl": f"pkg:pypi/egressweave@{VERSION}",
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "properties": [
                    {
                        "name": "egressweave:release:artifact-filename",
                        "value": filename,
                    }
                ],
            }
        },
        "components": [],
        "dependencies": [],
    }
    document["serialNumber"] = _serial(document)
    return document


def _checksums(paths: dict[str, Path]) -> None:
    """Write canonical filename-sorted checksums."""
    payloads = [paths[key] for key in ("wheel", "sdist", "wheel_sbom", "sdist_sbom")]
    paths["checksum"].write_text(
        "".join(
            f"{_digest(path)}  {path.name}\n"
            for path in sorted(payloads, key=lambda item: item.name)
        ),
        encoding="ascii",
    )


def _evidence(root: Path) -> dict[str, Path]:
    """Create one complete valid evidence set."""
    root.mkdir()
    wheel = root / f"egressweave-{VERSION}-py3-none-any.whl"
    sdist = root / f"egressweave-{VERSION}.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    paths = {
        "wheel": wheel,
        "sdist": sdist,
        "wheel_sbom": root / f"{wheel.name}.cdx.json",
        "sdist_sbom": root / f"{sdist.name}.cdx.json",
        "checksum": root / "SHA256SUMS",
    }
    paths["wheel_sbom"].write_text(json.dumps(_sbom(wheel.name, _digest(wheel))))
    paths["sdist_sbom"].write_text(json.dumps(_sbom(sdist.name, _digest(sdist))))
    _checksums(paths)
    return paths


def _build(root: Path, *, repository: str = REPOSITORY, sha: str = SOURCE_SHA):
    """Build a manifest with the normal exact identity."""
    return _module().build_evidence_manifest(root, repository=repository, source_sha=sha)


def _mutate(paths: dict[str, Path], change: Mutator, *, resign: bool) -> None:
    """Change the wheel SBOM and optionally restore a valid content identity."""
    document = json.loads(paths["wheel_sbom"].read_text())
    change(document)
    if resign and "serialNumber" in document:
        document.pop("serialNumber")
        document["serialNumber"] = _serial(document)
    paths["wheel_sbom"].write_text(json.dumps(document))
    _checksums(paths)


def test_valid_manifest_and_cli_are_deterministic(tmp_path: Path, monkeypatch) -> None:
    """Bind exact artifacts to one source and emit byte-stable external JSON."""
    root = tmp_path / "evidence"
    _evidence(root)
    first = _build(root)
    assert first == _build(root)
    assert first["format"] == "egressweave.release-evidence"
    assert first["formatVersion"] == 1
    assert first["repository"] == REPOSITORY
    assert first["sourceSha"] == SOURCE_SHA
    assert first["predicateType"] == "https://cyclonedx.org/bom"
    assert first["cycloneDxSpecVersion"] == "1.7"
    assert [item["kind"] for item in first["artifacts"]] == ["wheel", "sdist"]
    assert "timestamp" not in json.dumps(first)

    outputs = [tmp_path / "one.json", tmp_path / "two.json"]
    for output in outputs:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                str(SCRIPT_PATH),
                "--evidence-dir",
                str(root),
                "--repository",
                REPOSITORY,
                "--source-sha",
                SOURCE_SHA,
                "--output",
                str(output),
            ],
        )
        assert _module().main() == 0
    assert outputs[0].read_bytes() == outputs[1].read_bytes()

    monkeypatch.setattr(sys, "argv", [*sys.argv[:-1], str(root / "inside.json")])
    with pytest.raises(SystemExit, match="outside the verified set"):
        _module().main()


def test_module_entrypoint_uses_the_same_path(tmp_path: Path, monkeypatch) -> None:
    """Cover direct ``python -m`` execution."""
    root = tmp_path / "evidence"
    _evidence(root)
    output = tmp_path / "manifest.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT_PATH),
            "--evidence-dir",
            str(root),
            "--repository",
            REPOSITORY,
            "--source-sha",
            SOURCE_SHA,
            "--output",
            str(output),
        ],
    )
    with pytest.raises(SystemExit, match="0"):
        runpy.run_path(str(SCRIPT_PATH), run_name="__main__")
    assert output.is_file()


@pytest.mark.parametrize(
    ("repository", "sha"),
    [("Other/Repo", SOURCE_SHA), (REPOSITORY, "A" * 40), (REPOSITORY, "0" * 39)],
)
def test_wrong_repository_or_source_fails(tmp_path: Path, repository: str, sha: str) -> None:
    """Bind evidence only to the approved exact repository head."""
    root = tmp_path / "evidence"
    _evidence(root)
    with pytest.raises(SystemExit):
        _build(root, repository=repository, sha=sha)


def test_hashing_and_directory_failures_are_bounded(tmp_path: Path, monkeypatch) -> None:
    """Normalize filesystem errors and reject unsafe evidence containers."""
    verifier = _module()
    missing = tmp_path / "missing"
    with pytest.raises(SystemExit, match="unreadable"):
        verifier._sha256_file(missing, maximum_bytes=1, label="file")
    large = tmp_path / "large"
    large.write_bytes(b"xx")
    with pytest.raises(SystemExit, match="safety bound"):
        verifier._sha256_file(large, maximum_bytes=1, label="file")
    original_open = Path.open

    def bad_open(path: Path, *args, **kwargs):
        if path == large:
            raise OSError
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", bad_open)
    with pytest.raises(SystemExit, match="unreadable"):
        verifier._sha256_file(large, maximum_bytes=2, label="file")

    with pytest.raises(SystemExit, match="missing or unsafe"):
        verifier._select_evidence_paths(missing)
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(SystemExit, match="missing or unsafe"):
        verifier._select_evidence_paths(link)
    original_iterdir = Path.iterdir

    def bad_iterdir(path: Path):
        if path == real:
            raise OSError
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", bad_iterdir)
    with pytest.raises(SystemExit, match="directory is unreadable"):
        verifier._select_evidence_paths(real)
    monkeypatch.setattr(Path, "iterdir", original_iterdir)
    child = real / "child"
    child.mkdir()
    with pytest.raises(SystemExit, match="regular direct-child"):
        verifier._select_evidence_paths(real)
    child.rmdir()
    target = real / "target"
    target.write_text("x")
    child = real / "child-link"
    child.symlink_to(target)
    with pytest.raises(SystemExit, match="regular direct-child"):
        verifier._select_evidence_paths(real)


def test_archive_and_cardinality_contracts_fail_closed(tmp_path: Path) -> None:
    """Require exactly one same-version wheel, sdist, SBOM pair, and checksum."""
    verifier = _module()
    root = tmp_path / "empty"
    root.mkdir()
    with pytest.raises(SystemExit, match="exactly one canonical"):
        verifier._select_evidence_paths(root)
    (root / "egressweave-0.3.0-py3-none-any.whl").write_bytes(b"x")
    with pytest.raises(SystemExit, match="exactly one canonical"):
        verifier._select_evidence_paths(root)
    (root / "egressweave-0.4.0.tar.gz").write_bytes(b"x")
    with pytest.raises(SystemExit, match="versions do not match"):
        verifier._select_evidence_paths(root)

    root = tmp_path / "evidence"
    _evidence(root)
    (root / "extra").write_text("x")
    with pytest.raises(SystemExit, match="cardinality mismatch"):
        _build(root)


def test_checksum_contract_rejects_every_ambiguous_form(tmp_path: Path, monkeypatch) -> None:
    """Require ASCII, canonical lines, ordering, cardinality, and exact digests."""
    verifier = _module()
    checksum = tmp_path / "SHA256SUMS"
    checksum.write_bytes(b"\xff")
    with pytest.raises(SystemExit, match="canonical ASCII"):
        verifier._load_checksums(checksum, set())
    line = f"{'0' * 64}  file.whl"
    for text in (line, line + "\r\n"):
        checksum.write_bytes(text.encode())
        with pytest.raises(SystemExit, match="trailing newline"):
            verifier._load_checksums(checksum, {"file.whl"})
    checksum.write_text(line + "\n" + line + "\n")
    with pytest.raises(SystemExit, match="duplicate"):
        verifier._load_checksums(checksum, {"file.whl"})
    checksum.write_text(line + "\n")
    with pytest.raises(SystemExit, match="exact evidence payload"):
        verifier._load_checksums(checksum, {"file.whl", "other.whl"})
    checksum.write_text(f"{'0' * 64}  ../escape\n")
    with pytest.raises(SystemExit, match="noncanonical"):
        verifier._load_checksums(checksum, set())

    original_read = Path.read_bytes

    def bad_read(path: Path):
        if path == checksum:
            raise OSError
        return original_read(path)

    checksum.write_text(line + "\n")
    monkeypatch.setattr(Path, "read_bytes", bad_read)
    with pytest.raises(SystemExit, match="canonical ASCII"):
        verifier._load_checksums(checksum, {"file.whl"})

    root = tmp_path / "evidence"
    paths = _evidence(root)
    lines = paths["checksum"].read_text().splitlines()
    paths["checksum"].write_text("\n".join(reversed(lines)) + "\n")
    with pytest.raises(SystemExit, match="sorted by filename"):
        _build(root)
    _checksums(paths)
    paths["wheel"].write_bytes(b"changed")
    with pytest.raises(SystemExit, match="digest mismatch"):
        _build(root)


def test_strict_json_helpers_reject_ambiguous_values(tmp_path: Path) -> None:
    """Reject duplicate keys, nonfinite numbers, arrays, and Python-only values."""
    verifier = _module()
    for index, text in enumerate(
        ('{"x":1,"x":2}', '{"x":NaN}', "[]"),
    ):
        path = tmp_path / f"{index}.json"
        path.write_text(text)
        with pytest.raises(SystemExit):
            verifier._load_strict_json(path)
    with pytest.raises(SystemExit, match="outside strict JSON"):
        verifier._canonical_pre_serial_digest({"bad": object()})
    with pytest.raises(SystemExit, match="must be a JSON object"):
        verifier._require_mapping([], label="value")


SBOM_CASES: list[tuple[Mutator, str, bool]] = [
    (lambda d: d.__setitem__("specVersion", "1.6"), "exact CycloneDX", False),
    (lambda d: d.__setitem__("version", True), "non-integer", False),
    (lambda d: d.pop("serialNumber"), "lacks a serial", False),
    (lambda d: d.__setitem__("serialNumber", "bad"), "invalid serial", False),
    (
        lambda d: d.__setitem__(
            "serialNumber", "urn:uuid:" + d["serialNumber"].split(":", 2)[2].upper()
        ),
        "noncanonical UUID",
        False,
    ),
    (
        lambda d: d.__setitem__(
            "serialNumber", "urn:uuid:00000000-0000-5000-0000-000000000000"
        ),
        "RFC UUID variant",
        False,
    ),
    (
        lambda d: d.__setitem__(
            "serialNumber", "urn:uuid:00000000-0000-4000-8000-000000000000"
        ),
        "UUID version 5",
        False,
    ),
    (lambda d: d.__setitem__("metadata", []), "metadata must be", True),
    (lambda d: d["metadata"].__setitem__("component", []), "root component", True),
    (lambda d: d["metadata"]["component"].__setitem__("name", "x"), "package name", True),
    (
        lambda d: d["metadata"]["component"].__setitem__("version", "9.9.9"),
        "package version",
        True,
    ),
    (lambda d: d["metadata"]["component"].__setitem__("purl", "x"), "package URL", True),
    (lambda d: d["metadata"]["component"].__setitem__("hashes", []), "root hash", True),
    (
        lambda d: d["metadata"]["component"].__setitem__("properties", {}),
        "root properties",
        True,
    ),
    (
        lambda d: d["metadata"]["component"].__setitem__(
            "properties", [None, {"name": "other"}]
        ),
        "filename binding",
        True,
    ),
]


@pytest.mark.parametrize(("change", "message", "resign"), SBOM_CASES)
def test_sbom_profile_rejects_each_wrong_identity_or_binding(
    tmp_path: Path,
    change: Mutator,
    message: str,
    resign: bool,
) -> None:
    """Exercise every independent CycloneDX and artifact-binding rejection."""
    root = tmp_path / "evidence"
    paths = _evidence(root)
    _mutate(paths, change, resign=resign)
    with pytest.raises(SystemExit, match=message):
        _build(root)


def test_content_identity_and_root_reference_are_independent(tmp_path: Path) -> None:
    """Reject copied UUIDv5 identity and a valid SBOM for different bytes."""
    root = tmp_path / "evidence"
    paths = _evidence(root)
    document = json.loads(paths["wheel_sbom"].read_text())
    document["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_DNS, 'wrong')}"
    paths["wheel_sbom"].write_text(json.dumps(document))
    _checksums(paths)
    with pytest.raises(SystemExit, match="content-bound identity"):
        _build(root)

    wrong = "0" * 64
    paths["wheel_sbom"].write_text(json.dumps(_sbom(paths["wheel"].name, wrong)))
    _checksums(paths)
    with pytest.raises(SystemExit, match="root reference"):
        _build(root)
