"""Regression tests for sealed repository and source identity binding."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

import pytest

from egressweave import release_evidence

REPOSITORY = "ContextualWisdomLab/EgressWeave"
SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_SOURCE_SHA = "89abcdef0123456789abcdef0123456789abcdef"
VERSION = "0.3.0"


def _digest(path: Path) -> str:
    """Return SHA-256 for one test fixture."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _serial(document: dict[str, Any]) -> str:
    """Derive the content-bound UUIDv5 independently of production code."""
    canonical = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    prefix = "https://github.com/ContextualWisdomLab/EgressWeave/sbom/sha256/"
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, prefix + digest)}"


def _sbom(filename: str, digest: str) -> dict[str, Any]:
    """Return one valid exact-profile CycloneDX document."""
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


def _identity(source_sha: str = SOURCE_SHA, repository: str = REPOSITORY) -> bytes:
    """Return the canonical versioned source-identity payload."""
    document = {
        "format": "egressweave.release-source-identity",
        "formatVersion": 1,
        "repository": repository,
        "sourceSha": source_sha,
    }
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _checksums(root: Path) -> None:
    """Write canonical checksums for all non-checksum evidence payloads."""
    payloads = [path for path in root.iterdir() if path.name != "SHA256SUMS"]
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{_digest(path)}  {path.name}\n"
            for path in sorted(payloads, key=lambda item: item.name)
        ),
        encoding="ascii",
    )


def _evidence(
    root: Path,
    *,
    source_sha: str = SOURCE_SHA,
    repository: str = REPOSITORY,
    include_identity: bool = True,
) -> dict[str, Path]:
    """Create one complete release-evidence set, optionally without identity."""
    root.mkdir()
    wheel = root / f"egressweave-{VERSION}-py3-none-any.whl"
    sdist = root / f"egressweave-{VERSION}.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    wheel_sbom = root / f"{wheel.name}.cdx.json"
    sdist_sbom = root / f"{sdist.name}.cdx.json"
    wheel_sbom.write_text(json.dumps(_sbom(wheel.name, _digest(wheel))), encoding="utf-8")
    sdist_sbom.write_text(json.dumps(_sbom(sdist.name, _digest(sdist))), encoding="utf-8")
    identity = root / "SOURCE_IDENTITY.json"
    if include_identity:
        identity.write_bytes(_identity(source_sha, repository))
    _checksums(root)
    return {"identity": identity, "checksum": root / "SHA256SUMS"}


def _build(root: Path, *, source_sha: str = SOURCE_SHA, repository: str = REPOSITORY):
    """Build one manifest against explicit caller expectations."""
    return release_evidence.build_evidence_manifest(
        root,
        repository=repository,
        source_sha=source_sha,
    )


def test_legacy_evidence_without_sealed_source_identity_fails(tmp_path: Path) -> None:
    """Reject artifact evidence whose repository and source are only caller assertions."""
    root = tmp_path / "evidence"
    _evidence(root, include_identity=False)

    with pytest.raises(SystemExit, match="sealed source identity"):
        _build(root)


def test_valid_artifacts_cannot_be_relabeled_with_another_source(tmp_path: Path) -> None:
    """Reject a different valid-looking source SHA for the same sealed payload bytes."""
    root = tmp_path / "evidence"
    _evidence(root)

    with pytest.raises(SystemExit, match="does not match caller expectations"):
        _build(root, source_sha=OTHER_SOURCE_SHA)


def test_valid_artifacts_cannot_be_relabeled_with_another_repository(
    tmp_path: Path,
) -> None:
    """Reject a caller repository outside the exact approved repository boundary."""
    root = tmp_path / "evidence"
    _evidence(root)

    with pytest.raises(SystemExit, match="repository must equal"):
        _build(root, repository="Other/Repository")


def test_valid_identity_is_digest_bound_into_manifest(tmp_path: Path) -> None:
    """Return the sealed identity and its checksum-bound digest in manifest v2."""
    root = tmp_path / "evidence"
    paths = _evidence(root)

    manifest = _build(root)

    assert manifest["formatVersion"] == 2
    assert manifest["repository"] == REPOSITORY
    assert manifest["sourceSha"] == SOURCE_SHA
    assert manifest["sourceIdentityFilename"] == paths["identity"].name
    assert manifest["sourceIdentitySha256"] == _digest(paths["identity"])
    assert manifest["checksumFilename"] == paths["checksum"].name
    assert manifest["checksumSha256"] == _digest(paths["checksum"])


def test_changing_only_source_identity_changes_manifest_bytes(tmp_path: Path) -> None:
    """Make a source-only change alter both sealed digest and handoff bytes."""
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    _evidence(first_root)
    _evidence(second_root, source_sha=OTHER_SOURCE_SHA)

    first = _build(first_root)
    second = _build(second_root, source_sha=OTHER_SOURCE_SHA)

    assert first["sourceIdentitySha256"] != second["sourceIdentitySha256"]
    assert release_evidence._encode_evidence_manifest(first) != release_evidence._encode_evidence_manifest(second)


@pytest.mark.parametrize(
    "document",
    [
        {},
        {
            "format": "wrong",
            "formatVersion": 1,
            "repository": REPOSITORY,
            "sourceSha": SOURCE_SHA,
        },
        {
            "format": "egressweave.release-source-identity",
            "formatVersion": True,
            "repository": REPOSITORY,
            "sourceSha": SOURCE_SHA,
        },
        {
            "format": "egressweave.release-source-identity",
            "formatVersion": 1,
            "repository": "Other/Repository",
            "sourceSha": SOURCE_SHA,
        },
        {
            "format": "egressweave.release-source-identity",
            "formatVersion": 1,
            "repository": REPOSITORY,
            "sourceSha": "A" * 40,
        },
        {
            "format": "egressweave.release-source-identity",
            "formatVersion": 1,
            "repository": REPOSITORY,
            "sourceSha": SOURCE_SHA,
            "extra": "ambiguous",
        },
    ],
)
def test_invalid_exact_identity_profiles_fail_closed(
    tmp_path: Path,
    document: dict[str, Any],
) -> None:
    """Reject missing, stale, mixed, wrongly typed, or additional identity fields."""
    root = tmp_path / "evidence"
    paths = _evidence(root)
    paths["identity"].write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    _checksums(root)

    with pytest.raises(SystemExit, match="invalid exact profile"):
        _build(root)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"[]\n", "must be a JSON object"),
        (b'{"format":1,"format":2}\n', "not strict JSON"),
        (b'{"format":NaN}\n', "not strict JSON"),
    ],
)
def test_ambiguous_source_identity_json_fails_closed(
    tmp_path: Path,
    payload: bytes,
    message: str,
) -> None:
    """Reject non-object, duplicate-member, and non-finite identity JSON."""
    root = tmp_path / "evidence"
    paths = _evidence(root)
    paths["identity"].write_bytes(payload)
    _checksums(root)

    with pytest.raises(SystemExit, match=message):
        _build(root)


def test_noncanonical_identity_encoding_fails_closed(tmp_path: Path) -> None:
    """Require exact compact, sorted, newline-terminated identity bytes."""
    root = tmp_path / "evidence"
    paths = _evidence(root)
    document = json.loads(_identity())
    paths["identity"].write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    _checksums(root)

    with pytest.raises(SystemExit, match="not canonical JSON"):
        _build(root)


def test_identity_digest_must_match_the_initial_payload_snapshot(tmp_path: Path) -> None:
    """Reject a valid identity when it no longer matches the selected digest."""
    root = tmp_path / "evidence"
    paths = _evidence(root)

    with pytest.raises(SystemExit, match="changed during verification"):
        release_evidence._load_source_identity(
            paths["identity"],
            expected_digest="0" * 64,
        )


def test_oversized_identity_fails_before_unbounded_parsing(tmp_path: Path) -> None:
    """Apply a finite descriptor-read ceiling to the sealed identity payload."""
    root = tmp_path / "evidence"
    paths = _evidence(root)
    paths["identity"].write_bytes(b"x" * (release_evidence.MAX_SOURCE_IDENTITY_BYTES + 1))
    _checksums(root)

    with pytest.raises(SystemExit, match="safety bound"):
        _build(root)
