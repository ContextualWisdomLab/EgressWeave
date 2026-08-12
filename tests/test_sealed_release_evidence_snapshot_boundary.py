"""Regression tests for immutable sealed-evidence verification snapshots."""

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
    """Return one minimal valid exact-profile CycloneDX document."""
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


def _source_identity() -> bytes:
    """Return one canonical exact repository/source identity payload."""
    return (
        json.dumps(
            {
                "format": "egressweave.release-source-identity",
                "formatVersion": 1,
                "repository": REPOSITORY,
                "sourceSha": SOURCE_SHA,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _evidence(
    root: Path,
    *,
    wheel_bytes: bytes = b"wheel",
    sdist_bytes: bytes = b"sdist",
) -> dict[str, Path]:
    """Create one complete valid six-file release evidence set."""
    root.mkdir()
    wheel = root / f"egressweave-{VERSION}-py3-none-any.whl"
    sdist = root / f"egressweave-{VERSION}.tar.gz"
    wheel.write_bytes(wheel_bytes)
    sdist.write_bytes(sdist_bytes)
    wheel_sbom = root / f"{wheel.name}.cdx.json"
    sdist_sbom = root / f"{sdist.name}.cdx.json"
    wheel_sbom.write_text(
        json.dumps(_sbom(wheel.name, _digest(wheel))),
        encoding="utf-8",
    )
    sdist_sbom.write_text(
        json.dumps(_sbom(sdist.name, _digest(sdist))),
        encoding="utf-8",
    )
    source_identity = root / "SOURCE_IDENTITY.json"
    source_identity.write_bytes(_source_identity())
    checksum = root / "SHA256SUMS"
    payloads = (wheel, sdist, wheel_sbom, sdist_sbom, source_identity)
    checksum.write_text(
        "".join(
            f"{_digest(path)}  {path.name}\n"
            for path in sorted(payloads, key=lambda item: item.name)
        ),
        encoding="ascii",
    )
    return {
        "wheel": wheel,
        "sdist": sdist,
        "wheel_sbom": wheel_sbom,
        "sdist_sbom": sdist_sbom,
        "identity": source_identity,
        "checksum": checksum,
    }


def test_hashing_rejects_a_symlink_even_when_target_bytes_are_valid(
    tmp_path: Path,
) -> None:
    """Keep a post-selection symlink swap outside the digest trust boundary."""
    target = tmp_path / "target"
    target.write_bytes(b"same accepted bytes")
    link = tmp_path / "payload"
    link.symlink_to(target)

    with pytest.raises(SystemExit, match="unsafe"):
        release_evidence._sha256_file(
            link,
            maximum_bytes=64,
            label="payload",
        )


def test_descriptor_identity_error_is_masked_as_unsafe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep descriptor metadata failures behind the stable evidence boundary."""
    path = tmp_path / "payload"
    path.write_bytes(b"payload")

    def fail_lstat(candidate: Path):
        """Model a path disappearing after its descriptor has opened."""
        if candidate == path:
            raise OSError("replaced")
        return original_lstat(candidate)

    original_lstat = Path.lstat
    monkeypatch.setattr(Path, "lstat", fail_lstat)
    with (
        path.open("rb") as stream,
        pytest.raises(SystemExit, match="unreadable or unsafe"),
    ):
        release_evidence._require_open_regular_file(
            path,
            stream,
            label="payload",
        )


@pytest.mark.parametrize("mismatch", ["before", "after"])
def test_stable_read_rejects_each_digest_mismatch(mismatch: str) -> None:
    """Reject either a stale pre-read digest or a changed post-read digest."""
    content = b"stable payload"
    digest = hashlib.sha256(content).hexdigest()
    wrong_digest = "0" * 64
    digest_before = wrong_digest if mismatch == "before" else digest
    digest_after = wrong_digest if mismatch == "after" else digest

    with pytest.raises(SystemExit, match="changed during verification"):
        release_evidence._require_stable_read(
            content,
            digest_before=digest_before,
            digest_after=digest_after,
            label="payload",
        )


def test_manifest_rejects_release_root_replacement_after_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep a whole-directory replacement outside the sealed-evidence boundary."""
    root = tmp_path / "evidence"
    parked_root = tmp_path / "evidence-original"
    replacement_root = tmp_path / "evidence-replacement"
    _evidence(root)
    _evidence(
        replacement_root,
        wheel_bytes=b"replacement wheel bytes",
        sdist_bytes=b"replacement sdist bytes",
    )
    original_load_checksums = release_evidence._load_checksums

    def replace_root_then_load(
        checksum_path: Path,
        expected_names: set[str],
    ) -> tuple[dict[str, str], str]:
        """Replace the already-selected evidence directory before first hashing."""
        root.rename(parked_root)
        replacement_root.rename(root)
        return original_load_checksums(checksum_path, expected_names)

    monkeypatch.setattr(release_evidence, "_load_checksums", replace_root_then_load)

    with pytest.raises(SystemExit, match="release evidence directory changed"):
        release_evidence.build_evidence_manifest(
            root,
            repository=REPOSITORY,
            source_sha=SOURCE_SHA,
        )


def test_manifest_rejects_payload_mutation_during_sbom_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not issue a manifest after verified payload bytes have changed."""
    root = tmp_path / "evidence"
    paths = _evidence(root)
    original_verify = release_evidence._verify_sbom

    def verify_then_mutate(
        sbom_path: Path,
        *,
        artifact_name: str,
        artifact_digest: str,
        version: str,
        expected_digest: str,
    ) -> str:
        """Change the wheel only after the verifier captured all initial digests."""
        serial = original_verify(
            sbom_path,
            artifact_name=artifact_name,
            artifact_digest=artifact_digest,
            version=version,
            expected_digest=expected_digest,
        )
        if artifact_name.endswith(".tar.gz"):
            paths["wheel"].write_bytes(b"changed after initial digest verification")
        return serial

    monkeypatch.setattr(release_evidence, "_verify_sbom", verify_then_mutate)

    with pytest.raises(SystemExit, match="changed during verification"):
        release_evidence.build_evidence_manifest(
            root,
            repository=REPOSITORY,
            source_sha=SOURCE_SHA,
        )
