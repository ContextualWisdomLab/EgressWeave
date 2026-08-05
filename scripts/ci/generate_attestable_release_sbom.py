"""Generate deterministic CycloneDX evidence accepted by ``actions/attest``.

The existing release SBOM foundation deliberately omits clock-derived and random
identity. GitHub's reviewed ``actions/attest`` CycloneDX parser additionally
requires ``serialNumber``. This adapter derives an RFC 4122 UUID version 5 URN
from the canonical SBOM bytes, preserving repeatability while giving the whole
SBOM document a stable content-bound identity.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import uuid
from pathlib import Path
from types import ModuleType
from typing import Any

FOUNDATION_GENERATOR_PATH = Path(__file__).with_name("generate_release_sbom.py")
ATTESTATION_PREDICATE_TYPE = "https://cyclonedx.org/bom"
CYCLONEDX_SCHEMA = "https://cyclonedx.org/schema/bom-1.7.schema.json"
CYCLONEDX_FORMAT = "CycloneDX"
CYCLONEDX_SPEC_VERSION = "1.7"
CYCLONEDX_DOCUMENT_VERSION = 1
FOUNDATION_PROFILE_ERROR = (
    "release SBOM foundation must produce exact CycloneDX 1.7 evidence"
)
STRICT_JSON_ERROR = "release SBOM foundation must produce strict JSON evidence"
DOCUMENT_IDENTITY_URL_PREFIX = (
    "https://github.com/ContextualWisdomLab/EgressWeave/sbom/sha256/"
)


def _parse_arguments() -> argparse.Namespace:
    """Parse exact artifact, reviewed evidence inputs, and output path."""
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("artifact", "manifest", "lock", "output"):
        parser.add_argument(f"--{flag}", type=Path, required=True)
    return parser.parse_args()


def _load_foundation_generator() -> ModuleType:
    """Load the repository-only foundation without importing EgressWeave."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_generate_release_sbom_foundation",
        FOUNDATION_GENERATOR_PATH,
    )
    if specification is None or specification.loader is None:
        raise SystemExit("deterministic release SBOM foundation could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _validate_foundation_sbom(sbom: object) -> dict[str, Any]:
    """Return exact CycloneDX 1.7 foundation output or fail closed."""
    if type(sbom) is not dict:
        raise SystemExit(FOUNDATION_PROFILE_ERROR)
    if any(
        sbom.get(field_name) != expected_value
        for field_name, expected_value in (
            ("$schema", CYCLONEDX_SCHEMA),
            ("bomFormat", CYCLONEDX_FORMAT),
            ("specVersion", CYCLONEDX_SPEC_VERSION),
            ("version", CYCLONEDX_DOCUMENT_VERSION),
        )
    ) or type(sbom["version"]) is not int:
        raise SystemExit(FOUNDATION_PROFILE_ERROR)
    return sbom


def _validate_strict_json_value(root: object) -> None:
    """Require only exact RFC 8259 value types without Python coercions.

    Python's JSON encoder accepts tuples as arrays and integer mapping keys as
    object names. Those conveniences can collapse distinct Python structures
    into the same serialized evidence. This iterative validator accepts only
    exact built-in dictionaries with exact string keys, exact lists, strings,
    booleans, integers, finite floats, and ``None``. Active-container tracking
    rejects cycles while allowing one immutable value or completed container to
    be referenced from more than one part of the source object.
    """
    stack: list[tuple[object, bool]] = [(root, False)]
    active_container_ids: set[int] = set()

    while stack:
        value, leaving = stack.pop()
        if leaving:
            active_container_ids.remove(id(value))
            continue

        value_type = type(value)
        if value_type is dict:
            container_id = id(value)
            if container_id in active_container_ids:
                raise SystemExit(STRICT_JSON_ERROR)
            active_container_ids.add(container_id)
            stack.append((value, True))
            for key, item in value.items():
                if type(key) is not str:
                    raise SystemExit(STRICT_JSON_ERROR)
                stack.append((item, False))
            continue

        if value_type is list:
            container_id = id(value)
            if container_id in active_container_ids:
                raise SystemExit(STRICT_JSON_ERROR)
            active_container_ids.add(container_id)
            stack.append((value, True))
            stack.extend((item, False) for item in value)
            continue

        if value is None or value_type in {str, bool, int}:
            continue
        if value_type is float and math.isfinite(value):
            continue
        raise SystemExit(STRICT_JSON_ERROR)


def _canonical_document_digest(sbom: dict[str, Any]) -> str:
    """Return SHA-256 over strict stable JSON before document identity is added."""
    _validate_strict_json_value(sbom)
    try:
        canonical = json.dumps(
            sbom,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError):
        raise SystemExit(STRICT_JSON_ERROR) from None
    return hashlib.sha256(canonical).hexdigest()


def _serial_number(sbom: dict[str, Any]) -> str:
    """Return a deterministic RFC 4122 UUID version 5 URN for the complete SBOM."""
    digest = _canonical_document_digest(sbom)
    identity_url = f"{DOCUMENT_IDENTITY_URL_PREFIX}{digest}"
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity_url)}"


def build_attestable_sbom(
    artifact_path: Path,
    manifest_path: Path,
    lock_path: Path,
) -> dict[str, Any]:
    """Build lock-bound CycloneDX 1.7 evidence with stable document identity."""
    foundation = _load_foundation_generator()
    foundation.validate_runtime_lock(manifest_path, lock_path)
    sbom = _validate_foundation_sbom(
        foundation.build_sbom(artifact_path, manifest_path)
    )
    if "serialNumber" in sbom:
        raise SystemExit("release SBOM foundation unexpectedly supplied document identity")
    sbom["serialNumber"] = _serial_number(sbom)
    return sbom


def write_attestable_sbom(sbom: dict[str, Any], output_path: Path) -> None:
    """Write stable sorted UTF-8 JSON through the reviewed foundation writer."""
    foundation = _load_foundation_generator()
    foundation.write_sbom(sbom, output_path)


def main() -> int:
    """Validate reviewed runtime evidence and generate one attestable release SBOM."""
    arguments = _parse_arguments()
    sbom = build_attestable_sbom(
        arguments.artifact.resolve(),
        arguments.manifest.resolve(),
        arguments.lock.resolve(),
    )
    write_attestable_sbom(sbom, arguments.output.resolve())
    print(
        "wrote deterministic CycloneDX 1.7 SBOM for predicate "
        f"{ATTESTATION_PREDICATE_TYPE}: {arguments.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
