"""Require the GitHub Release publisher to read release attestations."""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW = _ROOT / ".github" / "workflows" / "release.yml"


def _publisher_permissions() -> dict[str, str]:
    """Return only direct scalar permissions owned by publish-github-release."""
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    publisher = workflow.split("\n  publish-github-release:\n", 1)[1]
    permissions = publisher.split("\n    permissions:\n", 1)[1]
    parsed: dict[str, str] = {}
    for line in permissions.splitlines():
        if not line.startswith("      "):
            break
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, separator, value = stripped.partition(":")
        if not separator or not key or not value.strip():
            raise AssertionError("publisher permissions must be direct scalar entries")
        if key in parsed:
            raise AssertionError(f"duplicate publisher permission: {key}")
        parsed[key] = value.strip()
    return parsed


def test_publisher_has_minimum_release_attestation_authority() -> None:
    """Attestation verification must have read authority without broader token scope."""
    assert _publisher_permissions() == {
        "actions": "read",
        "attestations": "read",
        "contents": "write",
    }
