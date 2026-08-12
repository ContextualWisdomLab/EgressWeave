"""Documentation contracts for the exact TLS configuration type boundary."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TLS_GUIDE = REPOSITORY_ROOT / "docs" / "research" / "tls-configuration.md"
CHANGELOG = REPOSITORY_ROOT / "CHANGELOG.md"


def _normalized(path: Path) -> str:
    """Return repository documentation with insignificant whitespace collapsed."""
    return " ".join(path.read_text(encoding="utf-8").split())


def test_tls_guide_requires_exact_configuration_type_before_dispatch() -> None:
    """Explain why subclass dispatch cannot replace the reviewed TLS policy."""
    guide = _normalized(TLS_GUIDE)

    assert (
        "The public context helper accepts only the exact `TLSConfiguration` type "
        "before it invokes `create_ssl_context()`."
    ) in guide
    assert (
        "a subclass could otherwise replace `create_ssl_context()` with "
        "caller-controlled dispatch and return a context that disables hostname "
        "verification or certificate verification"
    ) in guide


def test_changelog_records_exact_tls_configuration_type_boundary() -> None:
    """Keep the pre-1.0 TLS policy-integrity tightening visible to integrators."""
    changelog = _normalized(CHANGELOG)

    assert (
        "Require the exact `TLSConfiguration` type before TLS context creation."
    ) in changelog
    assert (
        "A subclass can no longer override `create_ssl_context()` to replace the "
        "reviewed immutable policy with a context that disables hostname or "
        "certificate verification"
    ) in changelog
