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

    assert "exact `TLSConfiguration` type" in guide
    assert "subclass" in guide
    assert "before" in guide and "create_ssl_context" in guide
    assert "hostname verification" in guide
    assert "certificate verification" in guide


def test_changelog_records_exact_tls_configuration_type_boundary() -> None:
    """Keep the pre-1.0 TLS policy-integrity tightening visible to integrators."""
    changelog = _normalized(CHANGELOG)

    assert "exact `TLSConfiguration` type" in changelog
    assert "subclass" in changelog
