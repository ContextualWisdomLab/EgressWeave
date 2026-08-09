"""Contracts for request-body timing claims in canonical product diagrams and requirements."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    """Return one repository text file as normalized single-line text."""
    return " ".join(
        (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8").split()
    )


def test_prd_separates_declared_body_preflight_from_stream_accounting() -> None:
    """Do not claim actual streamed bytes are fully enforced before HTTPCore consumption."""
    prd = _read("docs/product/PRD.md")

    assert "finite request-body consumption" not in prd
    assert "declared request-body length" in prd
    assert "before pool dispatch" in prd
    assert "actual streamed request bytes" in prd
    assert "while HTTPCore consumes" in prd


def test_uml_places_stream_accounting_after_connection_setup() -> None:
    """Keep Mermaid request timing aligned with the shipped bounded-stream implementation."""
    uml = _read("docs/architecture/UML.md")

    assert "validate method, target, headers, body and phase budgets" not in uml
    assert "framing + declared body + phase budgets" in uml
    assert "stream exact request bytes while HTTPCore consumes body" in uml
    assert uml.index("connect only to pinned revalidated address with original TLS identity") < uml.index(
        "stream exact request bytes while HTTPCore consumes body"
    )
    assert "body / timeout violation" not in uml
    assert "declared body / timeout violation" in uml
    assert "streamed body violation" in uml
