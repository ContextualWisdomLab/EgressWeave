"""Contracts for the canonical commercial documentation and architecture pack."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

REQUIRED_DOCUMENTS = (
    "docs/product/PRD.md",
    "docs/product/TRD.md",
    "docs/product/API_CONTRACT.md",
    "docs/product/TEST_STRATEGY.md",
    "docs/product/OPERABILITY.md",
    "docs/product/COMPLIANCE_TRACEABILITY.md",
    "docs/product/DOCUMENTATION_AUDIT.md",
    "docs/architecture/SYSTEM_ARCHITECTURE.md",
    "docs/architecture/UML.md",
    "docs/architecture/ERD.md",
    "docs/adr/README.md",
    "docs/adr/0002-documentation-governance-and-persistence-boundary.md",
    "docs/doctoring/REFERENCES.md",
)


def _read(relative_path: str) -> str:
    """Return a repository text file as UTF-8."""
    return (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")


def test_canonical_commercial_documentation_pack_is_present() -> None:
    """Keep the product source of truth discoverable without chat or PR archaeology."""
    missing = [
        path for path in REQUIRED_DOCUMENTS if not (REPOSITORY_ROOT / path).is_file()
    ]
    assert not missing, f"canonical documentation is missing: {missing}"


def test_product_documents_separate_runtime_truth_from_target_design() -> None:
    """Prevent an active PR or future target from being documented as shipped behavior."""
    required_status_terms = (
        "IMPLEMENTED-ON-PROTECTED-MAIN",
        "ACTIVE-PR",
        "ACCEPTED-TARGET",
        "PLANNED",
        "OUT-OF-SCOPE",
    )
    combined = "\n".join(
        _read(path)
        for path in (
            "docs/product/PRD.md",
            "docs/product/TRD.md",
            "docs/product/DOCUMENTATION_AUDIT.md",
        )
    )
    missing = [term for term in required_status_terms if term not in combined]
    assert not missing, f"documentation maturity vocabulary is missing: {missing}"
    assert "ARCHITECTURE.md" in combined


def test_architecture_pack_contains_machine_readable_diagrams() -> None:
    """Require structural and behavioral diagrams rather than prose-only architecture."""
    system_architecture = _read("docs/architecture/SYSTEM_ARCHITECTURE.md")
    uml = _read("docs/architecture/UML.md")
    erd = _read("docs/architecture/ERD.md")

    assert "```mermaid" in system_architecture
    assert "flowchart" in system_architecture
    assert "classDiagram" in uml
    assert "sequenceDiagram" in uml
    assert "stateDiagram" in uml
    assert "erDiagram" in erd


def test_erd_records_the_no_owned_persistence_boundary() -> None:
    """Do not invent an EgressWeave database merely to satisfy an ERD request."""
    erd = " ".join(_read("docs/architecture/ERD.md").split())

    assert "EgressWeave core owns no durable database" in erd
    assert "NON-NORMATIVE" in erd
    assert "host-owned" in erd


def test_product_contracts_cross_link_the_authoritative_spine() -> None:
    """Keep requirements, design, verification, operations, and evidence connected."""
    prd = _read("docs/product/PRD.md")
    trd = _read("docs/product/TRD.md")
    audit = _read("docs/product/DOCUMENTATION_AUDIT.md")
    adr_index = _read("docs/adr/README.md")

    for required_link in (
        "TRD.md",
        "../architecture/SYSTEM_ARCHITECTURE.md",
        "API_CONTRACT.md",
        "TEST_STRATEGY.md",
        "OPERABILITY.md",
        "COMPLIANCE_TRACEABILITY.md",
        "../doctoring/REFERENCES.md",
    ):
        assert required_link in prd or required_link in trd or required_link in audit
    assert "0001-security-boundaries-and-modular-integration.md" in adr_index
    assert "0002-documentation-governance-and-persistence-boundary.md" in adr_index


def test_repository_entrypoints_link_the_canonical_product_graph() -> None:
    """Make the commercial source of truth discoverable from normal repo entrypoints."""
    readme = _read("README.md")
    agents = _read("AGENTS.md")
    claude = _read("CLAUDE.md")

    for required_link in (
        "docs/product/PRD.md",
        "docs/product/TRD.md",
        "docs/architecture/UML.md",
        "docs/architecture/ERD.md",
        "docs/adr/README.md",
    ):
        assert required_link in readme, f"README does not link {required_link}"

    assert "docs/product/PRD.md" in agents
    assert "docs/product/TRD.md" in agents
    assert "docs/adr/README.md" in agents
    assert "docs/product/PRD.md" in claude
    assert "docs/product/TRD.md" in claude
    assert "Independent non-author approval" in agents


def test_security_model_matches_implemented_resource_bounds() -> None:
    """Reject stale security prose that denies currently implemented response controls."""
    security_model = _read("docs/security-model.md")

    assert "cap response size" not in security_model
    assert "max_response_bytes" in security_model
    assert "max_request_bytes" in security_model


def test_product_docs_keep_naruon_adapter_host_owned() -> None:
    """Keep host integration responsibility separate from the package public API."""
    api_contract = _read("docs/product/API_CONTRACT.md")
    prd = _read("docs/product/PRD.md")

    assert "naruon integration adapter that translates host configuration" not in api_contract
    assert "The standalone builder and naruon adapter SHALL share" not in prd
    assert "host-side adapter" in api_contract
    assert "host-owned" in prd


def test_doctoring_records_authoritative_standards_and_no_certification_claim() -> None:
    """Keep standards traceability explicit without overclaiming compliance status."""
    references = _read("docs/doctoring/REFERENCES.md")
    compliance = _read("docs/product/COMPLIANCE_TRACEABILITY.md")

    for required_reference in (
        "RFC 9110",
        "OWASP",
        "NIST SP 800-218",
        "SLSA",
        "Trust Services Criteria",
        "CSAP",
    ):
        assert required_reference in references or required_reference in compliance
    assert "does not claim certification" in compliance


def test_documentation_pack_has_no_unresolved_template_markers() -> None:
    """Prevent placeholder planning prose from becoming the canonical product record."""
    forbidden_markers = ("TODO", "TBD", "PLACEHOLDER", "FIXME")
    violations: list[str] = []
    for path in REQUIRED_DOCUMENTS:
        if not (REPOSITORY_ROOT / path).is_file():
            continue
        content = _read(path)
        for marker in forbidden_markers:
            if marker in content:
                violations.append(f"{path}: {marker}")
    assert not violations, f"documentation placeholders remain: {violations}"


def test_changelog_records_the_commercial_documentation_baseline() -> None:
    """Keep the new canonical product source of truth visible in release history."""
    changelog = " ".join(_read("CHANGELOG.md").split())

    assert "commercial documentation baseline" in changelog
    assert "PRD" in changelog
    assert "TRD" in changelog
    assert "UML" in changelog
    assert "ERD" in changelog
