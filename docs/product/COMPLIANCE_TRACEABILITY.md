# EgressWeave Compliance and Control Traceability

Status: Proposed product-control mapping. This document **does not claim certification** for EgressWeave, ContextualWisdomLab, or any host deployment.

## 1. Scope

EgressWeave is a security library, not a complete information system. It can contribute technical evidence to a host's security and compliance program, but controls that depend on organization governance, identity lifecycle, physical security, human processes, service operations, data residency, backup, incident response, or certified cloud-service scope remain host/platform responsibilities.

## 2. Standards baseline

The current documentation baseline distinguishes final standards from drafts:

- NIST SP 800-218, Secure Software Development Framework (SSDF) Version 1.1, is the current final core SSDF publication.
- NIST SP 800-218 Rev. 1 / SSDF Version 1.2 is an Initial Public Draft published in December 2025 and is tracked as informative future direction rather than a final normative baseline.
- OWASP Application Security Verification Standard (ASVS) 5.0.0 was released in May 2025.
- OWASP SSRF Prevention guidance is used as a focused implementation reference for destination allowlisting, DNS/IP validation, and redirect avoidance.
- SLSA specification v1.2 is Approved and includes Build and Source tracks.
- AICPA's 2017 Trust Services Criteria with revised points of focus (2022) is used to structure SOC 2-oriented traceability; a SOC 2 report is an attestation outcome, not a property of this library by itself.
- Korea Internet & Security Agency (KISA) administers the Cloud Security Assurance Program (CSAP) certification process for eligible cloud services under its published program. A library alone is not a CSAP-certified cloud-service scope.

See [`../doctoring/REFERENCES.md`](../doctoring/REFERENCES.md) for APA 7 references.

## 3. NIST SSDF traceability

| SSDF theme | EgressWeave contribution | Host/platform responsibility |
|---|---|---|
| Prepare the organization | Repository engineering rules, ADRs, threat model, documented ownership boundaries | Governance, roles, training, enterprise risk acceptance |
| Protect software | Protected-branch expectations, exact-head evidence, hash-pinned actions/dependencies where configured, least-privilege automation design | Identity lifecycle, workstation/build-platform hardening, enterprise key management |
| Produce well-secured software | Test-first security fixes, 100% production statement/branch coverage, docstring requirements, deterministic regressions, protocol hardening | Product-specific threat analysis beyond egress, deployment configuration, host authorization |
| Respond to vulnerabilities | Security regression expectations, CHANGELOG/security notes, rollback guidance | Vulnerability intake, SLA, customer notification, incident command, patch deployment |

The draft SSDF v1.2 Source-track concepts are useful for future evidence design, but this documentation does not relabel draft requirements as final SSDF obligations.

## 4. OWASP ASVS and SSRF traceability

EgressWeave contributes to server-side request and communications controls through:

- explicit normalized destination allowlists;
- validation of all resolved A/AAAA candidates before connection;
- rejection of private/reserved/local address classes unless explicitly permitted by reviewed local policy;
- DNS-rebinding-resistant pinning and policy revalidation;
- TLS hostname identity preservation;
- disabled redirect following in guarded clients;
- disabled ambient proxy inheritance and alternate target mechanisms;
- strict HTTP method/header/framing controls;
- finite request/response resource policies.

The host must still perform application authorization, authentication, tenant isolation, input semantics, output encoding, data validation, access control, secrets management, and all other ASVS controls outside the transport boundary.

## 5. SLSA v1.2 traceability

### Source-track contributions

Repository branch protection, independent review, immutable exact-head check evidence, and auditable change history can contribute to source integrity. EgressWeave documentation must not claim a SLSA Source level without verifying every requirement of that level for the actual repository and attestation mechanism.

### Build-track contributions

Hash-locked toolchains, deterministic package checks, source identity, SBOM/release-evidence work, and protected release workflows can contribute to build provenance. The package must not claim a SLSA Build level merely because a provenance file or attestation exists; the builder and full SLSA level requirements must be independently verified.

## 6. SOC 2 Trust Services Criteria-oriented traceability

| Trust Services Criteria area | EgressWeave contribution | Host/platform evidence still required |
|---|---|---|
| Security | Least-privilege egress, secure SDLC evidence, dependency/security checks, fail-closed controls | IAM, access reviews, security operations, asset inventory, enterprise risk management |
| Availability | Finite timeouts/resources and deterministic failure boundaries | SLOs, capacity, redundancy, DR, monitoring, incident response |
| Processing integrity | Deterministic policy validation, exact authority binding, tests and evidence | End-to-end business process correctness, input/output reconciliation, job controls |
| Confidentiality | Payload-opaque evidence, no ambient proxy, TLS validation | Data classification, KMS, access control, retention, secure storage |
| Privacy | Data minimization in library evidence; no blanket payload logging | Notice/consent/legal basis, subject rights, retention, tenant/user governance |

A host pursuing SOC 2 must establish and operate the complete applicable control system over a defined period; EgressWeave supplies only a subset of technical control evidence.

## 7. CSAP-oriented traceability

KISA's CSAP program evaluates the defined cloud-service certification scope, including related systems, facilities, organizations, and support services. EgressWeave can contribute to secure outbound communications, secure development evidence, dependency/supply-chain controls, least privilege, and bounded security logging in a host SaaS/IaaS/DaaS architecture.

The host/cloud-service operator remains responsible for the certification scope, Korean public-cloud requirements, asset and personnel controls, network/system security, incident response, logging/monitoring, vulnerability assessment, penetration testing, data protection, backup/recovery, and the formal application/evaluation/renewal process.

## 8. PII and privacy design

EgressWeave does not solve privacy by blanket masking payloads. The core remains payload-opaque and purpose-limited:

- it does not need request/response bodies for routine audit evidence;
- credentials and authorization data are not routine evidence fields;
- resolved IP addresses are not exposed in decision evidence;
- hosts should avoid logging complete URLs when paths/query values may contain personal or confidential data;
- hosts should use explicit authorization, encryption, scoped retention, tenant access controls, and purpose limitation;
- reversible tokenization or pseudonymized analytics belongs in the host data architecture when required by business workflow.

## 9. Evidence expectations

Commercial procurement evidence should be reproducible and tied to exact source/release identity. Depending on release maturity it can include:

- exact-head CI and coverage/docstring evidence;
- security-scan results;
- dependency lock and vulnerability evidence;
- SBOM and provenance artifacts where actually generated;
- signed/reviewed ADRs and threat model;
- package checksums and source identity;
- release/rollback runbook;
- host control-mapping package explaining shared responsibility.

Absence of one of these artifacts must be represented as a gap or non-applicable control, not silently inferred as passing.
