# EgressWeave persistence boundary and conceptual ERD

Status: **PRESENT-CURRENT** for ownership. The entity relationship models below are **NON-NORMATIVE** and host/platform-owned.

## Persistence decision

**EgressWeave core owns no durable database.** Protected-main EgressWeave is an in-process provider-neutral security library. It owns immutable configuration/value objects, validated request state, bounded transport behavior and optional detached decision evidence in process memory. It does not own tenant databases, credential stores, job queues, durable audit logs, automation scheduler stores, retention workflows or application observability backends.

A host may persist selected EgressWeave evidence, and an automation platform may persist workflow/run/incident evidence, but such persistence is **host-owned** or **platform-owned**. Those owners define authentication, tenant authorization, encryption, retention, deletion, legal basis, backup, disaster recovery and access logging. This document therefore does not create a migration contract or physical schema for the EgressWeave package.

See [`../adr/0002-documentation-governance-and-persistence-boundary.md`](../adr/0002-documentation-governance-and-persistence-boundary.md), [`../adr/0004-bounded-canonical-automation-prompt.md`](../adr/0004-bounded-canonical-automation-prompt.md), and root [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md).

## Core runtime and automation objects: not database entities

The following are runtime types, workflow evidence concepts or conceptual responsibilities; they are **not EgressWeave database entities**:

- `EgressPolicy`
- `EgressTimeoutPolicy`
- `EgressConnectionPoolPolicy`
- `TLSConfiguration`
- `ValidatedEgressURL`
- `EgressDecisionEvidence`
- synchronous/asynchronous pinned transports
- `automation_run_record`
- `control_plane_incident_record`
- canonical prompt bytes and prompt validation results
- workflow job/check/review state
- verified patch handoff and promotion state

The first group is defined by product code and the public API contract. The automation evidence group is repository/platform governance state. Neither group creates package-owned durable persistence.

## NON-NORMATIVE host-owned runtime audit model

The following model shows how a host could persist minimized operational evidence without assigning database ownership to the library. Names deliberately use descriptive two-or-more-word `snake_case`.

```mermaid
erDiagram
    tenant_record ||--o{ policy_record : owns
    tenant_record ||--o{ audit_event : scopes
    policy_record ||--o{ policy_revision : versions
    policy_revision ||--o{ decision_record : evaluated_by
    decision_record ||--o| evidence_record : may_emit
    decision_record ||--o{ audit_event : produces
    service_origin ||--o{ decision_record : targets
    release_record ||--o{ evidence_record : interprets_with

    tenant_record {
        string tenant_record_id PK
        string tenant_display_name
        datetime created_time
    }
    policy_record {
        string policy_record_id PK
        string tenant_record_id FK
        string policy_name
        string policy_status
    }
    policy_revision {
        string policy_revision_id PK
        string policy_record_id FK
        string policy_fingerprint
        datetime effective_time
    }
    service_origin {
        string service_origin_id PK
        string canonical_hostname
        int destination_port
    }
    decision_record {
        string decision_record_id PK
        string policy_revision_id FK
        string service_origin_id FK
        string decision_outcome
        string decision_fingerprint
        datetime observed_time
    }
    evidence_record {
        string evidence_record_id PK
        string decision_record_id FK
        string policy_fingerprint
        int ipv4_address_count
        int ipv6_address_count
        string evidence_schema_version
    }
    audit_event {
        string audit_event_id PK
        string tenant_record_id FK
        string decision_record_id FK
        string event_type
        datetime event_time
    }
    release_record {
        string release_record_id PK
        string package_version
        string source_commit_sha
        string artifact_digest
    }
```

This model intentionally omits request/response bodies, credentials, raw resolved IP addresses and full URL paths. A host that needs additional fields must perform its own data classification, purpose limitation and access-control review.

## NON-NORMATIVE platform-owned automation evidence model

The next conceptual model exists only to make the scheduler ownership boundary reviewable. A GitHub/organization/automation platform may retain equivalent records, but EgressWeave core neither defines nor migrates them.

```mermaid
erDiagram
    automation_definition_record ||--o{ automation_run_record : starts
    automation_run_record ||--o{ workflow_job_record : contains
    automation_run_record ||--o{ control_plane_incident_record : may_observe
    automation_run_record ||--o{ patch_handoff_record : may_produce
    prompt_revision_record ||--o{ automation_run_record : configures
    repository_revision_record ||--o{ automation_run_record : binds
    patch_handoff_record ||--o| promotion_record : may_be_consumed_by

    automation_definition_record {
        string automation_definition_id PK
        string schedule_expression
        string automation_status
    }
    prompt_revision_record {
        string prompt_revision_id PK
        string prompt_path
        string prompt_digest
        int prompt_size_bytes
    }
    repository_revision_record {
        string repository_revision_id PK
        string repository_name
        string source_commit_sha
    }
    automation_run_record {
        string automation_run_id PK
        string automation_definition_id FK
        string prompt_revision_id FK
        string repository_revision_id FK
        string run_status
        datetime started_time
        datetime finished_time
    }
    workflow_job_record {
        string workflow_job_id PK
        string automation_run_id FK
        string job_name
        string job_status
    }
    control_plane_incident_record {
        string control_plane_incident_id PK
        string automation_run_id FK
        string observed_error_class
        string observable_evidence_digest
        datetime observed_time
    }
    patch_handoff_record {
        string patch_handoff_id PK
        string automation_run_id FK
        string base_commit_sha
        string patch_digest
        string verification_status
    }
    promotion_record {
        string promotion_record_id PK
        string patch_handoff_id FK
        string promotion_status
        string independent_review_identity
    }
```

These names are conceptual and **platform-owned**. `automation_run_record` and `control_plane_incident_record` are explicitly not EgressWeave database entities. The exact external scheduler error code may be absent; the platform record must distinguish observable evidence from inferred or unknown cause.

## Ownership matrix

| Concern | EgressWeave core | Host/automation platform |
|---|---|---|
| Security policy value objects | Owns | Constructs from reviewed configuration |
| DNS validation and pinned transport | Owns | Supplies network environment |
| Decision evidence structure | Owns public in-memory contract | Chooses whether/where to persist |
| Tenant model | Does not own | Host owns |
| Credentials and secrets | Does not own | Host/platform owns |
| Runtime audit database | Does not own | Host owns |
| Automation run/incident store | Does not own | Automation platform owns |
| Prompt revision and workflow job records | Does not own | Repository/automation platform owns |
| Retention/deletion | Does not own | Host/platform owns |
| Backup/restore | Does not own | Host/platform owns |
| Service-mesh/firewall policy | Does not own | Host owns as defense in depth |

## Migration rule

No database migration belongs in EgressWeave solely because these conceptual ERDs exist. A future change that makes durable persistence part of the package requires a new or superseding Accepted ADR, a physical data model, migration/rollback strategy, tenant/security ownership, backup/restore behavior, deletion/retention requirements and realistic migration tests before implementation can be called shipped.
