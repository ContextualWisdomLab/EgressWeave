# Architecture decision records

Architecture decision records preserve security- and product-relevant decisions
that should not be rediscovered from source-code archaeology or pull-request
history.

## Status vocabulary

- **Proposed** — under review and not yet an accepted contract.
- **Accepted** — authoritative for new implementation work.
- **Superseded** — replaced by a later ADR, retained for history.
- **Deprecated** — still present for compatibility but not recommended.

An ADR status describes a decision's governance state. It does **not** by itself
prove that the corresponding implementation is present on protected `main`.
Product documents separately label implementation maturity.

## Index

| ADR | Status | Decision |
|---|---|---|
| [0001](0001-security-boundaries-and-modular-integration.md) | Accepted | Keep EgressWeave provider-neutral, fail-closed, standalone, and modular while binding all outbound authority channels to validated state. |
| [0002](0002-documentation-governance-and-persistence-boundary.md) | Proposed | Establish the canonical commercial documentation graph, explicit implementation-maturity labels, and the rule that EgressWeave core owns no durable database. |
| [0003](0003-work-conserving-automation-and-dependency-handoff.md) | Proposed | Make autonomous maintenance work-conserving, require exact-identity read-only dependency handoff, and treat control-plane incidents as non-terminal without broadening repository-write authority. |
| [0004](0004-bounded-canonical-automation-prompt.md) | Proposed | Store the hourly OpenCode policy in one 12 KiB canonical prompt, remove the inline YAML heredoc, and resume repository work after generic control-plane incidents without self-modifying authority. |

## When an ADR is required

Write or supersede an ADR when a change alters any of the following:

- threat model or trust boundary;
- destination, method, TLS, proxy, framing, or resource semantics;
- public API or compatibility policy;
- naruon/CWL integration boundary;
- persistence or database model;
- autonomous workflow identity, credentials, permissions, prompt source/budget, verification, execution/exit semantics, or dependency-handoff rules;
- documentation-governance or evidence-authority model;
- release, provenance, or support policy; or
- a numerical or scientific method.

Routine implementation detail, test expansion, typo correction, and behavior-
preserving refactoring do not require separate ADRs unless they expose a hidden
architectural assumption.
