# Architecture decision records

Architecture decision records preserve security- and product-relevant decisions
that should not be rediscovered from source-code archaeology or pull-request
history.

## Status vocabulary

- **Proposed** — under review and not yet an accepted contract.
- **Accepted** — authoritative for new implementation work.
- **Superseded** — replaced by a later ADR, retained for history.
- **Deprecated** — still present for compatibility but not recommended.

## Index

| ADR | Status | Decision |
|---|---|---|
| [0001](0001-security-boundaries-and-modular-integration.md) | Accepted | Keep EgressWeave provider-neutral, fail-closed, standalone, and modular while binding all outbound authority channels to validated state. |

## When an ADR is required

Write or supersede an ADR when a change alters any of the following:

- threat model or trust boundary;
- destination, method, TLS, proxy, framing, or resource semantics;
- public API or compatibility policy;
- naruon/CWL integration boundary;
- persistence or database model;
- autonomous workflow identity, credentials, permissions, or verification;
- release, provenance, or support policy; or
- a numerical or scientific method.

Routine implementation detail, test expansion, typo correction, and behavior-
preserving refactoring do not require separate ADRs unless they expose a hidden
architectural assumption.
