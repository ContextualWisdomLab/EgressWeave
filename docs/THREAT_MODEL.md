# EgressWeave Threat Model

Status: **PRESENT-CURRENT** for the protected-main threat boundary unless a section is explicitly marked `ACTIVE-PR` or `ACCEPTED-TARGET`.

The normative runtime security boundary remains [`docs/security-model.md`](security-model.md), protected-main code and root [`ARCHITECTURE.md`](../ARCHITECTURE.md). This document provides the explicit threat-analysis view required for design review, acquisition diligence and change impact analysis; it does not widen product authority or claim that host controls are implemented by the library.

## 1. Protected assets

EgressWeave is intended to protect:

- network destinations outside an explicitly reviewed `(hostname, port)` authority set;
- cloud metadata, loopback, link-local, private, reserved and otherwise non-global services that are not explicitly admitted by the local-development policy;
- the integrity of reviewed egress policy, TLS configuration, timeout/resource budgets and connection-pool configuration;
- the integrity of `ValidatedEgressURL` state between validation and transport use;
- HTTP authority and TLS identity from URL validation through TCP/TLS connection and request dispatch;
- application availability against unbounded DNS, connection, request and response resource consumption;
- caller-facing denial semantics from dependency-controlled exception text and internal topology disclosure;
- minimized decision evidence from accidental inclusion of credentials, payloads, full paths or resolved IP addresses; and
- exact-source package/release evidence used by reviewers and downstream hosts.

## 2. Attacker capabilities

The attacker may control or influence one or more untrusted inputs that reach the public egress path. The model assumes the attacker may:

- choose candidate URL text, path, explicit port, method, request fields, body data and low-level HTTPX request extensions supplied by application code;
- operate an otherwise allowlisted DNS name, return several A/AAAA records, change DNS answers after validation, or return mixed safe/unsafe address classes;
- use unusual URL/authority spellings, credentials, control characters, backslashes, IP-literal forms or alternate-port syntax to seek parsing differentials;
- attempt `Host`, TLS SNI, socket-destination, proxy or absolute-form authority drift;
- send ambiguous or excessive request metadata or request bodies and return ambiguous, excessive, content-coded or dishonestly length-declared responses;
- cause individual validated connection candidates to fail, stall or complete in adversarial order;
- return dependency-controlled stream/cleanup objects that raise ordinary exceptions, cancellation-like failures or custom `BaseException` subclasses at cleanup boundaries; and
- exploit stale, predecessor-head or incomplete CI/review/release evidence if governance treats it as current.

The attacker is **not** assumed to have arbitrary code execution inside the embedding Python process, control over the trusted `EgressPolicy`/`TLSConfiguration` construction authority, the operating system kernel, the installed EgressWeave package, or the host's trusted CA/key material. If those assumptions fail, EgressWeave is defense in depth rather than a sandbox.

## 3. Trust boundaries

| Trust boundary | Trusted side | Untrusted side | Required control |
|---|---|---|---|
| Policy construction | reviewed host configuration | malformed or ambiguous deployment input | reject before request handling; use complete authority identities |
| URL parsing and normalization | immutable policy | candidate URL text | canonicalize only documented fields; reject unsupported/ambiguous forms |
| DNS resolution | reviewed hostname/policy | resolver answers and timing | finite deadline/count; validate every candidate address |
| Validated state | package-local integrity contract | forged/mutated state | verify identity, authority, address set and integrity before transport use |
| Request dispatch | validated authority/policy | method, target, fields, body, extensions | enforce exact authority, method/framing and finite resource budgets before network exposure |
| TCP connection | pinned validated addresses | connection outcomes/platform errors | revalidate each destination and keep candidate work bounded |
| TLS identity | original validated hostname and fresh configuration | peer certificate / override attempts | certificate verification and SNI identity remain bound to reviewed authority |
| Response delivery | finite response policy | peer metadata, coding, framing and body | validate and bound before/while exposing bytes to the caller |
| Denial cleanup | selected policy outcome | dependency-controlled cleanup behavior | contain dependency-private failures without replacing the stable denial; preserve interpreter/coordinator control flow |
| Decision evidence | accepted/revalidated decision | sensitive request/network detail | emit only the documented bounded evidence fields |
| Package/release evidence | exact source/release identity | stale or substituted evidence | bind acceptance to exact source; never transfer predecessor evidence |
| Host integration | EgressWeave public contracts | tenant, credentials, business authorization and durable persistence | keep those concerns host-owned and explicit |

## 4. Threats and mitigations

| Threat | Consequence | EgressWeave control | Residual / host responsibility |
|---|---|---|---|
| SSRF / unintended authority | access to metadata, internal or unexpected services | exact normalized authority allowlisting, URL restrictions and validated address classes | host chooses the correct narrow policy and retains network egress defense in depth |
| DNS rebinding / validate-then-connect TOCTOU | validation names one address while transport reaches another | validate all returned candidates, integrity-bind validated state, connect only to pinned/revalidated addresses | resolver availability/authenticity and OS network stack remain external |
| HTTP/TLS authority drift | request or certificate identity no longer matches reviewed origin | bind URL authority, `Host`, SNI, certificate hostname and socket destination | remote service authorization remains external |
| Tunnelling / method abuse | authorized origin opens a secondary connection or sensitive operation | positive method policy; `CONNECT` remains forbidden | host owns application-level method/path/body authorization |
| Request smuggling or framing ambiguity | intermediaries disagree about request boundaries | canonical request-field/body/framing validation and exact byte accounting | downstream infrastructure still requires secure HTTP configuration |
| Resource exhaustion | DNS fanout, pool starvation, unbounded bodies or waits | finite DNS, connection, pool, timeout, target, field and request/response body policies | host additionally bounds callers, retries, jobs, tenants and process-wide concurrency |
| Response decompression/size amplification | memory or CPU exhaustion before caller control | identity content-coding boundary and finite response byte accounting | richer decoding requires a separately reviewed bounded decoder |
| Dependency cleanup poisoning | private exception text or child failure replaces an already-selected denial/result | narrow cleanup containment and generic public denial | arbitrary in-process compromise is out of model |
| Policy-oracle disclosure | attackers learn internal topology/rules through errors or evidence | generic denial text and data-minimized decision evidence | host logging must remain purpose-limited and access-controlled |
| Stale review/check evidence | unsafe code is treated as reviewed/verified | exact-head evidence and branch/governance rules | GitHub control plane and reviewer governance are shared dependencies |
| Supply-chain substitution | package/source differs from reviewed object | package acceptance, source/release identity and provenance/SBOM evidence where actually integrated | builder/distributor/host must preserve complete custody and verify artifacts |

The CWE/RFC/OWASP/NIST/SLSA references supporting these decisions are maintained in [`docs/doctoring/REFERENCES.md`](doctoring/REFERENCES.md) and topic-specific [`docs/research/`](research/README.md) notes.

## 5. Security invariants

A change must preserve, unless a superseding Accepted ADR explicitly changes the boundary:

1. fail-closed handling for indeterminate policy/validation/transport states;
2. authorization by complete normalized authority identities rather than independent hostname/port projection checks;
3. validation of every resolved address and connect-time destination revalidation;
4. one authority channel across URL, HTTP `Host`, TLS SNI/certificate identity and socket destination;
5. no redirects, ambient environment proxies, Unix sockets or caller-selected destination IPs in guarded clients;
6. positive finite DNS, connection-pool, timeout, request and response resource limits;
7. generic non-leaking policy denials;
8. synchronous/asynchronous parity for shared security invariants; and
9. exact-head review/check/package evidence for integration and release claims.

## 6. Explicit non-goals

EgressWeave core does not:

- authorize application paths, query semantics, request-body business meaning, user/tenant access, API keys or OAuth scopes;
- make an allowlisted remote service trustworthy or prevent exfiltration to a legitimately authorized but compromised service;
- replace firewall, service-mesh, cloud egress, operating-system sandbox or workload-isolation controls;
- provide tenant databases, credential stores, queues, durable audit persistence, backup/restore or retention enforcement;
- perform general malware/content classification or semantic inspection of application payloads;
- provide a concrete naruon-specific adapter inside the EgressWeave package; or
- claim SOC 2, CSAP, SLSA level or other certification/assurance outcome solely because a library control or evidence artifact exists.

These ownership boundaries are also stated in [`docs/product/PRD.md`](product/PRD.md), [`docs/product/API_CONTRACT.md`](product/API_CONTRACT.md), [`docs/architecture/ERD.md`](architecture/ERD.md) and [`docs/product/COMPLIANCE_TRACEABILITY.md`](product/COMPLIANCE_TRACEABILITY.md).

## 7. Privacy and PII boundary

EgressWeave does not solve privacy by transforming or blanket-masking application payloads. The core should remain payload-opaque and purpose-limited. Credentials, raw request/response bodies, resolved IP addresses and unnecessary path/query data are not routine decision-evidence fields. Host applications own tenant/user authorization, legal basis, encryption-at-rest, retention/deletion and controlled audit access.

## 8. Automation and release threats

Repository automation is a separate authority boundary from runtime egress policy.

- Automated model output is untrusted proposed change material, not review, security-scan, merge or release authority.
- Product-development model access uses the reviewed OpenCode/contextual-orchestrator gateway path (`orchestrator/free`); reviewer identity and credentials remain separate.
- Exact-head CI/security evidence is not transferable after a head/base change.
- A green aggregate workflow does not prove a required inner security action executed when that action was skipped.
- Repository-local product development must not regain publisher credentials merely to make autonomous output easier to merge.

Where an automation or release hardening remains on an unmerged pull request, it is **ACTIVE-PR** rather than protected-main behavior.

## 9. Validation expectations

Security-boundary changes require a deterministic fail-first regression at the affected production boundary, focused GREEN evidence, the full exact-head test/coverage/package suite, applicable security scans, review resolution and the repository's integration gates. Threat-model changes that merely document already-shipped behavior must still be machine-checked against code-current terminology and ownership contracts where practical.

See [`docs/product/TEST_STRATEGY.md`](product/TEST_STRATEGY.md) and [`docs/product/TRACEABILITY.md`](product/TRACEABILITY.md).
