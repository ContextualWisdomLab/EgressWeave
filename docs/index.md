# EgressWeave

EgressWeave is a provider-neutral Python library for SSRF- and DNS-rebinding-safe outbound HTTP. It gives applications an explicit egress boundary: exact HTTPS authorities and methods are authorized up front, validated DNS results are pinned through connection establishment, and request, timeout, and response resource use stays finite.

## Start here

- [README](https://github.com/ContextualWisdomLab/EgressWeave/blob/main/README.md) — installation, quickstart, API, compatibility, and security behavior.
- [Product requirements](product/PRD.md) — buyer problems, product goals, acceptance criteria, and product boundaries.
- [Technical requirements](product/TRD.md) — the technical contract behind the public behavior.
- [Architecture](https://github.com/ContextualWisdomLab/EgressWeave/blob/main/ARCHITECTURE.md) — protected-main implementation architecture.
- [Architecture views](architecture/UML.md) and [conceptual ERD](architecture/ERD.md) — system structure and the explicit no-durable-database boundary.
- [Architecture decisions](adr/README.md) — durable design decisions and their status.
- [Research grounding](research/README.md) — standards and security evidence behind authority, DNS, HTTP framing, resource limits, and TLS choices.
- [Changelog](https://github.com/ContextualWisdomLab/EgressWeave/blob/main/CHANGELOG.md) — release history and unreleased changes.
- [Repository releases](https://github.com/ContextualWisdomLab/EgressWeave/releases) — published GitHub release records when available.
- [Ask DeepWiki](https://deepwiki.com/ContextualWisdomLab/EgressWeave) — repository-oriented Q&A and navigation.

## Product boundary

EgressWeave owns the in-process outbound HTTP safety boundary. It validates destination authority, DNS results, TLS identity, HTTP request semantics, and finite request/response resource policy before and during network use. Host applications remain responsible for business authorization, tenant policy, job cancellation and quotas, and network-layer controls such as firewalls or service-mesh egress policy.

The repository distinguishes protected-main behavior from active pull-request and planned work. Product and architecture documents are the source of truth for that maturity boundary; this page intentionally does not promote unmerged work to shipped behavior.

## Onboarding

Start with the README quickstart, define the smallest exact host/port/method policy your integration needs, and keep EgressWeave's fail-closed defaults unless a reviewed integration requirement calls for a bounded override. For contributor and automation controls, follow the repository documentation rather than treating this public landing page as an operational runbook.

## License

EgressWeave is licensed under the [Apache License 2.0](https://github.com/ContextualWisdomLab/EgressWeave/blob/main/LICENSE). Package metadata and release-contract tests use the same `Apache-2.0` expression; third-party dependencies retain their own compatible license obligations.

## Publication status

GitHub Pages publication, package publication, and GitHub Releases are separate states. A source commit or a successful build is not evidence that a public package or release already exists. Use the README publication-status section and the repository's live release records as the authoritative public availability evidence.
