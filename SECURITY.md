# Security Policy

EgressWeave is a security boundary for outbound HTTP, so vulnerability reports are handled as coordinated disclosures rather than ordinary bug reports.

## Supported versions

| Version | Security support |
|---|---|
| 0.2.x | Supported |
| 0.1.x | No longer supported |

Only the latest minor release receives security fixes. Upgrade to the newest published version before reporting behavior that may already have been corrected.

## Reporting a vulnerability

Use GitHub's private **Report a vulnerability** flow on this repository. Do not open a public issue, pull request, discussion, or test repository containing exploit details, private addresses, credentials, or production traffic.

A useful report includes:

- the affected EgressWeave version and Python version;
- the exact policy and URL shape, with secrets and real internal hosts replaced;
- whether the issue affects validation, DNS pinning, TLS authority, redirects, proxies, local-development exceptions, or packaging;
- a minimal reproducer that does not contact third-party systems;
- the security impact and any known preconditions;
- suggested remediation or standards references, when available.

## Response targets

Maintainers aim to acknowledge a complete report within three business days, provide an initial severity assessment within seven business days, and post a status update at least every fourteen days until resolution. These are targets, not guarantees; complex resolver, TLS, or dependency issues may require coordinated upstream work.

Confirmed vulnerabilities are fixed on a private branch, assigned a CVE or GitHub Security Advisory when appropriate, tested against supported Python versions, and released before public technical details are disclosed. Credit is offered unless the reporter requests anonymity.

## Disclosure expectations

Please allow maintainers a reasonable remediation window before publication. Immediate public disclosure may be necessary only when exploitation is already widespread and withholding details would create greater harm. Maintainers will coordinate publication timing and clearly identify fixed versions and upgrade guidance.

## Security model and non-goals

Read [`docs/security-model.md`](docs/security-model.md) before filing a report. It defines the enforced invariants, trust boundaries, local-development exception, and behaviors that remain the embedding application's responsibility.
