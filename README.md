# egressweave

**SSRF- and DNS-rebinding-safe outbound HTTP for Python.**

`egressweave` validates an outbound URL against an explicit host allowlist,
refuses any target that resolves to a non-globally-routable address, and hands
back a synchronous `httpx.Client` or asynchronous `httpx.AsyncClient` whose
every connection is *pinned* to the validated addresses — rejecting any host
or port that changes after validation.

It exists because the naive pattern — resolve, check the IP, then
`httpx.get(url)` — is unsafe: the attacker-controlled DNS answer can change
between the check and the connect (a TOCTOU / DNS-rebinding attack, CWE-350),
and a permissive URL parser can be tricked into reaching internal services
(SSRF, CWE-918).

## What it defends against

- **SSRF (CWE-918):** rejects private, loopback, link-local, reserved,
  multicast, unspecified, and otherwise non-global addresses; rejects embedded
  credentials, query/fragment, plaintext `http` to remote hosts, IP-literal
  hosts, backslash smuggling, and ASCII control characters.
- **DNS rebinding / validate-then-connect TOCTOU (CWE-350):** resolves *all*
  addresses up front, validates each, and pins them into a custom transport
  that re-validates on every connect and refuses any host/port drift.
- **Egress allowlist:** only hostnames you explicitly list are reachable;
  wildcards are refused — the allowlist is exact.
- Redirects are disabled and environment proxies ignored (`trust_env=False`),
  so a `302` cannot bounce a request to an unvalidated host, and Unix sockets
  are refused.
- **Fail-closed optional configuration:** an empty or absent base URL returns a
  deny-all client rather than an unrestricted fallback transport.

## Install

```bash
pip install egressweave
```

## Quickstart

Synchronous applications:

```python
from egressweave import EgressPolicy, build_egress_sync_client

policy = EgressPolicy.from_hosts("api.openai.com, api.anthropic.com")

normalized_url, client = build_egress_sync_client(
    "https://api.openai.com/v1", policy=policy
)
with client:
    response = client.get(f"{normalized_url}/models")
```

Asynchronous applications:

```python
from egressweave import EgressPolicy, build_egress_http_client

policy = EgressPolicy.from_hosts("api.openai.com, api.anthropic.com")

normalized_url, client = await build_egress_http_client(
    "https://api.openai.com/v1", policy=policy
)
async with client:
    response = await client.get(f"{normalized_url}/models")
```

Both builders fail closed when the supplied base URL is `None`, empty, or only
whitespace: they return `(None, client)`, but that client rejects every request
with `EgressNotAllowedError` before network I/O. This lets applications preserve
optional configuration shapes without silently bypassing the egress policy.

Validate without building a client:

```python
from egressweave import EgressPolicy, validate_egress_url, EgressNotAllowedError

policy = EgressPolicy.from_hosts("api.openai.com")
try:
    url = validate_egress_url("https://api.openai.com/v1", policy=policy)
except EgressNotAllowedError:
    ...  # generic, non-leaking rejection
```

Local development (Ollama-style container name that resolves to a private IP):

```python
policy = EgressPolicy.from_hosts("ollama", allow_local=True)
```

## API

| Symbol | Purpose |
|---|---|
| `EgressPolicy` | Injected allowlist config: `from_hosts(...)`, `allow_local`, `dns_timeout_seconds`. |
| `validate_egress_url` / `validate_egress_url_details` (+ `_async`) | Validate a URL and resolve pinnable addresses. |
| `build_egress_sync_client(url, *, policy)` | Validate + build a synchronous DNS-pinned `httpx.Client`; empty URLs produce a deny-all client. |
| `build_egress_http_client(url, *, policy)` | Validate + build an asynchronous DNS-pinned `httpx.AsyncClient`; empty URLs produce a deny-all client. |
| `build_pinned_https_client(validated, *, policy)` | Build a synchronous client from an already-validated URL. |
| `build_pinned_https_async_client(validated, *, policy)` | Build an asynchronous client from an already-validated URL. |
| `ValidatedEgressURL`, `EgressNotAllowedError` | Result type and typed failure (a `ValueError`). |

## One source, multi use (OSMU)

`egressweave` is extracted, behaviour-preserving, from a production control
plane ([naruon](https://github.com/ContextualWisdomLab/naruon)), where it guards
every LLM-provider call. It is usable both as a standalone dependency and as a
git submodule. The only change on extraction was replacing the app-specific
settings object with an injected `EgressPolicy`.

## Autonomous maintenance

Two hourly, credential-separated workflows keep the pull-request queue and the
product roadmap moving without bypassing normal governance:

- at minute `07`, the repository calls the organization-owned review-fix and
  merge schedulers to inspect feedback, recheck current-head evidence, update
  eligible branches, and merge only when every central gate permits it;
- at minute `37`, a bounded Codex maintainer runs only when there are zero open
  pull requests and implements one test-driven improvement.

The product workflow uses three fresh runners. The model job has read-only
GitHub permissions, no direct network access, and can emit only a guard-checked
patch. A second credential-free job builds trusted dependencies before applying
the patch and executes modified source only inside an offline, non-root,
capability-free, read-only verifier container. A third publisher rechecks the
sealed patch but never executes modified package code before obtaining an
external write identity. CI, security scans, independent reviews, branch
protection, and guarded auto-merge remain authoritative. See
[`docs/hourly-autonomous-maintenance.md`](docs/hourly-autonomous-maintenance.md)
for the complete control and configuration contract.

## Version compatibility

The pinned transports use a few `httpx` / `httpcore` internals, so those
libraries are constrained to `httpx>=0.28,<0.29` and `httpcore>=1.0,<2.0` and
exercised by the test suite. Bumping either requires re-verifying both the
synchronous and asynchronous transports.

## Research grounding

See [`docs/research`](docs/research/README.md): OWASP SSRF Prevention, secure
by default / fail securely, CWE-918, CWE-350 (DNS rebinding / TOCTOU), and RFC
8305 (Happy Eyeballs — the concurrent connect used across asynchronously pinned
addresses).

## License

Apache-2.0. See [LICENSE](LICENSE).
