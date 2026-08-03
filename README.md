# egressweave

**SSRF- and DNS-rebinding-safe outbound HTTP for Python.**

`egressweave` validates an outbound URL against explicit host and TCP-port
allowlists, refuses any target that resolves to a non-globally-routable address,
and hands back an `httpx.AsyncClient` whose every connection is *pinned* to the
validated addresses — rejecting any host or port that changes after validation.

It exists because the naive pattern — resolve, check the IP, then
`httpx.get(url)` — is unsafe: the attacker-controlled DNS answer can change
between the check and the connect (a TOCTOU / DNS-rebinding attack, CWE-350),
and a permissive URL parser can be tricked into reaching internal services
(SSRF, CWE-918).

## What it defends against

- **SSRF (CWE-918):** rejects private, loopback, link-local, reserved,
  multicast, unspecified, and otherwise non-global addresses; rejects embedded
  credentials, query/fragment, plaintext `http` to remote hosts, IP-literal
  hosts, reserved explicit port `0`, backslash smuggling, and ASCII control
  characters.
- **DNS rebinding / validate-then-connect TOCTOU (CWE-350):** resolves *all*
  addresses up front, validates each, and pins them into a custom transport
  that re-validates on every connect and refuses any host or port drift.
- **Egress allowlist:** only hostnames and TCP destination ports you explicitly
  list are reachable; wildcards are refused. Remote HTTPS defaults to port 443
  because the default port set is `{80, 443}` and remote plaintext HTTP is
  rejected.
- **Fail-closed construction:** the required client factory rejects an absent
  URL instead of returning an unrestricted fallback client. The optional
  factory returns no client when no endpoint is configured.
- Redirects are disabled and environment proxies ignored (`trust_env=False`),
  so a `302` cannot bounce a request to an unvalidated host, and Unix sockets
  are refused.

## Install

```bash
pip install egressweave
```

## Quickstart

```python
from egressweave import EgressPolicy, build_egress_http_client

policy = EgressPolicy.from_hosts("api.openai.com, api.anthropic.com")

normalized_url, client = await build_egress_http_client(
    "https://api.openai.com/v1", policy=policy
)
async with client:
    resp = await client.get(f"{normalized_url}/models")
```

For an integration whose endpoint is optional, use the explicit optional
factory. An absent URL produces `(None, None)`, never a general-purpose client:

```python
from egressweave import build_optional_egress_http_client

normalized_url, client = await build_optional_egress_http_client(
    configured_url, policy=policy
)
if client is not None:
    async with client:
        ...
```

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
policy = EgressPolicy.from_hosts(
    "ollama", allow_local=True, allowed_ports=(11434,)
)
```

## API

| Symbol | Purpose |
|---|---|
| `EgressPolicy` | Exact host and TCP-port allowlists with `allow_local` and a finite, positive DNS timeout. |
| `validate_egress_url` / `validate_egress_url_details` (+ `_async`) | Validate a URL and resolve pinnable addresses. |
| `build_egress_http_client(url, *, policy)` | Require a URL, then validate and build a DNS-pinned client. |
| `build_optional_egress_http_client(url, *, policy)` | Return no client for an absent URL; otherwise validate and pin it. |
| `build_pinned_https_async_client(validated, *, policy)` | Pin an already-validated URL. |
| `ValidatedEgressURL`, `EgressNotAllowedError` | Result type and typed failure (a `ValueError`). |

## One source, multi use (OSMU)

`egressweave` is extracted, behaviour-preserving, from a production control
plane ([naruon](https://github.com/ContextualWisdomLab/naruon)), where it guards
every LLM-provider call. It is usable both as a standalone dependency and as a
git submodule. The only change on extraction was replacing the app-specific
settings object with an injected `EgressPolicy`.

## Version compatibility

The pinned transport uses a few `httpx` / `httpcore` internals, so those
libraries are constrained to `httpx>=0.28,<0.29` and `httpcore>=1.0,<2.0` and
exercised by the test-suite. Bumping either requires re-verifying the transport.

## Research grounding

See [`docs/research`](docs/research/README.md): OWASP SSRF Prevention, CWE-918,
CWE-350 (DNS rebinding / TOCTOU), and RFC 8305 (Happy Eyeballs — the concurrent
connect used across pinned addresses).

## License

Apache-2.0. See [LICENSE](LICENSE).
