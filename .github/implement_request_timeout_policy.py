"""Apply the reviewed bounded request-timeout implementation once."""

from __future__ import annotations

from pathlib import Path


def replace_exact(
    path_text: str,
    old: str,
    new: str,
    *,
    expected_count: int = 1,
) -> None:
    """Replace an exact reviewed fragment or fail without partial publication."""
    path = Path(path_text)
    text = path.read_text(encoding="utf-8")
    observed_count = text.count(old)
    if observed_count != expected_count:
        raise RuntimeError(
            f"{path_text}: expected {expected_count} matches, found {observed_count}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8")


def replace_first(path_text: str, old: str, new: str) -> None:
    """Replace only the first reviewed fragment in one ordered document."""
    path = Path(path_text)
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"{path_text}: required fragment was not found")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def apply_policy_changes() -> None:
    """Add the immutable timeout contract to the injected egress policy."""
    replace_exact(
        "src/egressweave/policy.py",
        "HTTP methods those authorities may receive, finite request- and response-body\n"
        "budgets, and an ``allow_local`` escape hatch for local development stacks:\n",
        "HTTP methods those authorities may receive, finite request- and response-body\n"
        "budgets, finite request-phase timeout ceilings, and an ``allow_local`` escape\n"
        "hatch for local development stacks:\n",
    )
    replace_exact(
        "src/egressweave/policy.py",
        "import idna\n\nDEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS = 5.0\n",
        "import idna\n\n"
        "from egressweave.timeout_policy import (\n"
        "    DEFAULT_EGRESS_TIMEOUT_POLICY,\n"
        "    EgressTimeoutPolicy,\n"
        ")\n\n"
        "DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS = 5.0\n",
    )
    replace_exact(
        "src/egressweave/policy.py",
        "    ``CONNECT`` is always invalid because it can ask an allowlisted proxy to open\n"
        "    a tunnel to a second, unvalidated destination.\n\n"
        "    ``max_request_bytes`` is the largest outbound request body a returned client\n",
        "    ``CONNECT`` is always invalid because it can ask an allowlisted proxy to open\n"
        "    a tunnel to a second, unvalidated destination.\n\n"
        "    ``request_timeout_policy`` caps the connect, read, write, and pool timeout\n"
        "    values delegated to HTTPCore. Missing or explicitly disabled request values\n"
        "    receive the finite policy maximum, while stricter caller values are retained.\n\n"
        "    ``max_request_bytes`` is the largest outbound request body a returned client\n",
    )
    replace_exact(
        "src/egressweave/policy.py",
        "    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES\n\n"
        "    def __post_init__(self) -> None:\n",
        "    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES\n"
        "    request_timeout_policy: EgressTimeoutPolicy = DEFAULT_EGRESS_TIMEOUT_POLICY\n\n"
        "    def __post_init__(self) -> None:\n",
    )
    replace_exact(
        "src/egressweave/policy.py",
        "        if not isinstance(self.allow_local, bool):\n"
        "            raise TypeError(\"allow_local must be a boolean\")\n\n"
        "        timeout = self.dns_timeout_seconds\n",
        "        if not isinstance(self.allow_local, bool):\n"
        "            raise TypeError(\"allow_local must be a boolean\")\n"
        "        if not isinstance(self.request_timeout_policy, EgressTimeoutPolicy):\n"
        "            raise TypeError(\n"
        "                \"request_timeout_policy must be an EgressTimeoutPolicy\"\n"
        "            )\n\n"
        "        timeout = self.dns_timeout_seconds\n",
    )
    replace_exact(
        "src/egressweave/policy.py",
        "        allowed_methods: str | Iterable[str] = DEFAULT_ALLOWED_HTTP_METHODS,\n"
        "        max_request_bytes: int | str = DEFAULT_MAX_REQUEST_BYTES,\n",
        "        allowed_methods: str | Iterable[str] = DEFAULT_ALLOWED_HTTP_METHODS,\n"
        "        request_timeout_policy: EgressTimeoutPolicy = (\n"
        "            DEFAULT_EGRESS_TIMEOUT_POLICY\n"
        "        ),\n"
        "        max_request_bytes: int | str = DEFAULT_MAX_REQUEST_BYTES,\n",
        expected_count=2,
    )
    replace_exact(
        "src/egressweave/policy.py",
        "            allowed_methods=frozenset(method_items),\n"
        "            max_request_bytes=max_request_bytes,\n",
        "            allowed_methods=frozenset(method_items),\n"
        "            request_timeout_policy=request_timeout_policy,\n"
        "            max_request_bytes=max_request_bytes,\n",
        expected_count=2,
    )


def apply_request_extension_changes() -> None:
    """Sanitize HTTPX timeout extensions before either HTTPCore dispatch path."""
    replace_exact(
        "src/egressweave/request_safety.py",
        "from __future__ import annotations\n\n"
        "from collections.abc import Iterable, Mapping\n"
        "from typing import Any\n",
        "from __future__ import annotations\n\n"
        "import math\n"
        "from collections.abc import Iterable, Mapping\n"
        "from numbers import Real\n"
        "from typing import Any\n",
    )
    replace_exact(
        "src/egressweave/request_safety.py",
        "from egressweave.policy import (\n"
        "    EgressPolicy,\n"
        "    _normalize_allowed_method,\n"
        "    _normalize_host,\n"
        ")\n",
        "from egressweave.policy import (\n"
        "    EgressPolicy,\n"
        "    _normalize_allowed_method,\n"
        "    _normalize_host,\n"
        ")\n"
        "from egressweave.timeout_policy import EgressTimeoutPolicy\n",
    )
    replace_exact(
        "src/egressweave/request_safety.py",
        "_FORBIDDEN_OUTBOUND_REQUEST_FIELD_NAMES = frozenset(\n"
        "    {\n"
        "        b\"connection\",\n"
        "        b\"keep-alive\",\n"
        "        b\"proxy-authenticate\",\n"
        "        b\"proxy-authorization\",\n"
        "        b\"proxy-connection\",\n"
        "        b\"upgrade\",\n"
        "    }\n"
        ")\n",
        "_FORBIDDEN_OUTBOUND_REQUEST_FIELD_NAMES = frozenset(\n"
        "    {\n"
        "        b\"connection\",\n"
        "        b\"keep-alive\",\n"
        "        b\"proxy-authenticate\",\n"
        "        b\"proxy-authorization\",\n"
        "        b\"proxy-connection\",\n"
        "        b\"upgrade\",\n"
        "    }\n"
        ")\n"
        "_REQUEST_TIMEOUT_EXTENSION_KEYS = (\"connect\", \"read\", \"write\", \"pool\")\n",
    )
    helper = '''\n\ndef _bind_bounded_request_timeouts(\n    extensions: Mapping[str, Any],\n    timeout_policy: EgressTimeoutPolicy,\n) -> dict[str, Any]:\n    """Return request extensions with finite phase-timeout ceilings.\n\n    HTTPX carries connect, read, write, and pool timeouts in the low-level\n    ``timeout`` extension. A caller can otherwise use ``None`` to disable one or\n    every phase after the destination has already passed policy validation.\n    Missing or disabled values therefore receive the immutable policy maximum;\n    stricter non-negative finite values are preserved and larger values are\n    capped. Malformed maps, unknown keys, booleans, negative numbers, and\n    non-finite values fail through the generic policy boundary before HTTPCore\n    can allocate a connection or wait on network I/O.\n    """\n    raw_timeout = extensions.get("timeout")\n    if raw_timeout is None:\n        requested_timeouts: dict[object, object] = {}\n    elif isinstance(raw_timeout, Mapping):\n        requested_timeouts = dict(raw_timeout)\n    else:\n        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None\n\n    if any(\n        not isinstance(key, str) or key not in _REQUEST_TIMEOUT_EXTENSION_KEYS\n        for key in requested_timeouts\n    ):\n        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None\n\n    bounded_timeouts: dict[str, float] = {}\n    for key, maximum in timeout_policy.as_httpcore_timeout().items():\n        requested_value = requested_timeouts.get(key)\n        if requested_value is None:\n            bounded_timeouts[key] = maximum\n            continue\n        if isinstance(requested_value, bool) or not isinstance(requested_value, Real):\n            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None\n        normalized_value = float(requested_value)\n        if not math.isfinite(normalized_value) or normalized_value < 0:\n            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None\n        bounded_timeouts[key] = min(normalized_value, maximum)\n\n    safe_extensions = dict(extensions)\n    safe_extensions["timeout"] = bounded_timeouts\n    return safe_extensions\n'''
    replace_exact(
        "src/egressweave/request_safety.py",
        "\ndef _bind_validated_tls_server_name(\n",
        helper + "\ndef _bind_validated_tls_server_name(\n",
    )

    for transport_path in (
        "src/egressweave/sync_transport.py",
        "src/egressweave/transport.py",
    ):
        replace_exact(
            transport_path,
            "from egressweave.request_safety import (\n"
            "    _bind_validated_tls_server_name,\n",
            "from egressweave.request_safety import (\n"
            "    _bind_bounded_request_timeouts,\n"
            "    _bind_validated_tls_server_name,\n",
        )
        replace_exact(
            transport_path,
            "        safe_extensions = _bind_validated_tls_server_name(\n"
            "            request.extensions, self._validated.hostname\n"
            "        )\n",
            "        safe_extensions = _bind_bounded_request_timeouts(\n"
            "            _bind_validated_tls_server_name(\n"
            "                request.extensions, self._validated.hostname\n"
            "            ),\n"
            "            self._policy.request_timeout_policy,\n"
            "        )\n",
        )


def apply_evidence_and_docs() -> None:
    """Make timeout drift auditable and document the public security boundary."""
    replace_exact(
        "src/egressweave/decision_evidence.py",
        "        \"max_request_bytes\": policy.max_request_bytes,\n"
        "        \"max_response_bytes\": policy.max_response_bytes,\n",
        "        \"max_request_bytes\": policy.max_request_bytes,\n"
        "        \"max_response_bytes\": policy.max_response_bytes,\n"
        "        \"request_timeout_policy\": {\n"
        "            key: repr(value)\n"
        "            for key, value in (\n"
        "                policy.request_timeout_policy.as_httpcore_timeout().items()\n"
        "            )\n"
        "        },\n",
    )

    replace_exact(
        "README.md",
        "validated addresses—rejecting authority drift and bounding both outbound\n"
        "request bodies and inbound identity-coded response bodies.\n",
        "validated addresses—rejecting authority drift and bounding outbound request\n"
        "bodies, request-phase waits, and inbound identity-coded response bodies.\n",
    )
    replace_exact(
        "README.md",
        "- **Unbounded response consumption (CWE-400):** both transports force\n",
        "- **Unbounded request waits (CWE-400):** connect, read, write, and pool\n"
        "  timeout metadata is bounded at the transport boundary. Missing or `None`\n"
        "  values receive finite policy ceilings, larger values are capped, and\n"
        "  malformed low-level timeout extensions fail before HTTPCore dispatch.\n"
        "- **Unbounded response consumption (CWE-400):** both transports force\n",
    )
    replace_exact(
        "README.md",
        "artifact_policy = EgressPolicy.from_hosts(\n"
        "    \"artifacts.example.com\",\n"
        "    max_request_bytes=8 * 1024 * 1024,\n"
        "    max_response_bytes=64 * 1024 * 1024,\n"
        ")\n"
        "```\n",
        "artifact_policy = EgressPolicy.from_hosts(\n"
        "    \"artifacts.example.com\",\n"
        "    max_request_bytes=8 * 1024 * 1024,\n"
        "    max_response_bytes=64 * 1024 * 1024,\n"
        ")\n"
        "```\n\n"
        "Set request-phase timeout ceilings for an integration:\n\n"
        "```python\n"
        "from egressweave import EgressTimeoutPolicy\n\n"
        "latency_policy = EgressPolicy.from_hosts(\n"
        "    \"api.example.com\",\n"
        "    request_timeout_policy=EgressTimeoutPolicy(\n"
        "        connect_timeout_seconds=3,\n"
        "        read_timeout_seconds=15,\n"
        "        write_timeout_seconds=10,\n"
        "        pool_timeout_seconds=2,\n"
        "    ),\n"
        ")\n"
        "```\n",
    )
    replace_exact(
        "README.md",
        "The default response-body budget is 16 MiB. `max_response_bytes` accepts a\n",
        "Every policy also carries finite five-second connect, read, write, and pool\n"
        "timeout ceilings by default. Request-specific values may be stricter,\n"
        "including zero for an immediate timeout, but cannot exceed the configured\n"
        "ceiling or use `None` to disable a phase. These are per-operation inactivity\n"
        "bounds rather than a whole-request wall-clock deadline; host services should\n"
        "still apply cancellation and end-to-end job deadlines.\n\n"
        "The default response-body budget is 16 MiB. `max_response_bytes` accepts a\n",
    )
    replace_exact(
        "README.md",
        "| `EgressPolicy` | Injected exact `(hostname, port)` authority, HTTP-method, DNS-timeout, local-address, and finite request/response body resource policy; use `from_authorities(...)` when both host and port axes vary. |\n"
        "| `TLSConfiguration` | Immutable provider-neutral TLS 1.3/TLS 1.2 compatibility, private trust, and optional mutual-TLS client identity settings. |\n",
        "| `EgressPolicy` | Injected exact `(hostname, port)` authority, HTTP-method, DNS-timeout, request-timeout, local-address, and finite request/response body resource policy; use `from_authorities(...)` when both host and port axes vary. |\n"
        "| `EgressTimeoutPolicy` | Immutable connect, read, write, and pool timeout ceilings enforced immediately before HTTPCore dispatch. |\n"
        "| `TLSConfiguration` | Immutable provider-neutral TLS 1.3/TLS 1.2 compatibility, private trust, and optional mutual-TLS client identity settings. |\n",
    )
    replace_exact(
        "README.md",
        "- at minute `37`, a bounded Codex maintainer runs only when there are zero open\n"
        "  pull requests and implements one test-driven improvement.\n",
        "- at minute `37`, a supply-chain-pinned OpenCode maintainer using the existing\n"
        "  `NVIDIA_NIM_API_KEY` runs only when there are zero open pull requests and\n"
        "  implements one test-driven improvement.\n",
    )
    replace_exact(
        "README.md",
        "The product workflow uses three fresh runners. The model job has read-only\n"
        "GitHub permissions, no direct network access, and can emit only a guard-checked\n"
        "patch. A second credential-free job builds trusted dependencies before applying\n",
        "The product workflow uses three fresh runners. The model job has read-only\n"
        "GitHub permissions, block-mode egress limited to the reviewed NVIDIA endpoint,\n"
        "and can emit only a guard-checked patch. A second credential-free job builds\n"
        "trusted dependencies before applying\n",
    )
    replace_exact(
        "README.md",
        "[`request-body-resource-limits.md`](docs/research/request-body-resource-limits.md),\n"
        "and response limits in\n",
        "[`request-body-resource-limits.md`](docs/research/request-body-resource-limits.md),\n"
        "request-phase timeout ceilings in\n"
        "[`request-timeout-boundaries.md`](docs/research/request-timeout-boundaries.md),\n"
        "and response limits in\n",
    )

    replace_first(
        "CHANGELOG.md",
        "### Added\n",
        "### Added\n"
        "- Add immutable `EgressTimeoutPolicy` connect, read, write, and pool\n"
        "  ceilings and expose them through both policy constructors and decision\n"
        "  evidence fingerprints.\n",
    )
    replace_first(
        "CHANGELOG.md",
        "### Security\n",
        "### Security\n"
        "- Enforce finite request-phase timeout metadata immediately before synchronous\n"
        "  or asynchronous HTTPCore dispatch. Missing and disabled values receive policy\n"
        "  maxima, larger values are capped, stricter values are preserved, and malformed\n"
        "  timeout extensions fail through the generic policy boundary.\n",
    )

    research_document = '''# Finite outbound request-timeout boundaries

## Decision

Every `EgressPolicy` carries an immutable `EgressTimeoutPolicy` with positive
finite ceilings for connection establishment, response reads, request writes,
and connection-pool acquisition. Both pinned transports rewrite the low-level
HTTPX timeout extension immediately before HTTPCore dispatch:

- a missing timeout extension receives all four policy ceilings;
- a missing phase or `None` receives that phase's policy ceiling;
- a finite non-negative caller value is retained when it is stricter;
- a value above the ceiling is capped; and
- malformed maps, unknown keys, booleans, negative values, and non-finite
  numbers fail through the generic `EgressNotAllowedError` boundary.

Policy maxima must be greater than zero. A request may still choose zero as an
immediate, stricter timeout. The sanitized mapping is detached from caller-owned
state and preserves unrelated safe extensions, including the validated TLS
server name and tracing callbacks.

## Why client defaults are insufficient

HTTPX provides finite defaults, but its documented request extension lets a
caller override connect, read, write, and pool timeout values. `None` disables a
timeout. A custom security transport that forwards this metadata unchanged would
therefore let request code weaken a resource boundary after destination
validation. Enforcing ceilings in the transport keeps the invariant attached to
the same unskippable boundary that verifies methods, authority, SNI, request
framing, and body size.

HTTPCore applies the four phases independently. Connect timeout covers TCP and
TLS establishment; read and write timeouts bound inactivity while transferring
chunks; pool timeout bounds waiting for a reusable connection. EgressWeave
preserves those native semantics and exception types.

## Operational boundary

Phase timeouts are inactivity limits, not a single end-to-end wall-clock
deadline. A peer can make progress just before each read or write deadline, and
application processing can occur outside the transport. Embedding services must
therefore combine EgressWeave with cancellation, job-level deadlines, bounded
concurrency, queue capacity, and tenant quotas.

The timeout policy is included in the deterministic policy fingerprint so an
operator can correlate audit evidence with the exact normalized resource
boundary without exposing request URLs, timing observations, credentials, or
response data.

## Security properties

- **No timeout disablement:** missing and `None` phase values become finite.
- **No weaker override:** a request cannot exceed the immutable policy cap.
- **Stricter caller control:** non-negative values below the cap are retained.
- **Fail-closed metadata:** malformed extension shapes never reach HTTPCore.
- **Sync/async parity:** both transports call the same sanitizer immediately
  before constructing the HTTPCore request.
- **Audit-visible drift:** changing only a timeout ceiling changes both policy
  and decision fingerprints.

## Authoritative references

Encode OSS. (n.d.). *Timeouts*. HTTPX.
https://www.python-httpx.org/advanced/timeouts/

Encode OSS. (n.d.). *Extensions*. HTTPX.
https://www.python-httpx.org/advanced/extensions/

Encode OSS. (n.d.). *Request extensions*. HTTPCore.
https://www.encode.io/httpcore/extensions/

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP/1.1* (RFC 9112),
section 9.5. RFC Editor.
https://www.rfc-editor.org/rfc/rfc9112.html#section-9.5

MITRE. (2026). *CWE-400: Uncontrolled resource consumption* (Version 4.20).
Common Weakness Enumeration.
https://cwe.mitre.org/data/definitions/400.html

Open Worldwide Application Security Project. (n.d.). *Denial of service cheat
sheet*. OWASP Cheat Sheet Series.
https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
'''
    Path("docs/research/request-timeout-boundaries.md").write_text(
        research_document,
        encoding="utf-8",
    )
    replace_exact(
        "docs/research/README.md",
        "## Provenance\n",
        "## Request-phase timeout ceilings — HTTPX / HTTPCore / CWE-400\n\n"
        "HTTPX and HTTPCore carry connect, read, write, and pool timeouts in a\n"
        "low-level request extension, where `None` can disable a phase. EgressWeave\n"
        "caps that metadata at the transport boundary so request code cannot weaken\n"
        "finite resource limits after destination validation. See\n"
        "[Finite outbound request-timeout boundaries](request-timeout-boundaries.md).\n\n"
        "## Provenance\n",
    )


def main() -> None:
    """Apply every reviewed source, transport, evidence, and documentation edit."""
    apply_policy_changes()
    apply_request_extension_changes()
    apply_evidence_and_docs()


if __name__ == "__main__":
    main()
