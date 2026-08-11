# Response extension capability boundary

EgressWeave treats dependency-provided response extensions as untrusted transport metadata. This guide is normative for revisions that include the response-extension filtering implemented by `src/egressweave/response_safety.py`.

## Security contract

HTTPCore and HTTPX define response extensions that can carry both inert metadata and live transport capabilities. In particular, `http_version` and `reason_phrase` are byte metadata, while `network_stream` exposes direct network read, write, close, TLS-upgrade, and socket-information operations. EgressWeave therefore does not forward a dependency response-extension mapping wholesale.

Caller-visible responses may receive only these keys:

- `http_version`
- `reason_phrase`

For either key, the value must be an exact built-in `bytes` object. The dependency extension container itself must be an exact built-in `dict`. Subclasses, custom mappings, polymorphic values, `network_stream`, `stream_id`, and every unknown or future extension remain internal and are not copied to the caller-visible HTTPX response.

This is a positive allowlist, not an attempt to enumerate dangerous extensions. A newly introduced dependency extension therefore remains unavailable until EgressWeave deliberately reviews and admits it.

## Failure and cleanup semantics

Ordinary failures mean every `BaseException` other than `KeyboardInterrupt`,
`SystemExit`, and `GeneratorExit`. The shared `_RESPONSE_BASE_EXCEPTIONS`
catch is reached only after those three process-control exceptions have been
explicitly re-raised. Ordinary failures while inspecting dependency-controlled
keys or values fail closed behind the generic `EgressNotAllowedError` boundary.
The denial is raised after the private inspection exception has left its active
exception context so dependency exception details are not exported to callers.

Process-control exceptions `KeyboardInterrupt`, `SystemExit`, and `GeneratorExit` are re-raised rather than normalized into policy denial. Both synchronous and asynchronous transports close the source response stream when extension validation prevents caller-visible delivery.

The extension filter does not broaden authority. Host applications continue to own path and body business authorization, tenant selection, credentials, persistence, queues, retention, and application observability. EgressWeave continues to own only its outbound transport-security boundary.

## Verification expectations

Tests for this boundary should demonstrate all of the following against the exact implementation under review:

1. `http_version` and `reason_phrase` exact-byte values survive filtering.
2. `network_stream` and unknown extension keys do not cross the caller-visible response boundary.
3. Non-exact containers and values fail closed.
4. Hostile dictionary-key lookup or comparison failures do not leak private exception provenance.
5. `KeyboardInterrupt`, `SystemExit`, and `GeneratorExit` are re-raised.
6. Source streams close deterministically on synchronous and asynchronous rejection paths.
7. Owned production statement and branch coverage are each 100%.

The exact-current-head evidence for this boundary includes these canonical
commands:

```text
pip install -e ".[test]" ruff
ruff check .
coverage run -m pytest -q
coverage report -m
python scripts/ci/hourly_product_guard.py self-test
python -m compileall -q src tests scripts
```

## References

The reviewed dependency resolution at current head `c96bc71a4c4ad00066bb3dc3a1d6094646dd6047`
pins HTTPCore 1.0.9 and HTTPX 0.28.1 in `uv.lock` (reviewed August 12, 2026).

Encode. (n.d.). *Extensions* (HTTPCore 1.0.9) [Documentation]. Encode. Retrieved
August 12, 2026, from https://www.encode.io/httpcore/extensions/

Encode. (n.d.). *Extensions* (HTTPX 0.28.1) [Documentation]. Encode. Retrieved
August 12, 2026, from https://www.python-httpx.org/advanced/extensions/
