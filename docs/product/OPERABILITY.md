# EgressWeave Operability and Runbook Contract

Status: Proposed documentation baseline.

## 1. Operating model

EgressWeave is an in-process library, not a daemon. It therefore does not own a service endpoint, scheduler, durable telemetry store, alert manager, database, tenant directory, or independent availability SLO. Those controls are **OUT-OF-SCOPE** for core and are owned by the host application/platform.

The library nevertheless contributes deterministic controls and evidence that hosts can operate safely.

## 2. Host-owned SLIs

A production host SHOULD expose bounded, non-sensitive metrics around EgressWeave use, such as:

- validation requests, accepted decisions, and policy denials by coarse reason class;
- URL validation and DNS-resolution latency;
- resolved-candidate count distribution without publishing the actual IP addresses;
- connection-attempt count, deadline exhaustion, and connection latency;
- connection-pool saturation/timeout rates;
- request target/header/body limit rejections;
- response header/body/content-coding limit rejections;
- TLS validation failures by coarse class;
- cleanup failures recorded without dependency-private payload details;
- decision-evidence generation failures.

A host must not place credentials, full request/response bodies, unnecessary paths/query strings, or resolved IP addresses into routine metrics merely to improve observability.

## 3. Host-owned SLOs

Because deployment topology and remote services differ, EgressWeave does not define one universal latency or availability target. The host establishes SLOs using its business criticality and network environment. Recommended dimensions include:

- successful authorized call availability;
- validation latency budget;
- DNS/connect deadline exhaustion rate;
- policy denial rate and unexpected-denial rate;
- remote dependency error budget;
- retry amplification and request concurrency;
- alerting delay for security-control regressions.

Security controls must not be relaxed merely to satisfy an availability SLO.

## 4. Deployment checklist

Before production use:

1. Construct a distinct `EgressPolicy` for each trust domain.
2. Keep allowed authorities and methods minimal.
3. Configure finite timeout, pool, request, response, and DNS policies appropriate to the integration.
4. Configure private trust roots/mTLS only through reviewed `TLSConfiguration` inputs.
5. Reuse long-lived clients and close them deterministically.
6. Keep HTTPX redirects and ambient proxies disabled for guarded calls.
7. Preserve network-layer egress policy as defense in depth.
8. Define host-level user/tenant/body/path authorization separately.
9. Define host telemetry, incident response, retry/idempotency, and retention.
10. Exercise failure scenarios before traffic cutover.

## 5. Denial runbook

When a legitimate call is denied:

1. Capture a correlation identifier and coarse denial category without copying sensitive payloads into the ticket.
2. Confirm the exact installed EgressWeave version/source evidence.
3. Reproduce with the same normalized base URL, policy, TLS, timeout, and pool configuration in a safe environment.
4. Verify the requested hostname/port/method is intentionally authorized.
5. Inspect DNS answers under the same network view and classify whether a rebinding/private/reserved-address rule is expected.
6. Check policy/resource-limit drift before considering a code change.
7. Never fall back to an unguarded HTTP client.
8. If a defect is confirmed, add a deterministic test-first regression and follow the repository security review path.

## 6. DNS and connection runbook

For DNS timeout, candidate overflow, or connect-deadline failures:

- confirm the resolver and network path rather than increasing limits blindly;
- compare observed candidate fanout with the policy's maximum;
- verify that all resolved candidates belong to the intended public/local class;
- check whether a remote service has changed to an architecture requiring an explicitly reviewed authority/network decision;
- preserve the finite global connection deadline and candidate ordering;
- use host retry policy only when the business operation is safe to retry.

## 7. TLS runbook

For certificate or handshake failures:

- verify normalized hostname/SNI and the configured trust roots;
- confirm certificate validity and hostname coverage independently;
- inspect explicit client-certificate configuration when mTLS is used;
- do not disable certificate verification as a recovery action;
- treat protocol/cipher-policy changes as security-sensitive compatibility work.

## 8. Resource-limit runbook

When `max_request_bytes`, `max_response_bytes`, header, target, timeout, or pool limits reject traffic:

- determine whether the request is legitimately outside the documented bounded profile;
- measure realistic payload/metadata sizes from authorized production samples without logging sensitive content;
- prefer application pagination/chunking or narrower responses over unbounded policy increases;
- if a larger bound is required, change trusted configuration explicitly and add load/resource regression evidence;
- reject non-finite or effectively disabled settings.

## 9. Rollback

A package rollback is acceptable only to a still-supported version whose security properties satisfy the current incident. Do not roll back across a known vulnerability merely to restore compatibility. Pin dependencies and package versions through the host's normal change-control path, preserve artifact hashes/provenance where available, and re-run smoke/egress tests after rollback.

## 10. Incident evidence

Useful incident evidence includes exact package version/source commit, policy fingerprint, coarse decision evidence, host correlation ID, timestamps, deployment/environment identity, check/run identifiers, and bounded error classification. Application-owned logs may contain more business context under separate privacy and access rules; EgressWeave itself should remain payload-opaque.

## 11. Upgrade and release acceptance

Before an upgrade:

- review `CHANGELOG.md` and public API/security-tightening notes;
- run the host's representative allow/deny integration suite;
- verify exact supported Python/dependency compatibility;
- validate package and supply-chain evidence required by the organization;
- confirm monitoring and rollback readiness.

The release source must satisfy [`TEST_STRATEGY.md`](TEST_STRATEGY.md), [`COMPLIANCE_TRACEABILITY.md`](COMPLIANCE_TRACEABILITY.md), and the repository's protected-branch review/check policy.
