# EgressWeave Operability and Runbook Contract

Status: Proposed documentation baseline.

## 1. Operating model

EgressWeave is an in-process library, not a daemon. It therefore does not own a service endpoint, scheduler, durable telemetry store, alert manager, database, tenant directory, or independent availability SLO. Those controls are **OUT-OF-SCOPE** for core and are owned by the host application/platform.

The library nevertheless contributes deterministic controls and evidence that hosts can operate safely. Repository automation is a separate platform control plane; its state is not runtime product state.

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
- preserve the protected-main finite per-attempt connect timeouts and candidate ordering;
- treat the coordinator-owned global connection deadline across all staggered waits as **ACTIVE-PR** behavior until that change reaches protected main and completes operational acceptance;
- use host retry policy only when the business operation is safe to retry.

The maturity distinction matters operationally: a runbook must not instruct an operator to rely on the ACTIVE-PR global connection deadline while the installed protected-main package still exposes only its current per-attempt timeout and candidate-launch behavior. Re-evaluate this section after the corresponding implementation is integrated rather than silently promoting the target behavior.

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

## 11. Repository automation control-plane incident runbook

The bounded canonical prompt source, loader, **12,000-byte** guard, and model/verifier authority separation are **IMPLEMENTED-ON-PROTECTED-MAIN**. This runbook separately governs external scheduler/provider/connector failure evidence; repository integration alone is not proof that an external control plane has executed successfully.

When a run returns a generic scheduled-task error, misses an expected invocation, emits an empty prior response, or fails in a connector/provider path:

1. Classify the event as a **control-plane incident**, not an EgressWeave runtime defect and not product completion.
2. Record the external task identity/time and any observable connector, provider, permission, workflow, or repository evidence. The **exact hidden error code is unavailable** unless the external control plane explicitly exposes it; do not invent one.
3. Re-fetch the current automation definition, protected main, relevant PR heads/bases, workflow runs/jobs, and active-writer evidence before trusting any prior conclusion.
4. Verify the repository-local **canonical prompt** path `.github/prompts/hourly-product-maintainer.md`, regular-file/non-symlink status, and **12,000-byte** budget against the exact protected source.
5. Verify that the workflow loads that file rather than an inline YAML heredoc and that the model still lacks repository-write, review, signing, publication, and release authority.
6. Reproduce a repository-owned failure through machine-checkable tests when possible and record the exact evidence. If the evidence implicates canonical-prompt content or another `.github/**` control, request the required **external maintainer** correction; the repository-local model workflow must not modify that control itself.
7. Continue another safe in-scope EgressWeave action in the same invocation while the external correction is pending. External prompt repair alone is not completion, and a dependency wait does not justify unrelated queue starvation.
8. Do not disable the recurring loop for an unclassified transient tool, provider, rate-limit, or connector failure. Disablement requires evidence that continued execution is unsafe or impossible and that no other safe EgressWeave work remains.

External operational acceptance requires a subsequent invocation or GitHub-native workflow run to demonstrate the intended bootstrap/recovery path using the exact integrated protected source. A generic success message without repository/check evidence is not operational acceptance.

## 12. Upgrade and release acceptance

Before an upgrade:

- review `CHANGELOG.md` and public API/security-tightening notes;
- run the host's representative allow/deny integration suite;
- verify exact supported Python/dependency compatibility;
- validate package and supply-chain evidence required by the organization;
- confirm monitoring and rollback readiness.

The release source must satisfy [`TEST_STRATEGY.md`](TEST_STRATEGY.md), [`COMPLIANCE_TRACEABILITY.md`](COMPLIANCE_TRACEABILITY.md), and the repository's protected-branch review/check policy. Canonical prompt loading and authority separation are **IMPLEMENTED-ON-PROTECTED-MAIN**; external scheduler recovery remains a separate operational-acceptance claim until exact protected-source execution evidence exists.
