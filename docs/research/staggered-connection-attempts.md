# Bounded DNS candidates and staggered pinned connection attempts

## Decision

EgressWeave accepts at most `EgressPolicy.max_resolved_addresses` unique,
validated addresses from one platform DNS result. The default is 16. Duplicate
resolver rows collapse without consuming additional capacity, the original
resolver preference order is preserved, and a result containing more unique
addresses fails closed with the generic policy error. It is not silently
truncated because truncation could hide materially different resolver state
from operators and downstream audit correlation.

The asynchronous pinned transport starts one validated address immediately and
starts each later candidate only after a 250 ms delay while earlier attempts are
still pending. The first successful stream wins; every losing task is cancelled
and awaited. The connection-race coordinator owns one absolute monotonic
deadline derived from the caller's finite connection timeout. Each child attempt
receives only its remaining budget, and the coordinator also applies that same
remaining budget to every `asyncio.wait(...)`, including after every candidate
has already been started. Immediately after each wait returns, the coordinator
rechecks the monotonic deadline before consuming any completed task result. A
stream first observed at or after the deadline is closed and rejected, and a
child error first observed at or after the deadline is discarded behind the
stable generic policy failure. After a completed failure observed before the
deadline, the coordinator checks the same deadline again immediately before it
would schedule another candidate; if the budget has expired during result
processing, no later candidate starts and the generic deadline failure wins. An
empty wait follows the same rule: the deadline is rechecked again immediately
before the delayed candidate would be created, so time consumed between wait
return and scheduling cannot create an out-of-budget connection task. Staggered
racing therefore does not multiply the caller's timeout or turn a completion or
scheduling boundary at the deadline into unbudgeted network work. The
synchronous transport remains sequential.

When the coordinator's deadline is exhausted, it cancels and awaits every
pending attempt, consumes completed task outcomes without exposing their private
errors, closes completed successful streams best-effort, and returns the existing
generic `egress URL is not allowed` failure. Deadline cleanup treats the
injected stream as untrusted: a stream whose `aclose()` raises either before it
can return an awaitable or while that awaitable is executing cannot replace the
stable policy denial or survive as its exception provenance. A cleanup
coroutine that self-cancels with `asyncio.CancelledError` is likewise treated as
a child cleanup outcome rather than as authority to replace the deadline denial.
The implementation obtains the child cleanup awaitable and observes it through
`asyncio.gather(..., return_exceptions=True)`, while cancellation directed at
the coordinator itself still propagates normally. A more specific error
produced by an earlier child is likewise not surfaced after the coordinator has
observed exhaustion of the shared deadline. Exact hostname and port binding,
pinned-address revalidation, TLS identity, proxy isolation, address ordering,
first-success semantics before the deadline, and the injectable network-backend
boundary remain unchanged.

Python task cancellation is cooperative. The coordinator deliberately awaits
cancelled connection tasks instead of detaching live network work, so the finite
race deadline assumes an injected async network backend follows normal
cancellation semantics. Python 3.13 documents `asyncio.CancelledError` as a
direct `BaseException` subclass and generally requires cancellation of the
current task to propagate after cleanup. EgressWeave therefore distinguishes
external coordinator cancellation from cancellation produced by the untrusted
child cleanup operation: the former propagates, while the latter is consumed as
best-effort cleanup evidence. A malicious or broken connection backend that
catches and suppresses `CancelledError` indefinitely can still delay cleanup.
EgressWeave does not claim that Python can safely force-kill
cancellation-hostile coroutine code, and it does not trade this residual
dependency boundary for orphaned connection tasks.

The cardinality policy is re-applied whenever a signed validation result enters
a pinned transport or audit-evidence builder. A result created under a wider
policy therefore cannot bypass a stricter current policy. The normalized limit
is included in the policy fingerprint so operational correlation detects DNS
candidate-budget drift without recording any resolved address.

## Standards basis

RFC 8305 remains the current published IETF Standards Track Happy Eyeballs
specification. It advises clients not to start every connection simultaneously
because doing so creates unreasonable network load. It recommends starting one
candidate first, adding later attempts one at a time, cancelling losers after
the first success, and using 250 ms as the default Connection Attempt Delay. The
RFC assumes an ordered address list but does not require accepting an unbounded
list supplied by a resolver, nor does it require an application to delegate its
own finite connection deadline to child connection implementations.

Python 3.13 documents that `asyncio.wait(..., timeout=...)` returns the `done`
and `pending` task sets and does not raise `TimeoutError`; unfinished tasks are
simply returned in the pending set. Because return from the wait, application
consumption of completed tasks, and delayed scheduling after an empty wait are
distinct events, EgressWeave rechecks its own monotonic deadline immediately
after `asyncio.wait(...)`, before scheduling a later candidate from an empty
wait, and before scheduling a later candidate after completed failures. Python
also documents task cancellation as cooperative and states that
`asyncio.CancelledError` directly subclasses `BaseException`, so ordinary
`except Exception` cleanup does not intercept it. On deadline exhaustion
EgressWeave therefore cancels and awaits pending connection tasks explicitly,
observes dependency-injected cleanup cancellation separately from cancellation
of the coordinator itself, closes already completed successful streams, and
does not treat a boundary-time completion or empty wait as permission to exceed
the caller's finite budget.

CWE-400 identifies failure to constrain resource allocation as uncontrolled
resource consumption and recommends limiting resources according to expected
operating requirements. A DNS response can contain repeated or numerous address
records. Python's `socket.getaddrinfo()` exposes those results as a sequence of
address tuples; EgressWeave validates every candidate and then applies a finite
unique-address boundary before retaining pinned state or scheduling connection
attempts.

A limit of 16 is intentionally conservative for API-client use while preserving
ordinary multi-address IPv4/IPv6 deployments. Integrations with a demonstrated
need for a wider set can inject a larger positive integer or ASCII decimal
string. Zero, negative, boolean, fractional, signed, empty, non-ASCII, and other
malformed values fail at policy construction rather than disabling the control.

The IETF is developing Happy Eyeballs Version 3 in the
`draft-ietf-happy-happyeyeballs-v3` Internet-Draft series. An Internet-Draft is
work in progress and is not a published replacement for RFC 8305; it is therefore
informative rather than normative for this implementation until standardized.

## Threat and reliability model

A hostname can legitimately resolve to several IPv4 and IPv6 addresses. Without
a candidate cap, a large or compromised DNS answer can increase retained memory,
validation work, asynchronous task creation, and sequential or staggered TCP
attempts. Staggering alone limits concurrency but does not bound total work.
Without a coordinator-owned deadline, a timeout-ignoring injected backend could
also keep the final in-flight race alive after no further candidates remained to
start. Without a post-wait deadline check, a task that becomes observable exactly
as the shared budget expires could be accepted despite the caller's finite bound
or expose target-specific child error text after timeout. Without the later
pre-scheduling checks, time spent after either an empty wait or a completed
failure could let the budget expire before another candidate is launched while
still creating out-of-budget work or preserving a stale child-specific failure as
the final result. Without a best-effort cleanup boundary, a dependency-injected
stream could throw synchronously from `aclose()`, raise while its cleanup
awaitable executes, or self-cancel with `asyncio.CancelledError` and replace the
generic deadline denial with dependency-specific control flow or private text.

The combined controls preserve these invariants:

1. every address comes from the bounded validation resolver;
2. every unique address is validated before it is retained;
3. resolver preference order is preserved and duplicate rows collapse;
4. an over-limit unique set fails closed instead of being partially accepted;
5. every retained address is revalidated immediately before connect;
6. the hostname and port must still match the validated authority;
7. the first successful asynchronous stream observed before the shared deadline
   is returned and every loser is cancelled and awaited;
8. one absolute monotonic connection deadline is shared across every asynchronous
   attempt and coordinator wait;
9. the coordinator rechecks that deadline immediately after every wait, before
   scheduling a later candidate after an empty wait, and before scheduling a
   later candidate after completed failures; and
10. deadline exhaustion closes completed successful streams best-effort and uses
    the generic egress failure even if a child result or its cleanup produces
    dependency-specific text, exceptions, or child self-cancellation, while
    cancellation of the coordinator itself remains observable to its caller.

## References

MITRE Corporation. (2026). *CWE-400: Uncontrolled resource consumption* (CWE
Version 4.20). https://cwe.mitre.org/data/definitions/400.html

Python Software Foundation. (2026). *Coroutines and tasks—Waiting primitives and
task cancellation* (Python 3.13.14 documentation).
https://docs.python.org/3.13/library/asyncio-task.html

Python Software Foundation. (2026). *socket—Low-level networking interface*
(Python 3.13 documentation).
https://docs.python.org/3.13/library/socket.html#socket.getaddrinfo

Schinazi, D., & Pauly, T. (2017). *Happy Eyeballs Version 2: Better connectivity
using concurrency* (RFC 8305). Internet Engineering Task Force.
https://doi.org/10.17487/RFC8305
