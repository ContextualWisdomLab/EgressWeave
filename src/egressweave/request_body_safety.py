"""Outbound request-body resource limits shared by both pinned transports.

An application can accidentally or adversarially provide an unbounded request
stream even after the destination authority has passed egress validation. This
module applies a finite byte budget twice: it rejects an oversized declared
``Content-Length`` before connection-pool dispatch and counts the actual bytes
produced by synchronous and asynchronous streams. When a content length is
present, actual stream consumption must also equal that declaration exactly.
Each bounded request stream is single-consumption so an exhausted or replayable
source cannot be retried under stale framing or a reset allowance. Only exact
built-in ``bytes`` chunks are accepted before length accounting, preventing a
subclass or arbitrary object from executing attacker-controlled conversion or
length behavior at this trust boundary. The stream that would cross any boundary
is closed before the invalid chunk can be sent, while callers continue to
receive EgressWeave's generic non-leaking denial error.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable, Iterator
from contextlib import suppress

import httpx

from egressweave.validation import EGRESS_NOT_ALLOWED, EgressNotAllowedError

_DENIAL_CLEANUP_FAILURES = (BaseException,)


def _enforce_declared_request_size(
    headers: Iterable[tuple[bytes, bytes]], max_request_bytes: int
) -> int | None:
    """Validate and return one in-budget declared request length.

    Request-header syntax and framing have already been normalized by the
    shared request-safety layer. This function nevertheless remains fail closed
    when called independently: no more than one ``Content-Length`` is accepted,
    and its value must be a non-empty sequence of ASCII decimal digits. The
    comparison is performed by decimal text length and lexical order instead of
    converting attacker-influenced arbitrarily long text with Python's integer
    parser.

    A missing ``Content-Length`` returns ``None`` because streaming requests can
    use chunked framing. Actual bytes are always constrained by the stream
    wrappers below, so this metadata check is an early rejection rather than the
    sole enforcement boundary.
    """
    content_length_values = [
        value for name, value in headers if name.lower() == b"content-length"
    ]
    if not content_length_values:
        return None
    if len(content_length_values) != 1:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    content_length = content_length_values[0]
    if not content_length or any(
        octet < ord("0") or octet > ord("9") for octet in content_length
    ):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    significant_length = content_length.lstrip(b"0")
    if not significant_length:
        return 0
    budget_text = str(max_request_bytes).encode("ascii")
    if len(significant_length) > len(budget_text) or (
        len(significant_length) == len(budget_text)
        and significant_length > budget_text
    ):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    declared_bytes = 0
    for octet in significant_length:
        declared_bytes = declared_bytes * 10 + octet - ord("0")
    return declared_bytes


def _close_sync_request_after_policy_denial(stream: httpx.SyncByteStream) -> None:
    """Contain hostile denied-stream cleanup while preserving process control flow.

    Policy denial has already been decided when this helper runs. Dependency-
    controlled custom ``BaseException`` subclasses are discarded so they cannot
    replace or become provenance for the public denial. Interpreter control-flow
    exceptions remain outside that application-level boundary and propagate.
    """
    try:
        stream.close()
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except _DENIAL_CLEANUP_FAILURES:
        return


class _BoundedSyncRequestStream(httpx.SyncByteStream):
    """Forward one synchronous request within policy and framing bounds."""

    def __init__(
        self,
        stream: httpx.SyncByteStream,
        max_request_bytes: int,
        declared_request_bytes: int | None = None,
    ) -> None:
        """Store the source, finite policy budget, and optional exact length."""
        self._stream = stream
        self._max_request_bytes = max_request_bytes
        self._declared_request_bytes = declared_request_bytes
        self._consumed_bytes = 0
        self._iteration_started = False

    def __iter__(self) -> Iterator[bytes]:
        """Yield exact bytes only after cumulative and framing-limit checks."""
        if self._iteration_started:
            _close_sync_request_after_policy_denial(self._stream)
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None
        self._iteration_started = True

        for chunk in self._stream:
            if type(chunk) is not bytes:
                _close_sync_request_after_policy_denial(self._stream)
                raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None
            self._consumed_bytes += len(chunk)
            exceeds_declared_length = (
                self._declared_request_bytes is not None
                and self._consumed_bytes > self._declared_request_bytes
            )
            if (
                self._consumed_bytes > self._max_request_bytes
                or exceeds_declared_length
            ):
                _close_sync_request_after_policy_denial(self._stream)
                raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None
            yield chunk

        if (
            self._declared_request_bytes is not None
            and self._consumed_bytes != self._declared_request_bytes
        ):
            _close_sync_request_after_policy_denial(self._stream)
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None

    def close(self) -> None:
        """Close the untrusted source without leaking ordinary cleanup failures."""
        with suppress(Exception):
            self._stream.close()


async def _close_async_request_after_policy_denial(
    stream: httpx.AsyncByteStream,
) -> None:
    """Consume child cleanup failures while preserving coordinator cancellation.

    Policy denial has already been decided when this helper runs. A dependency-
    injected stream may violate the static async contract by raising while
    ``aclose`` is called, returning a non-awaitable value, or failing or
    self-cancelling after returning its awaitable. Those child outcomes are
    discarded. Interpreter control flow raised directly during cleanup setup and
    cancellation directed at the coordinator while it awaits the gather still
    propagate to the caller.
    """
    try:
        close_awaitable = stream.aclose()
        cleanup = asyncio.gather(close_awaitable, return_exceptions=True)
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except _DENIAL_CLEANUP_FAILURES:
        return
    _ = await cleanup


class _BoundedAsyncRequestStream(httpx.AsyncByteStream):
    """Forward one asynchronous request within policy and framing bounds."""

    def __init__(
        self,
        stream: httpx.AsyncByteStream,
        max_request_bytes: int,
        declared_request_bytes: int | None = None,
    ) -> None:
        """Store the async source, finite budget, and optional exact length."""
        self._stream = stream
        self._max_request_bytes = max_request_bytes
        self._declared_request_bytes = declared_request_bytes
        self._consumed_bytes = 0
        self._iteration_started = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield exact async bytes after cumulative and framing-limit checks."""
        if self._iteration_started:
            await _close_async_request_after_policy_denial(self._stream)
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None
        self._iteration_started = True

        async for chunk in self._stream:
            if type(chunk) is not bytes:
                await _close_async_request_after_policy_denial(self._stream)
                raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None
            self._consumed_bytes += len(chunk)
            exceeds_declared_length = (
                self._declared_request_bytes is not None
                and self._consumed_bytes > self._declared_request_bytes
            )
            if (
                self._consumed_bytes > self._max_request_bytes
                or exceeds_declared_length
            ):
                await _close_async_request_after_policy_denial(self._stream)
                raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None
            yield chunk

        if (
            self._declared_request_bytes is not None
            and self._consumed_bytes != self._declared_request_bytes
        ):
            await _close_async_request_after_policy_denial(self._stream)
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None

    async def aclose(self) -> None:
        """Close the untrusted async source without leaking cleanup failures."""
        with suppress(Exception):
            await self._stream.aclose()
