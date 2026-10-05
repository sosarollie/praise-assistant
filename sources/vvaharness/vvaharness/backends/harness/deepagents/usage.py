# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Recover token usage for DeepAgents sessions.

LangChain records per-call usage on ``AIMessage.usage_metadata``; nothing on
this route populates the graph-state ``usage`` key, so terminal results
previously reported ``usage: null``. Two recovery paths:

- ``UsageAccumulator``: fed every ``astream(..., subgraphs=True)`` event, so it
  also sees persona-subagent internal turns, which run in separate
  checkpointers and never appear in the parent graph state. Subagent turns are
  included in the top-level totals and broken out per persona under an
  additive ``subagents`` key.
- ``aggregate_usage_metadata``: sums over a final state's ``messages`` for
  paths with no stream. Parent-graph turns only; subagent usage is
  under-counted on this path.

Key normalization: LangChain's ``input_tokens`` is the total input including
cached tokens (the ``UsageMetadata`` contract: the sum of all input token
types), while the Anthropic-style shape ``TOKENS.add`` consumes keeps fresh
input separate from the cache counts (taken from
``usage_metadata["input_token_details"]``):

    input_tokens (fresh) = input_tokens - cache_read - cache_creation

A record violating that inclusive contract — cache counts exceeding total
input, i.e. a gateway reporting cache tokens *outside* ``input_tokens``,
which neither installed integration normalises or validates — is detected
per record: its ``input_tokens`` is treated as already fresh and a WARN is
emitted, rather than clamping the negative difference to zero and silently
under-counting fresh input.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from langchain_core.messages import AIMessage, BaseMessage

from vvaharness.util.tokens import TokenUsage
from vvaharness.util.warn_once import warn_once


class SessionUsage(TokenUsage, total=False):
    """Session-level usage: ``TokenUsage`` totals plus a per-persona breakdown.

    Structurally a ``TokenUsage``, so it feeds ``TOKENS.add`` and the typed
    ``usage`` result fields directly; ``subagents`` is additive detail.

    ``calls`` is the number of model API requests aggregated into this record
    (one per usage-bearing assistant turn, de-duplicated by message id) —
    ``TOKENS.add`` reads it so ``totals.calls`` counts *requests*, the same
    granularity the per-turn backends record, not pre-summed session records.
    Requests that failed or carried no usage are not counted, matching every
    other route's de-facto "billable responses" definition.
    """

    calls: int
    subagents: dict[str, TokenUsage]


def _as_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


#: TTL-specific cache-write keys langchain-anthropic nests under
#: ``input_token_details`` when the API reports a ``cache_creation`` breakdown.
_EPHEMERAL_CACHE_KEYS: Final = ("ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens")

#: warn-once registry for inclusive-contract violations. An exclusive-convention
#: gateway violates on every record, so the first WARN is the signal and
#: per-record repeats would be log spam; the per-record *treatment* (input
#: taken as already fresh) still applies to every violating record.
_EXCLUSIVE_USAGE_WARNED: set[str] = set()


def _cache_counts(meta: Mapping[str, object]) -> tuple[int, int]:
    """Return ``(cache_read, cache_creation)`` from a ``usage_metadata`` dict.

    langchain-anthropic ``_create_usage_metadata`` (chat_models.py) reports a
    TTL'd cache write under the ephemeral keys and ZEROES the generic
    ``cache_creation`` when their sum is positive, so cache-write spend lives
    in exactly one of the two shapes. Mirror that: prefer the ephemeral sum,
    fall back to the generic key — reading only the generic key made every
    TTL'd cache write count (and price) as zero.
    """
    details = meta.get("input_token_details")
    if not isinstance(details, Mapping):
        return 0, 0
    ephemeral = sum(_as_int(details.get(key)) for key in _EPHEMERAL_CACHE_KEYS)
    cache_creation = ephemeral if ephemeral > 0 else _as_int(details.get("cache_creation"))
    return _as_int(details.get("cache_read")), cache_creation


def _raw_cache_creation(raw: Mapping[str, object] | None) -> int:
    """Cache-write count from a provider-raw ``usage`` dict (``response_metadata``)."""
    if raw is None:
        return 0
    creation = _as_int(raw.get("cache_creation_input_tokens"))
    if not creation:
        # Flat key absent (or zero): the TTL'd breakdown may still carry the
        # write count nested under ``cache_creation``; a non-Mapping there
        # leaves the zero as-is.
        nested = raw.get("cache_creation")
        if isinstance(nested, Mapping):
            creation = sum(_as_int(nested.get(key)) for key in _EPHEMERAL_CACHE_KEYS)
    return creation


@dataclass
class _Counts:
    """Running sums in the normalized fresh-input shape."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read: int = 0
    cache_creation: int = 0
    calls: int = 0

    def add(
        self, meta: Mapping[str, object],
        raw_usage: Mapping[str, object] | None = None,
    ) -> None:
        cache_read, cache_creation = _cache_counts(meta)
        if cache_creation == 0:
            # Some gateways fold the write into input_tokens but omit the
            # detail key; the provider-raw usage dict still carries it.
            cache_creation = _raw_cache_creation(raw_usage)
        total_input = _as_int(meta.get("input_tokens"))
        cached = cache_read + cache_creation
        if total_input < cached:
            # Contract check: ``UsageMetadata.input_tokens`` is defined as the
            # sum of ALL input token types, so the cache counts can never
            # exceed it. A violating record means an exclusive-convention
            # gateway (input already fresh-only) or a corrupt payload;
            # subtracting would go negative and clamping to zero would
            # silently under-count fresh input, so treat the input as already
            # fresh and make the anomaly visible instead of smoothing it.
            warn_once(
                _EXCLUSIVE_USAGE_WARNED,
                "exclusive-usage-record",
                f"  [deepagents] WARN: usage record reports more cached input "
                f"(read {cache_read} + write {cache_creation}) than total "
                f"input ({total_input}); treating input_tokens as fresh-only "
                f"— the gateway appears to report cache counts outside "
                f"input_tokens",
            )
            fresh = total_input
        else:
            fresh = total_input - cached
        self.input_tokens += fresh
        self.output_tokens += _as_int(meta.get("output_tokens"))
        self.cache_read += cache_read
        self.cache_creation += cache_creation
        self.calls += 1

    def as_usage(self) -> TokenUsage:
        return TokenUsage(
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            cache_read_input_tokens=self.cache_read,
            cache_creation_input_tokens=self.cache_creation,
        )


def _unpack_event(
    event: tuple[object, ...] | Mapping[str, object],
) -> tuple[tuple[str, ...], Mapping[str, object] | None]:
    """Split a stream event into ``(namespace, payload)``; payload None if malformed.

    With ``subgraphs=True`` events are ``(namespace, payload)`` tuples; the
    namespace is ``()`` for the parent graph and non-empty for a persona
    subgraph.
    """
    if not isinstance(event, tuple):
        return (), event
    try:
        raw_ns, payload = event
    except ValueError:
        return (), None
    namespace = (
        tuple(str(part) for part in raw_ns)
        if isinstance(raw_ns, (list, tuple))
        else ()
    )
    return namespace, payload if isinstance(payload, Mapping) else None


class UsageAccumulator:
    """Accumulate usage across streamed graph events and the final state.

    Messages are de-duplicated by ``AIMessage.id``, so a turn seen in a stream
    update and again in the final state is counted once. Messages without an
    id are counted on every sighting; LangGraph ``updates`` payloads emit each
    message once, so this only matters if the same id-less message is fed twice.
    """

    def __init__(self) -> None:
        """Start with empty counters and no seen message ids."""
        self._seen_ids: set[str] = set()
        self._total: _Counts = _Counts()
        self._subagents: dict[str, _Counts] = {}
        self._ns_to_agent: dict[tuple[str, ...], str] = {}

    def add_event(
        self, event: tuple[object, ...] | Mapping[str, object]
    ) -> None:
        """Consume one ``stream_mode='updates'`` event."""
        namespace, payload = _unpack_event(event)
        if payload is None:
            return
        for update in payload.values():
            self._add_update(update, namespace)

    def _add_update(self, update: object, namespace: tuple[str, ...]) -> None:
        if not isinstance(update, Mapping):
            return
        msgs = update.get("messages")
        if not isinstance(msgs, Sequence):
            return
        for msg in msgs:
            if isinstance(msg, BaseMessage):
                self.add_message(msg, namespace=namespace)

    def _is_duplicate(self, message_id: object) -> bool:
        if not isinstance(message_id, str):
            return False
        if message_id in self._seen_ids:
            return True
        self._seen_ids.add(message_id)
        return False

    def add_message(
        self, message: BaseMessage, namespace: tuple[str, ...] = ()
    ) -> None:
        """Count one message's usage, attributed to *namespace*'s persona."""
        if not isinstance(message, AIMessage):
            return
        name = message.name
        if namespace and isinstance(name, str) and name:
            self._ns_to_agent[namespace] = name
        meta = message.usage_metadata
        if meta is None or self._is_duplicate(message.id):
            return
        raw = message.response_metadata.get("usage")
        raw_usage = raw if isinstance(raw, Mapping) else None
        self._total.add(meta, raw_usage)
        if namespace:
            agent = self._agent_label(namespace, name)
            self._subagents.setdefault(agent, _Counts()).add(meta, raw_usage)

    def _agent_label(self, namespace: tuple[str, ...], name: str | None) -> str:
        if isinstance(name, str) and name:
            return name
        learned = self._ns_to_agent.get(namespace)
        if learned is not None:
            return learned
        # Namespace elements are "node_name:task_id"; the node name is stable.
        return namespace[0].split(":", 1)[0]

    def snapshot(self) -> SessionUsage | None:
        """Return a ``TOKENS.add``-compatible usage, or None if no usage seen.

        Carries the per-request count under ``calls`` (see ``SessionUsage``)
        so ``TOKENS.add`` counts the session's model API requests rather than
        one pre-summed record per graph session.
        """
        if self._total.calls == 0:
            return None
        usage = SessionUsage(**self._total.as_usage())
        usage["calls"] = self._total.calls
        if self._subagents:
            usage["subagents"] = {
                agent: counts.as_usage()
                for agent, counts in sorted(self._subagents.items())
            }
        return usage


def aggregate_usage_metadata(messages: Sequence[object]) -> SessionUsage | None:
    """Sum ``usage_metadata`` across *messages*; None when no message carried usage.

    Final-state fallback: covers parent-graph turns only (see module docstring).
    """
    accumulator = UsageAccumulator()
    for message in messages:
        if isinstance(message, BaseMessage):
            accumulator.add_message(message)
    return accumulator.snapshot()


__all__ = ["SessionUsage", "UsageAccumulator", "aggregate_usage_metadata"]
