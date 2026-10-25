from __future__ import annotations

from collections import Counter
from collections.abc import Hashable, Iterable, Mapping
from typing import Any


def transport_protocol(match: Mapping[str, Any]) -> str | None:
    """Resolve TCP/UDP from OpenFlow protocol or transport-port match fields."""
    protocol = match.get("ip_proto")
    try:
        protocol_number = int(protocol) if protocol is not None else None
    except (TypeError, ValueError):
        protocol_number = None

    if protocol_number == 6 or match.get("tcp_src") is not None or match.get("tcp_dst") is not None:
        return "TCP"
    if protocol_number == 17 or match.get("udp_src") is not None or match.get("udp_dst") is not None:
        return "UDP"
    return None


def cumulative_protocol_packet_counts(flow_entries: Iterable[Any]) -> Counter[str]:
    """Sum switch-maintained packet counters for each recognized transport protocol."""
    counts: Counter[str] = Counter()
    for entry in flow_entries:
        protocol = transport_protocol(entry.match)
        if protocol is not None:
            counts[protocol] += max(0, int(entry.packet_count))
    return counts


class FlowStatsAssembler:
    """Collect multipart OpenFlow flow-stat replies into complete snapshots."""

    def __init__(self) -> None:
        self._parts: dict[tuple[int, int], list[Any]] = {}

    def add_reply(
        self,
        switch_id: int,
        xid: int,
        entries: Iterable[Any],
        *,
        has_more: bool,
    ) -> list[Any] | None:
        key = (switch_id, xid)
        accumulated = self._parts.setdefault(key, [])
        accumulated.extend(entries)
        if has_more:
            return None
        return self._parts.pop(key)

    def discard(self, switch_id: int, xid: int) -> None:
        self._parts.pop((switch_id, xid), None)


class FlowRateTracker:
    """Calculate new-flow rates only from complete, time-separated snapshots."""

    def __init__(self) -> None:
        self._snapshots: dict[int, tuple[set[Hashable], float]] = {}

    def update(self, switch_id: int, flow_keys: Iterable[Hashable], timestamp: float) -> float:
        current = set(flow_keys)
        previous = self._snapshots.get(switch_id)
        self._snapshots[switch_id] = (current, timestamp)
        if previous is None:
            return 0.0

        previous_keys, previous_timestamp = previous
        elapsed = timestamp - previous_timestamp
        if elapsed <= 0:
            return 0.0

        new_flow_count = len(current - previous_keys)
        return new_flow_count / elapsed
