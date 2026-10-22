from __future__ import annotations

import math
from collections import Counter
from typing import Any, Iterable, Mapping


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def counter_rate(current: float, previous: float, elapsed_seconds: float) -> float:
    """Convert a monotonically increasing counter delta to a per-second rate."""
    if elapsed_seconds <= 0:
        raise ValueError("elapsed_seconds must be positive")
    return max(0.0, float(current) - float(previous)) / elapsed_seconds


def shannon_entropy(distribution: Mapping[str, float] | Iterable[float] | None) -> float:
    if distribution is None:
        return 0.0

    if isinstance(distribution, Mapping):
        values = list(distribution.values())
    else:
        values = list(distribution)

    total = sum(float(v) for v in values)
    if total <= 0:
        return 0.0

    entropy = 0.0
    for value in values:
        p = float(value) / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def normalize_distribution(counter: Mapping[str, int] | Counter[str] | None) -> dict[str, float]:
    if not counter:
        return {}
    total = sum(float(v) for v in counter.values())
    if total <= 0:
        return {key: 0.0 for key in counter}
    return {key: float(value) / total for key, value in counter.items()}


def traffic_features(sample: Mapping[str, Any]) -> dict[str, float]:
    """Create a feature dictionary from a traffic sample.

    The implementation intentionally uses only measurements that are observable from
    controller flow statistics or lightweight instrumentation.
    """
    packet_rate = safe_float(sample.get("packet_rate"))
    byte_rate = safe_float(sample.get("byte_rate"))
    flow_count = safe_float(sample.get("flow_count"))
    flow_rate = safe_float(sample.get("flow_rate"), flow_count)
    syn_count = safe_float(sample.get("syn_count"))
    udp_count = safe_float(sample.get("udp_count"))
    total_packets = max(1.0, packet_rate)
    protocol_counts = sample.get("protocol_distribution") or {}
    src_ip_counts = sample.get("source_ip_distribution") or {}

    proto_distribution = normalize_distribution(protocol_counts)
    src_distribution = normalize_distribution(src_ip_counts)

    syn_ratio = safe_float(sample.get("syn_ratio"), syn_count / total_packets)
    udp_ratio = safe_float(sample.get("udp_ratio"), udp_count / total_packets)
    src_entropy = shannon_entropy(src_distribution)
    proto_entropy = shannon_entropy(proto_distribution)

    return {
        "packet_rate": packet_rate,
        "byte_rate": byte_rate,
        "flow_count": flow_count,
        "flow_rate": flow_rate,
        "syn_count": syn_count,
        "syn_ratio": syn_ratio,
        "udp_count": udp_count,
        "udp_ratio": udp_ratio,
        "source_ip_entropy": src_entropy,
        "protocol_entropy": proto_entropy,
    }
