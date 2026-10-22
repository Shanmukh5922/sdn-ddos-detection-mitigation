from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


def _as_counts(values: Mapping[str, Any] | Iterable[Any] | None) -> dict[str, float]:
    if not values:
        return {}
    if isinstance(values, Mapping):
        return {str(k): float(v) for k, v in values.items()}
    counts: dict[str, float] = {}
    for v in values:
        key = str(v)
        counts[key] = counts.get(key, 0.0) + 1.0
    return counts


@dataclass
class EntropyDetector:
    """Shannon entropy detector that compares current traffic to a baseline."""

    baseline_entropy: float = 2.5
    sensitivity: float = 0.75
    label: str = "entropy"

    def compute_entropy(self, sample: Mapping[str, Any], field_name: str = "source_ip_distribution") -> float:
        distribution = sample.get(field_name)
        counts = _as_counts(distribution)
        total = sum(counts.values())
        if total <= 0:
            return 0.0
        entropy = 0.0
        for count in counts.values():
            p = float(count) / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def detect(self, sample: Mapping[str, Any], field_name: str = "source_ip_distribution") -> dict[str, Any]:
        current_entropy = self.compute_entropy(sample, field_name)
        delta = abs(current_entropy - self.baseline_entropy)
        threshold = self.sensitivity * max(self.baseline_entropy, 1.0)
        decision = "normal"
        if delta > threshold:
            decision = "suspicious"

        return {
            "detector": self.label,
            "decision": decision,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "triggered_condition": {
                "baseline_entropy": self.baseline_entropy,
                "current_entropy": current_entropy,
                "delta": delta,
                "threshold": threshold,
            },
            "measured_values": {
                "entropy_value": current_entropy,
                "baseline_entropy": self.baseline_entropy,
                "distribution_field": field_name,
            },
        }
