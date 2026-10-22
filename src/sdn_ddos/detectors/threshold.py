from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


@dataclass
class ThresholdDetector:
    """Rule-based threshold detector for DDoS features."""

    thresholds: dict[str, float] = field(
        default_factory=lambda: {
            "packet_rate": 80.0,
            "byte_rate": 60_000.0,
            "flow_rate": 25.0,
            "syn_ratio": 0.25,
            "udp_ratio": 0.15,
        }
    )
    minimum_packet_rate_for_ratio: float = 20.0

    def update_thresholds(self, normal_observations: list[Mapping[str, Any]]) -> dict[str, float]:
        if not normal_observations:
            return self.thresholds.copy()

        values = {
            "packet_rate": [float(obs.get("packet_rate", 0.0)) for obs in normal_observations],
            "byte_rate": [float(obs.get("byte_rate", 0.0)) for obs in normal_observations],
            "flow_rate": [float(obs.get("flow_rate", obs.get("flow_count", 0.0))) for obs in normal_observations],
            "syn_ratio": [float(obs.get("syn_ratio", 0.0)) for obs in normal_observations],
            "udp_ratio": [float(obs.get("udp_ratio", 0.0)) for obs in normal_observations],
        }

        stats = {}
        for key, series in values.items():
            if not series:
                stats[key] = self.thresholds.get(key, 0.0)
                continue
            avg = sum(series) / len(series)
            high = max(series)
            stats[key] = max(avg * 2.5, high * 0.9, self.thresholds.get(key, 0.0))

        self.thresholds.update(stats)
        return self.thresholds.copy()

    def detect(self, sample: Mapping[str, Any]) -> dict[str, Any]:
        measured = {
            "packet_rate": float(sample.get("packet_rate", 0.0)),
            "byte_rate": float(sample.get("byte_rate", 0.0)),
            "flow_rate": float(sample.get("flow_rate", sample.get("flow_count", 0.0))),
            "syn_ratio": float(sample.get("syn_ratio", 0.0)),
            "udp_ratio": float(sample.get("udp_ratio", 0.0)),
        }

        triggered = []
        for name, value in measured.items():
            threshold = self.thresholds.get(name)
            if (
                name in {"syn_ratio", "udp_ratio"}
                and measured["packet_rate"] < self.minimum_packet_rate_for_ratio
            ):
                continue
            if threshold is not None and value > threshold:
                triggered.append({"feature": name, "value": value, "threshold": threshold})

        decision = "normal"
        if triggered:
            decision = "suspicious"

        return {
            "detector": "threshold",
            "decision": decision,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "triggered_condition": triggered,
            "measured_values": measured,
        }
