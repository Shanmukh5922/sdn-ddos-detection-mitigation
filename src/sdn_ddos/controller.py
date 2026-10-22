from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List

from .config import load_config
from .detectors import EntropyDetector, RandomForestDetector, ThresholdDetector
from .features import traffic_features
from .traffic import build_synthetic_dataset


@dataclass
class FeatureRecord:
    packet_rate: float = 0.0
    byte_rate: float = 0.0
    flow_count: float = 0.0
    flow_rate: float = 0.0
    syn_ratio: float = 0.0
    udp_ratio: float = 0.0
    source_ip_distribution: Dict[str, float] = field(default_factory=dict)
    protocol_distribution: Dict[str, float] = field(default_factory=dict)


class ControllerMonitor:
    """High-level controller component that coordinates detection and mitigation."""

    def __init__(self, detector_name: str = "threshold", config_path: str | None = None):
        self.config = load_config(config_path)
        self.detector_name = detector_name.lower()
        threshold_values = self.config.detection.get("threshold", {})
        self.threshold_detector = ThresholdDetector(thresholds={
            "packet_rate": float(threshold_values.get("packet_rate", 80.0)),
            "byte_rate": float(threshold_values.get("byte_rate", 60000.0)),
            "flow_rate": float(threshold_values.get("flow_rate", 25.0)),
            "syn_ratio": float(threshold_values.get("syn_ratio", 0.25)),
            "udp_ratio": float(threshold_values.get("udp_ratio", 0.15)),
        })
        self.threshold_detector.update_thresholds([
            {
                "packet_rate": self.config.normal_rate_per_second,
                "byte_rate": self.config.normal_rate_per_second * 900,
                "flow_rate": self.config.normal_rate_per_second / 2,
                "syn_ratio": 0.05,
                "udp_ratio": 0.04,
            }
        ])
        self.entropy_detector = EntropyDetector(baseline_entropy=3.0, sensitivity=0.75)
        self.random_forest_detector = RandomForestDetector()
        synthetic = build_synthetic_dataset(normal_count=80, attack_count=80, attack_type="syn")
        training_data = [
            {**traffic_features(record), "label": record["label"]}
            for record in synthetic
        ]
        self.random_forest_detector.fit(training_data)
        self.events: List[dict[str, Any]] = []

    def _build_feature_record(self, stats: Dict[str, Any]) -> FeatureRecord:
        flow_count = float(stats.get("flow_count", stats.get("flow_rate", 0.0)))
        packet_rate = float(stats.get("packet_rate", 0.0))
        byte_rate = float(stats.get("byte_rate", 0.0))
        return FeatureRecord(
            packet_rate=packet_rate,
            byte_rate=byte_rate,
            flow_count=flow_count,
            flow_rate=flow_count,
            syn_ratio=float(stats.get("syn_ratio", 0.0)),
            udp_ratio=float(stats.get("udp_ratio", 0.0)),
            source_ip_distribution=dict(stats.get("source_ip_distribution", {})),
            protocol_distribution=dict(stats.get("protocol_distribution", {})),
        )

    def collect_and_analyze(self, stats: Dict[str, Any]) -> dict[str, Any]:
        record = self._build_feature_record(stats)
        sample = traffic_features(record.__dict__)
        chosen = self._select_detector(sample, record.__dict__)
        self.events.append(chosen)
        return chosen

    def _select_detector(self, sample: Dict[str, Any], raw_sample: Dict[str, Any]) -> dict[str, Any]:
        if self.detector_name == "threshold":
            return self.threshold_detector.detect(sample)
        if self.detector_name == "entropy":
            return self.entropy_detector.detect(raw_sample)
        if self.detector_name == "random_forest":
            return self.random_forest_detector.detect(sample)
        raise ValueError(f"Unsupported detector '{self.detector_name}'")

    def evaluate_detector(self, detector_name: str, dataset: Iterable[Dict[str, Any]]) -> dict[str, Any]:
        if detector_name == "threshold":
            detections = [self.threshold_detector.detect(item) for item in dataset]
            positives = sum(1 for item in detections if item["decision"] == "suspicious")
            return {"detector": detector_name, "positives": positives, "samples": len(detections)}
        if detector_name == "entropy":
            detections = [self.entropy_detector.detect({"source_ip_distribution": item.get("source_ip_distribution", {})}) for item in dataset]
            positives = sum(1 for item in detections if item["decision"] == "suspicious")
            return {"detector": detector_name, "positives": positives, "samples": len(detections)}
        raise ValueError(f"Unsupported detector '{detector_name}'")

    def get_alerts(self) -> List[dict[str, Any]]:
        return [event for event in self.events if event.get("decision") == "suspicious"]
