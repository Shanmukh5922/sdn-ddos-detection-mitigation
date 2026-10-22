from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, List

from .config import load_config
from .detectors import EntropyDetector, RandomForestDetector, ThresholdDetector
from .traffic import build_synthetic_dataset


def evaluate_detectors(dataset: Iterable[dict[str, Any]], *, config_path: str | Path | None = None) -> dict[str, Any]:
    config = load_config(config_path)
    threshold = ThresholdDetector()
    threshold.update_thresholds([
        {"packet_rate": config.normal_rate_per_second, "byte_rate": config.normal_rate_per_second * 900, "flow_rate": config.normal_rate_per_second / 2, "syn_ratio": 0.05, "udp_ratio": 0.04}
    ])
    entropy = EntropyDetector(baseline_entropy=2.5, sensitivity=0.75)
    random_forest_cfg = config.detection.get("random_forest", {})
    rf = RandomForestDetector(random_state=int(random_forest_cfg.get("random_state", 42)))
    rf_dataset = list(dataset)
    rf_metrics = rf.evaluate(rf_dataset)

    return {
        "threshold": [threshold.detect(item) for item in rf_dataset[:5]],
        "entropy": [entropy.detect({"source_ip_distribution": item.get("source_ip_distribution", {})}) for item in rf_dataset[:5]],
        "random_forest": rf_metrics,
    }


def synthetic_demo() -> dict[str, Any]:
    dataset = build_synthetic_dataset(normal_count=220, attack_count=180, attack_type="syn")
    result = evaluate_detectors(dataset)
    return result
