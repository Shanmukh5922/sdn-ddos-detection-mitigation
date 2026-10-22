from __future__ import annotations

import random
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, List


@dataclass
class TrafficSpec:
    attack_type: str = "syn"
    duration_seconds: int = 30
    intensity: str = "medium"
    target_ip: str = "10.0.0.3"
    source_ip: str = "10.0.0.2"


def validate_lab_traffic(
    *,
    target_ip: str,
    configured_server_ip: str,
    source_ip: str,
    configured_attacker_ip: str,
    duration_seconds: int,
    intensity: int,
    attack_type: str,
) -> None:
    """Reject traffic settings that are not confined to the configured Mininet lab."""
    try:
        target = ipaddress.ip_address(target_ip)
        server = ipaddress.ip_address(configured_server_ip)
        source = ipaddress.ip_address(source_ip)
        attacker = ipaddress.ip_address(configured_attacker_ip)
    except ValueError as exc:
        raise ValueError("Source and target must be valid IP addresses.") from exc

    if target != server or source != attacker:
        raise ValueError("Traffic is restricted to the configured h2 attacker and h3 server.")
    if not 1 <= duration_seconds <= 20:
        raise ValueError("Duration must be between 1 and 20 seconds.")
    if attack_type not in {"syn", "udp"}:
        raise ValueError("Attack type must be 'syn' or 'udp'.")
    max_pps = 40 if attack_type == "syn" else 100
    if not 1 <= intensity <= max_pps:
        raise ValueError(f"{attack_type.upper()} rate must be between 1 and {max_pps} packets per second.")


def generate_normal_samples(count: int = 50, base_rate: float = 25.0) -> List[dict[str, Any]]:
    samples: List[dict[str, Any]] = []
    for i in range(count):
        rate = base_rate + (i % 9) * 2
        samples.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "packet_rate": round(rate, 2),
                "byte_rate": round(rate * 900, 2),
                "flow_count": round(rate / 2.0, 2),
                "flow_rate": round(rate / 2.0, 2),
                "syn_ratio": round(0.02 + ((i % 5) * 0.01), 4),
                "udp_ratio": round(0.04 + ((i % 4) * 0.01), 4),
                "source_ip_distribution": {f"10.0.0.{1 + (i % 5)}": 1.0},
                "protocol_distribution": {"TCP": 0.8, "UDP": 0.2},
                "label": 0,
            }
        )
    return samples


def generate_attack_samples(count: int = 50, *, attack_type: str = "syn", amplitude: float = 1.0) -> List[dict[str, Any]]:
    samples: List[dict[str, Any]] = []
    for i in range(count):
        packet_rate = 150.0 + (i * 3.5) * amplitude
        if attack_type == "udp":
            syn_ratio = 0.08
            udp_ratio = 0.55 + (i % 6) * 0.03
        else:
            syn_ratio = 0.46 + (i % 5) * 0.06
            udp_ratio = 0.08 + (i % 4) * 0.04

        source_ip_distribution = {f"10.0.0.{(i % 10) + 2}": 1.0 / (i % 7 + 1) for i in range(3)}
        samples.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "packet_rate": round(packet_rate, 2),
                "byte_rate": round(packet_rate * 900, 2),
                "flow_count": round(packet_rate / 1.5, 2),
                "flow_rate": round(packet_rate / 1.5, 2),
                "syn_ratio": round(syn_ratio, 4),
                "udp_ratio": round(udp_ratio, 4),
                "source_ip_distribution": source_ip_distribution,
                "protocol_distribution": {"TCP": 0.65, "UDP": 0.35},
                "label": 1,
            }
        )
    return samples


def build_synthetic_dataset(normal_count: int = 200, attack_count: int = 150, attack_type: str = "syn") -> List[dict[str, Any]]:
    records: List[dict[str, Any]] = []
    records.extend(generate_normal_samples(normal_count, base_rate=25.0))
    records.extend(generate_attack_samples(attack_count, attack_type=attack_type, amplitude=1.1 if attack_type == "syn" else 1.3))
    random.shuffle(records)
    return records


def experiment_summary(spec: TrafficSpec) -> dict[str, Any]:
    return {
        "attack_type": spec.attack_type,
        "duration_seconds": spec.duration_seconds,
        "intensity": spec.intensity,
        "target_ip": spec.target_ip,
        "source_ip": spec.source_ip,
    }
