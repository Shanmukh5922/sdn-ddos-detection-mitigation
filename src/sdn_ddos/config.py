from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict

import yaml


@dataclass
class LabConfig:
    project_name: str = "Intelligent DDoS Detection and Mitigation in SDN"
    lab_network: str = "10.0.0.0/24"
    controller_ip: str = "127.0.0.1"
    controller_port: int = 6633
    stats_interval_seconds: float = 1.0
    server_ip: str = "10.0.0.3"
    attacker_ip: str = "10.0.0.2"
    client_ip: str = "10.0.0.1"
    attacker_ports: list[int] = field(default_factory=lambda: [80, 443, 8080])
    normal_rate_per_second: int = 20
    attack_levels: Dict[str, Dict[str, float]] = field(default_factory=dict)
    detection: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    rule_ttl_seconds: int = 30
    rate_limit_pps: int = 25
    block_prefix_length: int = 24


def load_config(path: str | Path | None = None) -> LabConfig:
    config_path = Path(path) if path else Path(__file__).resolve().parents[2] / "config.yaml"
    with open(config_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    project = raw.get("project", {})
    controller = raw.get("controller", {})
    lab = raw.get("lab", {})
    detection = raw.get("detection", {})
    mitigation = raw.get("mitigation", {})

    return LabConfig(
        project_name=project.get("name", LabConfig.project_name),
        lab_network=project.get("lab_network", LabConfig.lab_network),
        controller_ip=controller.get("ip", LabConfig.controller_ip),
        controller_port=int(controller.get("port", LabConfig.controller_port)),
        stats_interval_seconds=float(controller.get("stats_interval_seconds", LabConfig.stats_interval_seconds)),
        server_ip=lab.get("server_ip", LabConfig.server_ip),
        attacker_ip=lab.get("attacker_ip", LabConfig.attacker_ip),
        client_ip=lab.get("client_ip", LabConfig.client_ip),
        attacker_ports=[int(port) for port in lab.get("attacker_ports", [80, 443, 8080])],
        normal_rate_per_second=int(lab.get("normal_rate_per_second", LabConfig.normal_rate_per_second)),
        attack_levels=lab.get("attack_levels", {}),
        detection=detection,
        rule_ttl_seconds=int(mitigation.get("rule_ttl_seconds", LabConfig.rule_ttl_seconds)),
        rate_limit_pps=int(mitigation.get("rate_limit_pps", LabConfig.rate_limit_pps)),
        block_prefix_length=int(mitigation.get("block_prefix_length", LabConfig.block_prefix_length)),
    )
