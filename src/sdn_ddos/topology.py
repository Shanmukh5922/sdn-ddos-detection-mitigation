from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class MininetTopology:
    controller_ip: str = "127.0.0.1"
    controller_port: int = 6633
    switch_name: str = "s1"
    hosts: Dict[str, str] = field(default_factory=lambda: {"h1": "10.0.0.1", "h2": "10.0.0.2", "h3": "10.0.0.3"})

    def as_dict(self) -> dict[str, Any]:
        return {
            "controller": {"ip": self.controller_ip, "port": self.controller_port},
            "switch": self.switch_name,
            "hosts": self.hosts,
        }


def build_topology(*, controller_ip: str = "127.0.0.1", controller_port: int = 6633, switch_name: str = "s1") -> MininetTopology:
    return MininetTopology(controller_ip=controller_ip, controller_port=controller_port, switch_name=switch_name)


def sanity_check_topology(topology: MininetTopology) -> dict[str, Any]:
    required_hosts = {"h1", "h2", "h3"}
    missing = sorted(required_hosts.difference(topology.hosts.keys()))
    return {
        "valid": not missing,
        "missing_hosts": missing,
        "hosts": topology.hosts,
    }
