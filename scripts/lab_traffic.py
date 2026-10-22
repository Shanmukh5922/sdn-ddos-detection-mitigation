#!/usr/bin/env python3
"""Generate bounded traffic from Mininet h2 to the configured Mininet h3 only."""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from sdn_ddos.config import load_config
from sdn_ddos.traffic import validate_lab_traffic


def main() -> int:
    config = load_config(PROJECT_ROOT / "config.yaml")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--type", choices=("syn", "udp"), required=True)
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--pps", type=int, default=20)
    parser.add_argument("--target", default=config.server_ip)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    if args.port not in config.attacker_ports:
        parser.error("Port is not in the configured lab service allowlist.")

    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect((args.target, args.port))
        source_ip = probe.getsockname()[0]
        probe.close()
        validate_lab_traffic(
            target_ip=args.target,
            configured_server_ip=config.server_ip,
            source_ip=source_ip,
            configured_attacker_ip=config.attacker_ip,
            duration_seconds=args.duration,
            intensity=args.pps,
            attack_type=args.type,
        )
    except (OSError, ValueError) as exc:
        parser.error(f"Lab safety check failed: {exc}")

    start_wall = datetime.now(timezone.utc)
    stop_at = time.monotonic() + args.duration
    sent = 0
    period = 1.0 / args.pps
    next_send = time.monotonic()
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if args.type == "udp" else None
    tcp_timeout = min(period * 0.8, 0.05)

    try:
        while time.monotonic() < stop_at:
            if args.type == "udp":
                assert udp_socket is not None
                udp_socket.sendto(b"SDN-LAB-TEST" + bytes(116), (args.target, args.port))
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                    client.settimeout(tcp_timeout)
                    try:
                        client.connect((args.target, args.port))
                    except (ConnectionRefusedError, TimeoutError, socket.timeout):
                        pass
            sent += 1
            next_send += period
            sleep_for = next_send - time.monotonic()
            if sleep_for > 0:
                time.sleep(min(sleep_for, max(0, stop_at - time.monotonic())))
    finally:
        if udp_socket is not None:
            udp_socket.close()

    end_wall = datetime.now(timezone.utc)
    experiment = {
        "attack_type": args.type,
        "description": "bounded TCP connection attempts (SYN-bearing) to the lab server" if args.type == "syn" else "bounded UDP datagrams to the lab server",
        "target_ip": args.target,
        "source_ip": source_ip,
        "target_port": args.port,
        "requested_pps": args.pps,
        "sent_packets_or_attempts": sent,
        "duration_seconds": args.duration,
        "start_time": start_wall.isoformat(),
        "end_time": end_wall.isoformat(),
        "ground_truth_label": 1,
        "traffic_scope": "configured Mininet h2 to h3 only",
    }
    log_path = PROJECT_ROOT / "data" / "experiment_log.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(experiment) + "\n")
    print(json.dumps(experiment, indent=2))
    print(f"Experiment record appended to {log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
