#!/usr/bin/env python3
"""Count bounded lab-test UDP datagrams received by the configured Mininet h3."""
from __future__ import annotations

import argparse
from collections import Counter
import json
import socket
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from sdn_ddos.config import load_config


def main() -> int:
    config = load_config(PROJECT_ROOT / "config.yaml")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, default=15)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    if not 1 <= args.duration <= 60:
        parser.error("Duration must be between 1 and 60 seconds.")
    if args.port not in config.attacker_ports:
        parser.error("Port is not in the configured lab service allowlist.")

    received = 0
    received_bytes = 0
    sources: Counter[str] = Counter()
    started = time.monotonic()
    deadline = started + args.duration
    next_report = started + 1.0

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((config.server_ip, args.port))
        listener.settimeout(0.25)
        print(
            f"UDP sink listening on {config.server_ip}:{args.port} "
            f"for {args.duration}s; counting test packets from {config.attacker_ip}",
            flush=True,
        )
        while time.monotonic() < deadline:
            try:
                payload, address = listener.recvfrom(65535)
            except socket.timeout:
                continue

            source_ip = address[0]
            if source_ip == config.attacker_ip and payload.startswith(b"SDN-LAB-TEST"):
                received += 1
                received_bytes += len(payload)
                sources[source_ip] += 1

            now = time.monotonic()
            if now >= next_report:
                print(
                    json.dumps({
                        "elapsed_seconds": round(now - started, 2),
                        "received_datagrams": received,
                        "received_bytes": received_bytes,
                        "sources": dict(sources),
                    }),
                    flush=True,
                )
                next_report = now + 1.0

    print(json.dumps({
        "result": "complete",
        "bind_ip": config.server_ip,
        "port": args.port,
        "duration_seconds": round(time.monotonic() - started, 2),
        "received_datagrams": received,
        "received_bytes": received_bytes,
        "sources": dict(sources),
    }, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
