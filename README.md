# Intelligent DDoS Detection and Mitigation in SDN

This project implements a modular academic prototype for detecting controlled SYN-flood and UDP-flood traffic in a Software-Defined Networking (SDN) lab. It combines:

- fixed threshold detection,
- Shannon entropy analysis,
- a Random Forest classifier,
- a mitigation manager that models temporary blocking and rate limiting.

The implementation is designed to run in a Linux/WSL environment with Mininet, Open vSwitch and OS-Ken (a maintained Ryu-compatible controller), while remaining testable in a pure Python environment when a full SDN lab is unavailable.

## Repository structure

- `config.yaml` – project parameters and thresholds
- `requirements.txt` – Python dependencies
- `setup_env.sh` – Ubuntu/Linux setup script
- `src/sdn_ddos` – prototype implementation
- `tests/` – validation tests

## Supported lab environment

Recommended environment:

- Ubuntu 22.04 or 24.04 in WSL2
- Mininet
- Open vSwitch
- OS-Ken controller (`python3-os-ken`), compatible with the Ryu application API
- Python 3.10+

## Quick start

1. Install WSL 2 and Ubuntu if needed:

   ```powershell
   wsl --install -d Ubuntu
   ```

2. In the Ubuntu shell, install the SDN packages:

   ```bash
   sudo apt update
   sudo apt install -y mininet openvswitch-switch python3-os-ken python3-pip python3-venv
   ```

3. From the project directory in WSL (usually under `/mnt/c/...`), prepare Python dependencies:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install -r requirements.txt
   python -m pip install -e .
   python -m sdn_ddos.cli --demo --output data/demo_output.json
   ```

4. Start the controller from the project directory in one Ubuntu terminal:

   ```bash
   bash scripts/run_ryu_controller.sh
   ```

5. In a second Ubuntu terminal, start the Mininet lab:

   ```bash
   sudo service openvswitch-switch start
   sudo mn -c
   sudo mn --controller=remote,ip=127.0.0.1,port=6633 --topo single,3 --switch ovsk --protocols=OpenFlow13 --mac
   ```

   At the `mininet>` prompt, run `pingall`, then `exit` to stop the lab.

## Controlled lab traffic test

Only run the traffic generator from Mininet host `h2`. It rejects any source or
destination other than the configured attacker `10.0.0.2` and server `10.0.0.3`,
restricts duration to 20 seconds maximum, and caps UDP at 100 packets/second and
TCP connection attempts at 40/second. These are bounded detector-validation
loads, not a high-volume stress test.

At the Mininet prompt, send a bounded UDP sample:

```text
h2 python3 /mnt/c/Users/Shanmukha/Desktop/cn_project/scripts/lab_traffic.py --type udp --duration 10 --pps 100 --port 8080
```

For bounded TCP connection attempts that emit SYN packets, first start the
protected server on `h3`, then run:

```text
h3 python3 -m http.server 8080 --directory /tmp >/tmp/h3-http.log 2>&1 &
h2 python3 /mnt/c/Users/Shanmukha/Desktop/cn_project/scripts/lab_traffic.py --type syn --duration 10 --pps 30 --port 8080
```

The SYN mode completes/tears down TCP connections when the server accepts them;
it is not a half-open SYN flood. Each run appends actual sent counts, timestamps,
configuration and ground-truth label to `data/experiment_log.jsonl`. Check the
OS-Ken terminal for detector decisions and mitigation logs; don't treat synthetic
or modeled output as live experiment measurements.

## Implementation notes

- All attack traffic remains within an isolated lab network; this project never targets public IPs or third-party systems.
- The entropy detector is explicitly conservative: its logic compares the current traffic entropy to a configured baseline and documents entropy as a directional feature with known caveats.
- The Random Forest model is trained on labelled synthetic traffic and should be replaced with real captured Mininet flow features in a controlled lab evaluation.
- The controller app accepts OS-Ken or Ryu imports. OS-Ken and Ryu system packages should be run with their system manager executable, not from the project virtual environment.
- The controller polls OpenFlow port and flow counters every configured interval. Packet and byte rates are computed from ingress-port counter deltas (excluding the OpenFlow local port). Flow creation rate is computed from complete multipart flow-stat snapshots over the elapsed time between snapshots; it counts new switch flow entries, not unique TCP connections. Source/protocol distributions use per-flow packet-counter deltas, including packets already present when a flow is first observed. TCP SYNs are counted when observed as controller Packet-In events; this is flow-start instrumentation, not a full packet capture.
- Select a detector with `detection.selected` in `config.yaml`: `threshold`, `entropy`, or `random_forest`. The default is `threshold`.
- Threshold-based SYN/UDP ratio checks are only considered when packet rate reaches `detection.threshold.minimum_packet_rate_for_ratio` (20 packets/second by default), preventing a small sample that is entirely one protocol from triggering a block by itself.
- Current mitigation is a temporary, source-IP-specific drop rule with a timeout. It is only applied to suspicious sources inside the configured lab CIDR and excludes the configured client and protected server.

## Lab topology

The prototype assumes the following topology:

- `h1` – legitimate client
- `h2` – attack generator
- `h3` – protected server
- `s1` – Open vSwitch
- controller – Ryu

A simple Mininet command set is included in the documentation for lab setup:

```bash
sudo mn --controller=remote,ip=127.0.0.1,port=6633 --topo single,3 --switch ovsk --mac
```

## Validation

This repository uses pytest for unit-level validation and example-driven synthetic evaluation. Run:

```bash
pytest -q
```

## Limitations

- The current environment may not support full Mininet networking on native Windows.
- Actual controller-to-switch verification and live rate limiting require a Linux-based lab or WSL2 environment with appropriate privileges.
- Synthetic data is valid for pipeline validation but must be replaced by real measurements for final academic evaluation.
