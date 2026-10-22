#!/usr/bin/env bash
set -euo pipefail

if ! command -v mn >/dev/null 2>&1; then
  echo "Mininet is not installed. Run ./setup_env.sh on Ubuntu/WSL first."
  exit 1
fi

sudo mn --controller=remote,ip=127.0.0.1,port=6633 --topo single,3 --switch ovsk --mac --nat
