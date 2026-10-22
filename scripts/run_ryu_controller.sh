#!/usr/bin/env bash
set -euo pipefail

if command -v osken-manager >/dev/null 2>&1; then
  export PYTHONPATH="$PWD/src${PYTHONPATH:+:$PYTHONPATH}"
  exec osken-manager sdn_ddos.ryu_app
elif command -v ryu-manager >/dev/null 2>&1; then
  export PYTHONPATH="$PWD/src${PYTHONPATH:+:$PYTHONPATH}"
  exec ryu-manager sdn_ddos.ryu_app
else
  echo "Neither OS-Ken nor Ryu is installed. On Ubuntu, install OS-Ken with:"
  echo "  sudo apt install python3-os-ken"
  exit 1
fi
