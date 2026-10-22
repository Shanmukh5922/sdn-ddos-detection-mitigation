#!/usr/bin/env bash
set -euo pipefail

if [[ "$OSTYPE" != linux-gnu* ]]; then
  echo "This setup script targets Ubuntu/Linux. On Windows, use WSL 2 with Ubuntu installed first."
  exit 1
fi

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3 python3-pip python3-venv build-essential git curl \
  mininet openvswitch-switch python3-os-ken

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .

echo "Environment is ready. Activate with: source .venv/bin/activate"
