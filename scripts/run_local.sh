#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -f config.json ]]; then
  echo "config.json missing. running seed.py..."
  python seed.py
fi

mkdir -p logs

PIDS=()

start_node() {
  local node_id="$1"
  python -m node.server --node-id "$node_id" > "logs/${node_id}.log" 2>&1 &
  local pid=$!
  PIDS+=("$pid")
  echo "started $node_id (pid $pid)"
}

start_gateway() {
  python -m gateway.server > "logs/gateway.log" 2>&1 &
  local pid=$!
  PIDS+=("$pid")
  echo "started gateway (pid $pid)"
}

cleanup() {
  echo ""
  echo "shutting down..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  echo "stopped."
}
trap cleanup EXIT INT TERM

start_node companyA
start_node companyB
start_node companyC
sleep 1
start_gateway

echo ""
echo "all services running:"
echo "  gateway    http://127.0.0.1:9000"
echo "  companyA   http://127.0.0.1:8001"
echo "  companyB   http://127.0.0.1:8002"
echo "  companyC   http://127.0.0.1:8003"
echo ""
echo "ctrl+c to stop. logs in ./logs/"

wait
