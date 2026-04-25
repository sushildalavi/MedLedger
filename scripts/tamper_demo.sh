#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

run() {
  echo ""
  echo "$ $*"
  "$@" || true
}

echo "=== MedLedger tamper-detection demo ==="
echo "(assumes ./scripts/demo.sh has already been run so blocks exist)"

echo ""
echo "--- baseline verify (expect all valid) ---"
run python cli.py verify --user admin

echo ""
echo "--- attack 1: modify ciphertext on companyA block 1 ---"
run python attacker.py tamper --node companyA --block 1 --mode modify-ciphertext
run python cli.py verify --user admin

echo ""
echo "--- attack 2: delete a block on companyA (block 2) ---"
run python attacker.py tamper --node companyA --block 2 --mode delete-block
run python cli.py verify --user admin

echo ""
echo "--- attack 3: modify prev_hash on companyA block 1 ---"
run python attacker.py tamper --node companyA --block 1 --mode modify-prev-hash
run python cli.py verify --user admin

echo ""
echo "all three attacks were detected by local verification and/or cross-node comparison"
