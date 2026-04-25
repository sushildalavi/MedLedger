#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

GATEWAY="http://127.0.0.1:9000"

run() {
  echo ""
  echo "$ $*"
  "$@"
}

echo "=== MedLedger end-to-end demo ==="
echo ""

run python cli.py login --user doctor_01

echo ""
echo "--- generating audit events for all 6 action types ---"
for action in create query change print copy delete; do
  run python cli.py access --user doctor_01 --patient patient_01 --action "$action"
done
run python cli.py access --user doctor_02 --patient patient_02 --action change
run python cli.py access --user doctor_03 --patient patient_03 --action print

echo ""
echo "--- inspecting on-disk encrypted storage (companyA) ---"
echo "$ head -2 data/companyA/chain.jsonl"
head -2 data/companyA/chain.jsonl
echo ""

echo ""
echo "--- patient_01 querying own audit log (allowed) ---"
run python cli.py query --user patient_01 --patient patient_01

echo ""
echo "--- patient_01 querying patient_02 (must be denied with 403) ---"
run python cli.py query --user patient_01 --patient patient_02 || true

echo ""
echo "--- audit_company_A querying all patients (allowed) ---"
run python cli.py query-all --user audit_company_A

echo ""
echo "--- system verification (clean state, expect all valid) ---"
run python cli.py verify --user admin
