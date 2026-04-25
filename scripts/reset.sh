#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

rm -f data/companyA/chain.jsonl data/companyB/chain.jsonl data/companyC/chain.jsonl
rm -f .medledger_token.json
rm -f config.json
rm -f keys/*.pem keys/*.pub 2>/dev/null || true

echo "reset complete (removed chains, tokens, config, keys)"
