#!/usr/bin/env bash
# Real local services and native policy engines only. Never deploys cloud resources.
set -euo pipefail
cd "$(dirname "$0")/.."
ssrf=(docker compose -p research-ssrf -f vulnerability-research/mcp-tool-ssrf/lab/compose.yaml)
bola=(docker compose -p research-bola -f vulnerability-research/api-bola-multi-tenant/lab/compose.yaml)
cleanup() {
  "${ssrf[@]}" down --volumes --remove-orphans
  "${bola[@]}" down --volumes --remove-orphans
}
trap cleanup EXIT
"${ssrf[@]}" config --quiet
"${bola[@]}" config --quiet
"${ssrf[@]}" up -d --build vulnerable secure gateway public metadata
"${ssrf[@]}" run --build --rm tests
"${ssrf[@]}" exec -T secure python test_egress.py
"${bola[@]}" run --build --rm lab
sh labs/postgresql-rls/run-tests.sh
bash labs/iac-policy/validate-opa.sh
bash labs/kubernetes-security/validate-kyverno.sh
bash labs/kubernetes-security/validate-rego.sh
bash scripts/validate-terraform.sh
