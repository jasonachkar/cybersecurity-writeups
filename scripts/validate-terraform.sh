#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
terraform fmt -check -recursive .
for directory in \
  labs/iac-policy/terraform/insecure \
  labs/iac-policy/terraform/hardened \
  docs/tutorials/azure-firewall-walkthrough; do
  terraform -chdir="$directory" init -backend=false -input=false
  terraform -chdir="$directory" validate
done
terraform -chdir=docs/tutorials/azure-firewall-walkthrough test
bash labs/azure-landing-zone/validate.sh
bash vulnerability-research/cicd-identity-escalation/lab/validate.sh
