#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/terraform"
terraform init -backend=false -input=false
terraform fmt -check
terraform validate
terraform test
