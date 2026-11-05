#!/usr/bin/env bash
# Delete the lab cluster. Safe to run when it does not exist.
set -euo pipefail
kind delete cluster --name "${LAB_CLUSTER:-k8s-sec-lab}"
