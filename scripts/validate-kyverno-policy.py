"""Validate the lab image policy against the pinned Kyverno v1.18.2 CRD structural schema.

Usage: python scripts/validate-kyverno-policy.py <crd.yaml> <policy.yaml>

This is offline schema validation only. It does not execute signature,
certificate, registry, transparency-log, or admission verification.
"""
import sys

import jsonschema
import yaml

crd_path, policy_path = sys.argv[1], sys.argv[2]

with open(crd_path, encoding="utf-8") as handle:
    crd = yaml.safe_load(handle)
with open(policy_path, encoding="utf-8") as handle:
    policy = yaml.safe_load(handle)

names = crd["spec"]["names"]
group = crd["spec"]["group"]
versions = {v["name"]: v for v in crd["spec"]["versions"]}

api_group, _, api_version = policy["apiVersion"].partition("/")
assert api_group == group, f"group mismatch: {api_group} != {group}"
assert policy["kind"] == names["kind"], f"kind mismatch: {policy['kind']} != {names['kind']}"
assert api_version in versions, f"version {api_version} not served by CRD"

schema = versions[api_version]["schema"]["openAPIV3Schema"]
jsonschema.validate(instance=policy, schema=schema)

print(
    f"PASS: {policy_path} conforms to {names['kind']} ({policy['apiVersion']}) "
    f"structural schema from the pinned Kyverno v1.18.2 CRD."
)
print("NOTE: schema validation only; no signature, registry, transparency, or admission test was run.")
