"""Validate the published Tetragon policy against the pinned v1.7.0 CRD structural schema.

Usage: python scripts/validate-tetragon-policy.py <crd.yaml> <policy.yaml>

Kubernetes CRD structural schemas are a restricted subset of JSON Schema, so a
JSON Schema validator gives a faithful offline schema check. This is schema
validation only; it is not a live admission or enforcement test.
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
assert crd["spec"]["scope"] == "Namespaced", "expected a namespaced CRD"

schema = versions[api_version]["schema"]["openAPIV3Schema"]
jsonschema.validate(instance=policy, schema=schema)

print(
    f"PASS: {policy_path} conforms to {names['kind']} ({policy['apiVersion']}) "
    f"structural schema from the pinned Tetragon v1.7.0 CRD."
)
print("NOTE: schema validation only; no live cluster enforcement test was run.")
