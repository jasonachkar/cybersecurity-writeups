"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const lab = path.resolve(__dirname, "..");
const read = (relative) => fs.readFileSync(path.join(lab, relative), "utf8");
const readJson = (relative) => JSON.parse(read(relative));

const secure = readJson("fixtures/secure_plan.json");
const insecure = readJson("fixtures/insecure_plan.json");
const unknown = readJson("fixtures/unknown_plan.json");
const deleted = readJson("fixtures/deleted_control_plan.json");

for (const [name, plan] of Object.entries({ secure, insecure, unknown, deleted })) {
  assert.equal(plan.format_version, "1.2", `${name}: unexpected plan format`);
  assert.ok(Array.isArray(plan.resource_changes), `${name}: resource_changes missing`);
}

const insecureTypes = new Set(insecure.resource_changes.map((item) => item.type));
assert.ok(insecureTypes.has("aws_s3_bucket_acl"));
assert.ok(insecureTypes.has("aws_security_group"));
assert.ok(insecureTypes.has("aws_db_instance"));
assert.match(
  insecure.resource_changes.find((item) => item.type === "aws_iam_policy").change.after.policy,
  /"Action":"\*","Resource":"\*"/,
);

const unknownDatabase = unknown.resource_changes[0];
assert.equal(unknownDatabase.change.after_unknown.publicly_accessible, true);
assert.equal(unknownDatabase.change.after_unknown.storage_encrypted, true);
assert.deepEqual(deleted.resource_changes[0].change.actions, ["delete"]);

const insecureBackend = read("terraform/insecure/backend.tf");
assert.match(insecureBackend, /dynamodb_table\s*=/);
assert.match(insecureBackend, /encrypt\s*=\s*false/);
assert.doesNotMatch(insecureBackend, /use_lockfile\s*=\s*true/);

const hardenedBackend = read("terraform/hardened/backend.tf");
assert.match(hardenedBackend, /use_lockfile\s*=\s*true/);
assert.match(hardenedBackend, /encrypt\s*=\s*true/);
assert.match(hardenedBackend, /kms_key_id\s*=/);
assert.doesNotMatch(hardenedBackend, /dynamodb_table\s*=/);

const policy = read("policy/terraform.rego");
for (const requiredReason of [
  "public ACL",
  "public-access block",
  "server-side encryption",
  "access logging",
  "public internet",
  "publicly accessible",
  "wildcard action and resource",
  "unknown at policy evaluation",
  "deletes a modeled security control",
]) {
  assert.match(policy, new RegExp(requiredReason.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
}

console.log("PASS: Terraform backend and plan-policy structural fixtures completed.");
