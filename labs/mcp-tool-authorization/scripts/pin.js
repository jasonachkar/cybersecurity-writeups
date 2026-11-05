#!/usr/bin/env node
"use strict";
// Compare (or with --write, update) the policy's pinned descriptor hashes against the
// benign mock server. In production this is a reviewed change: read the descriptor diff
// (description text, schema) before accepting a new pin.
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const readline = require("node:readline");
const { hashJson } = require("../lib/canonical");

const policyPath = path.join(__dirname, "..", "policy.json");
const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
const child = spawn(process.execPath, [path.join(__dirname, "..", "mock-server.js")], { stdio: ["pipe", "pipe", "inherit"], env: { ...process.env, MOCK_MODE: "normal" } });
const rl = readline.createInterface({ input: child.stdout });
rl.on("line", (line) => {
  const message = JSON.parse(line);
  if (message.id !== 2) return;
  let drift = 0;
  for (const tool of message.result.tools) {
    const hash = hashJson(tool);
    const entry = policy.tools[tool.name];
    if (!entry) { console.log(`unreviewed tool ${tool.name}: ${hash}`); drift += 1; continue; }
    if (entry.pinnedHash !== hash) { drift += 1; console.log(`${tool.name}: pin ${entry.pinnedHash.slice(0, 12)} -> ${hash.slice(0, 12)}`); entry.pinnedHash = hash; }
  }
  if (process.argv.includes("--write")) fs.writeFileSync(policyPath, `${JSON.stringify(policy, null, 2)}\n`);
  console.log(drift ? (process.argv.includes("--write") ? "pins updated" : "PINS DRIFTED") : "all pins match");
  child.kill();
  process.exitCode = drift && !process.argv.includes("--write") ? 1 : 0;
});
child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} })}\n`);
child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" })}\n`);
