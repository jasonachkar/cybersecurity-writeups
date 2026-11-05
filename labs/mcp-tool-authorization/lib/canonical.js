"use strict";

const crypto = require("node:crypto");

/** JSON with sorted keys and no insignificant whitespace, so equal values hash equally. */
function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
}

const sha256 = (text) => crypto.createHash("sha256").update(text, "utf8").digest("hex");
const hashJson = (value) => sha256(canonical(value));

module.exports = { canonical, hashJson, sha256 };
