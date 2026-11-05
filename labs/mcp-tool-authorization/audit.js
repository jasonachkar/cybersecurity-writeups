"use strict";

const { canonical, sha256 } = require("./lib/canonical");

/**
 * Append-only, hash-chained audit log.
 *
 * Each record carries the hash of the previous one, so editing, deleting or reordering a record
 * in the MIDDLE of the log breaks verification. Truncating the TAIL does not: a prefix of a valid
 * chain is a valid chain. Detecting that needs an external anchor (the latest hash written
 * somewhere an attacker with log access cannot also rewrite). verify() says so by returning the head
 * hash; this module does not provide the anchor.
 *
 * append() throws when the sink fails. Callers decide whether that is fatal; the gateway treats it as fatal
 * before any tool executes (fail closed).
 */
class AuditLog {
  #sink;
  #seq = 0;
  #prev = "0".repeat(64);
  #now;

  constructor({ sink = null, now = () => Date.now() } = {}) {
    this.lines = [];
    this.#sink = sink || ((line) => { this.lines.push(line); });
    this.#now = now;
  }

  append(fields) {
    const record = { ...fields, seq: this.#seq + 1, ts: new Date(this.#now()).toISOString(), prev: this.#prev };
    const hash = sha256(canonical(record));
    const line = JSON.stringify({ ...record, hash });
    this.#sink(line); // may throw: sequence and head only advance after the sink accepted the line
    this.#seq += 1;
    this.#prev = hash;
    return { seq: record.seq, hash };
  }

  get head() { return this.#prev; }
}

/** Verify a list of JSON lines. Returns { ok, error, head, records }. */
function verifyChain(lines) {
  let prev = "0".repeat(64);
  const records = [];
  for (let i = 0; i < lines.length; i += 1) {
    let record;
    try { record = JSON.parse(lines[i]); } catch { return { ok: false, error: `line ${i + 1}: not JSON`, head: prev, records }; }
    const { hash, ...rest } = record;
    if (record.seq !== i + 1) return { ok: false, error: `line ${i + 1}: sequence ${record.seq}`, head: prev, records };
    if (record.prev !== prev) return { ok: false, error: `line ${i + 1}: previous-hash mismatch`, head: prev, records };
    if (sha256(canonical(rest)) !== hash) return { ok: false, error: `line ${i + 1}: record altered`, head: prev, records };
    prev = hash;
    records.push(record);
  }
  return { ok: true, error: null, head: prev, records };
}

module.exports = { AuditLog, verifyChain };
