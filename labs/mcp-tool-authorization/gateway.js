"use strict";

/**
 * Policy gateway between an agent runtime and an MCP-style tool server.
 *
 * It is the single enforcement point: the model proposes, the gateway decides, and the
 * upstream server only ever sees a call that passed every check. It is written so that its
 * decisions hold even if the model is fully compromised (see agent-sim.js, which is that
 * worst case on purpose).
 *
 * Order of checks - cheap and structural first, effects last:
 *   context -> allowlist -> advertised and pinned -> schema -> resource validity -> authority
 *   (user AND agent) -> destination allowlist -> rate limit -> risk gating (allow / approval / deny)
 *   -> approval verification -> audit the decision -> execute with a timeout -> validate output
 *   -> taint the session -> audit the outcome.
 *
 * Every result carries a stable reason code. No path through this file executes an upstream
 * call without first writing an "allow" decision to the audit log (fail closed if that write fails).
 *
 * This is a teaching model. It validates a lab context object; it does not authenticate users or
 * agents, verify tokens, or protect the approval surface from a compromised runtime process.
 */

const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const readline = require("node:readline");
const { hashJson } = require("./lib/canonical");
const { validate } = require("./lib/schema");
const { ResourceError, allows, emailDomain, validatePath } = require("./lib/scope");

const RISKS = new Set(["read", "write_internal", "egress", "destructive"]);
// eslint-disable-next-line no-control-regex
const BAD_CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const INJECTION_HINT = /(ignore (all |any |the )?(previous|prior) instructions|system note to assistant|\bCALL\s+\w+\s*\{)/i;

class Deny extends Error {
  constructor(reason, detail = "") {
    super(`${reason}${detail ? `: ${detail}` : ""}`);
    this.reason = reason;
    this.detail = detail;
  }
}

function isRecord(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }

function validatePolicy(policy) {
  const bad = (m) => { throw new Deny("POLICY_INVALID", m); };
  if (!isRecord(policy) || typeof policy.version !== "string" || !isRecord(policy.tools)) bad("missing version or tools");
  for (const [name, t] of Object.entries(policy.tools)) {
    if (!RISKS.has(t.risk)) bad(`${name}: unknown risk class ${JSON.stringify(t.risk)}`);
    if (!/^[0-9a-f]{64}$/.test(t.pinnedHash || "")) bad(`${name}: pinnedHash must be a SHA-256`);
    if (!t.capability || !t.verb) bad(`${name}: capability and verb required`);
    if (t.resourceKind && !["path", "email_domain", "none"].includes(t.resourceKind)) bad(`${name}: unknown resourceKind`);
    if (t.resourceKind && t.resourceKind !== "none" && !t.resourceArg) bad(`${name}: resourceArg required`);
  }
  if (!Array.isArray(policy.approvers)) bad("approvers must be a list of human principal ids");
  if (!isRecord(policy.output) || !Number.isInteger(policy.output.maxBytes)) bad("output.maxBytes required");
  if (!isRecord(policy.egress) || !Array.isArray(policy.egress.allowedRecipientDomains)) bad("egress.allowedRecipientDomains required");
  return policy;
}

/** Minimal newline-delimited JSON-RPC 2.0 client over a child process's stdio. */
class StdioClient {
  constructor(command, args, env, timeoutMs, onNotification, onStderrLine) {
    this.timeoutMs = timeoutMs;
    this.pending = new Map();
    this.nextId = 1;
    this.closed = false;
    this.child = spawn(command, args, { stdio: ["pipe", "pipe", onStderrLine ? "pipe" : "ignore"], env: { ...process.env, ...env } });
    this.observesStderr = Boolean(onStderrLine);
    this.barriers = new Map();
    this.barrierSeq = 0;
    this.stderrClosed = Promise.resolve();
    if (onStderrLine) {
      const stderrLines = readline.createInterface({ input: this.child.stderr });
      this.stderrClosed = new Promise((resolve) => stderrLines.on("close", resolve));
      stderrLines.on("line", (line) => {
        if (line.startsWith("BARRIER ")) {
          const release = this.barriers.get(line.slice(8));
          if (release) { this.barriers.delete(line.slice(8)); release(); }
          return;
        }
        onStderrLine(line);
      });
    }
    this.child.on("exit", () => {
      this.closed = true;
      for (const { reject, timer } of this.pending.values()) { clearTimeout(timer); reject(new Deny("UPSTREAM_FAILURE", "server exited")); }
      this.pending.clear();
    });
    this.child.stdin.on("error", () => {});
    readline.createInterface({ input: this.child.stdout }).on("line", (line) => {
      let message;
      try { message = JSON.parse(line); } catch { return; }
      if (message.id !== undefined && this.pending.has(message.id)) {
        const { resolve, reject, timer } = this.pending.get(message.id);
        clearTimeout(timer);
        this.pending.delete(message.id);
        if (message.error) reject(new Deny("UPSTREAM_FAILURE", message.error.message));
        else resolve(message.result);
      } else if (message.method && onNotification) onNotification(message.method);
    });
  }

  request(method, params) {
    if (this.closed) return Promise.reject(new Deny("UPSTREAM_FAILURE", "server not running"));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Deny("UPSTREAM_TIMEOUT", `${method} exceeded ${this.timeoutMs} ms`)); }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  }

  notify(method, params) { this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`); }
  stop() { this.child.kill(); }

  /**
   * Test seam. Resolves once every stderr line the upstream wrote before this call has been delivered
   * to the stderr observer. Responses (stdout) and side-effect reports (stderr) are separate pipes with
   * no ordering guarantee between them, so "the response arrived" does not mean "its effect line has".
   * A positive assertion would flake; worse, a negative one ("nothing happened") would pass vacuously.
   * The barrier is a marker on the single ordered stderr pipe, so it is a proof, not a delay.
   */
  async barrier(timeoutMs = this.timeoutMs) {
    if (!this.observesStderr) return;
    if (this.closed) return this.stderrClosed;
    const token = `b${this.barrierSeq++}`;
    const seen = new Promise((resolve) => this.barriers.set(token, resolve));
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: `barrier-${token}`, method: "lab/barrier", params: { token } })}\n`);
    let timer;
    const expired = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`stderr barrier not observed within ${timeoutMs} ms`)), timeoutMs); });
    try { await Promise.race([seen, this.stderrClosed, expired]); } finally { clearTimeout(timer); this.barriers.delete(token); }
  }
}

class Gateway {
  #policy; #audit; #now; #client = null; #descriptors = new Map(); #status = new Map();
  #approvals = new Map(); #calls = new Map(); #command; #args; #env; #timeoutMs; #onStderr;

  constructor({ policy, audit, command = process.execPath, args = [], env = {}, now = () => Date.now(), timeoutMs = 1500, onUpstreamStderr = null }) {
    this.#policy = validatePolicy(policy);
    this.#audit = audit;
    this.#command = command; this.#args = args; this.#env = env; this.#now = now; this.#timeoutMs = timeoutMs; this.#onStderr = onUpstreamStderr;
  }

  get toolStatus() { return Object.fromEntries(this.#status); }

  async start() {
    this.#client = new StdioClient(this.#command, this.#args, this.#env, this.#timeoutMs, (method) => {
      if (method === "notifications/tools/list_changed") this.#refresh().catch(() => {});
    }, this.#onStderr);
    await this.#client.request("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "gateway", version: "0.0.1" } });
    this.#client.notify("notifications/initialized");
    await this.#refresh();
  }

  stop() { if (this.#client) this.#client.stop(); }

  /** Test seam, not reachable from an agent: see StdioClient.barrier. A no-op unless a stderr observer is configured. */
  upstreamStderrBarrier() { return this.#client ? this.#client.barrier() : Promise.resolve(); }

  /** Re-read tools/list and compare each descriptor with its pin. Unreviewed or changed tools are not callable. */
  async #refresh() {
    const { tools } = await this.#client.request("tools/list", {});
    this.#descriptors.clear(); this.#status.clear();
    for (const tool of tools) {
      const pinned = this.#policy.tools[tool.name];
      if (!pinned) this.#status.set(tool.name, "unreviewed");
      else if (hashJson(tool) !== pinned.pinnedHash) this.#status.set(tool.name, "drifted");
      else { this.#status.set(tool.name, "ok"); this.#descriptors.set(tool.name, tool); }
    }
    for (const name of Object.keys(this.#policy.tools)) if (!this.#status.has(name)) this.#status.set(name, "not advertised");
    this.#log({ event: "tools_refreshed", status: this.toolStatus });
  }

  /** What the model is shown: only pinned tools the user AND agent could ever use. Hiding is hygiene, not enforcement. */
  visibleTools(ctx) {
    const out = [];
    for (const [name, tool] of this.#descriptors) {
      const entry = this.#policy.tools[name];
      const mayUse = (scopes) => scopes.some((s) => s.startsWith(`${entry.capability}:${entry.verb}:`));
      if (isRecord(ctx) && ctx.user && ctx.agent && mayUse(ctx.user.scopes || []) && mayUse(ctx.agent.scopes || [])) {
        out.push({ name, description: tool.description, inputSchema: tool.inputSchema });
      }
    }
    return out;
  }

  #log(fields) {
    return this.#audit.append({ policyVersion: this.#policy.version, ...fields });
  }

  #validateContext(ctx) {
    const ok = isRecord(ctx) && isRecord(ctx.user) && isRecord(ctx.agent) && isRecord(ctx.session)
      && typeof ctx.user.id === "string" && ctx.user.id && typeof ctx.user.tenant === "string" && Array.isArray(ctx.user.scopes)
      && typeof ctx.agent.id === "string" && ctx.agent.id && Array.isArray(ctx.agent.scopes)
      && typeof ctx.session.id === "string" && typeof ctx.session.tainted === "boolean";
    if (!ok) throw new Deny("INVALID_CONTEXT", "user, agent and session identity are required and are never taken from the model");
  }

  static #redact(args, redactKeys) {
    const preview = {};
    for (const [k, v] of Object.entries(isRecord(args) ? args : {})) {
      if (typeof v === "string") preview[k] = redactKeys.includes(k) ? `<redacted ${v.length} chars>` : v.slice(0, 60);
      else preview[k] = `<${Array.isArray(v) ? "array" : typeof v}>`;
    }
    return preview;
  }

  #summary(tool, args) {
    const clean = (s) => String(s).replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 80);
    if (tool === "send_email") return `Send email to ${clean(args.to)}, subject "${clean(args.subject)}", body ${String(args.body).length} characters`;
    return `${tool} ${JSON.stringify(Gateway.#redact(args, this.#policy.redactKeys || []))}`;
  }

  /** Decide and, if allowed, execute. Never throws for a denial; returns a structured outcome. */
  async callTool(ctx, name, args, { approvalId = null } = {}) {
    let toolName = typeof name === "string" ? name : "<invalid>";
    const meta = () => ({
      userId: isRecord(ctx?.user) ? ctx.user.id : "<invalid>", tenant: isRecord(ctx?.user) ? ctx.user.tenant : "<invalid>",
      agentId: isRecord(ctx?.agent) ? ctx.agent.id : "<invalid>", sessionId: isRecord(ctx?.session) ? ctx.session.id : "<invalid>",
      tainted: isRecord(ctx?.session) ? ctx.session.tainted === true : null, tool: toolName,
      argsHash: (() => { try { return hashJson(args); } catch { return "<unhashable>"; } })(),
      argsPreview: Gateway.#redact(args, this.#policy.redactKeys || []),
    });
    let descriptorHash = null;
    try {
      this.#validateContext(ctx);
      const entry = this.#policy.tools[toolName];
      if (!entry || !Object.hasOwn(this.#policy.tools, toolName)) throw new Deny("TOOL_NOT_ALLOWLISTED");
      const status = this.#status.get(toolName);
      if (status === "drifted") throw new Deny("DESCRIPTOR_DRIFT", "the server's descriptor no longer matches the reviewed pin");
      if (status !== "ok") throw new Deny("TOOL_NOT_ADVERTISED");
      const descriptor = this.#descriptors.get(toolName);
      descriptorHash = hashJson(descriptor);

      // Structure: arguments must be a plain object that matches the PINNED schema, closed.
      if (!isRecord(args)) throw new Deny("SCHEMA_VIOLATION", "arguments must be an object");
      const schemaErrors = validate(descriptor.inputSchema, args);
      if (schemaErrors.length) throw new Deny("SCHEMA_VIOLATION", schemaErrors.slice(0, 3).join("; "));

      // Resource: validated, never repaired.
      let resource = "*";
      try {
        if (entry.resourceKind === "path") resource = validatePath(args[entry.resourceArg]);
        else if (entry.resourceKind === "email_domain") resource = emailDomain(args[entry.resourceArg]);
      } catch (e) {
        if (e instanceof ResourceError) throw new Deny(entry.resourceKind === "path" ? "PATH_INVALID" : "RECIPIENT_INVALID", e.message);
        throw e;
      }

      // Authority is the INTERSECTION of the user's and the agent's scopes.
      if (!allows(ctx.user.scopes, entry.capability, entry.verb, resource)) throw new Deny("USER_SCOPE_DENIED", `${entry.capability}:${entry.verb}`);
      if (!allows(ctx.agent.scopes, entry.capability, entry.verb, resource)) throw new Deny("AGENT_SCOPE_DENIED", `${entry.capability}:${entry.verb}`);
      if (entry.risk === "egress" && !this.#policy.egress.allowedRecipientDomains.includes(resource)) {
        throw new Deny("RECIPIENT_NOT_ALLOWED", "approval cannot widen the destination allowlist");
      }

      // Risk gating.
      let needsApproval = false;
      if (entry.risk === "write_internal") needsApproval = ctx.session.tainted;
      else if (entry.risk === "egress") needsApproval = true;
      else if (entry.risk === "destructive") {
        if (ctx.session.tainted) throw new Deny("TAINTED_SESSION_DESTRUCTIVE", "untrusted content is in the model's context");
        needsApproval = true;
      }

      let approvalToConsume = null;
      const actionHash = hashJson({ user: ctx.user.id, agent: ctx.agent.id, tool: toolName, args, descriptor: descriptorHash });
      if (needsApproval) {
        if (!approvalId) {
          // Bound the work an agent can push onto human reviewers.
          const pending = [...this.#approvals.values()].filter((a) => a.agentId === ctx.agent.id && ["pending", "approved"].includes(a.state) && this.#now() <= a.expiresAt).length;
          if (pending >= (this.#policy.maxPendingApprovals || 3)) throw new Deny("TOO_MANY_PENDING_APPROVALS", `${pending} requests already waiting for a human`);
          const id = `apr-${crypto.randomBytes(6).toString("hex")}`;
          const request = { id, actionHash, state: "pending", userId: ctx.user.id, agentId: ctx.agent.id, tool: toolName, summary: this.#summary(toolName, args), expiresAt: this.#now() + (this.#policy.approvalTtlSeconds || 120) * 1000, approverId: null };
          this.#approvals.set(id, request);
          const rec = this.#log({ event: "decision", decision: "approval_required", reason: "APPROVAL_REQUIRED", executed: false, approvalId: id, descriptorHash, ...meta() });
          return { decision: "approval_required", reason: "APPROVAL_REQUIRED", executed: false, approvalId: id, summary: request.summary, auditSeq: rec.seq };
        }
        const approval = this.#approvals.get(approvalId);
        if (!approval) throw new Deny("APPROVAL_INVALID", "unknown approval id");
        if (approval.state === "consumed") throw new Deny("APPROVAL_CONSUMED", "single use");
        if (approval.state === "denied") throw new Deny("APPROVAL_DENIED");
        if (approval.state !== "approved") throw new Deny("APPROVAL_INVALID", "not approved yet");
        if (this.#now() > approval.expiresAt) throw new Deny("APPROVAL_EXPIRED");
        if (approval.actionHash !== actionHash) throw new Deny("APPROVAL_MISMATCH", "approval is bound to different arguments, identity or tool descriptor");
        approvalToConsume = approval;
      }

      // Rate limit EXECUTIONS per agent and tool. Checked before the approval is consumed, so a
      // limited call does not waste a human's decision; denied probes do not consume budget (they are audited instead).
      if (entry.rate) {
        const key = `${ctx.agent.id}|${toolName}`;
        const window = (this.#calls.get(key) || []).filter((t) => this.#now() - t < entry.rate.windowSeconds * 1000);
        if (window.length >= entry.rate.max) { this.#calls.set(key, window); throw new Deny("RATE_LIMITED", `${entry.rate.max} per ${entry.rate.windowSeconds}s`); }
        window.push(this.#now()); this.#calls.set(key, window);
      }
      // Consumed before the call: a failed call must not leave a reusable approval.
      if (approvalToConsume) approvalToConsume.state = "consumed";

      // Audit the decision BEFORE executing. If this write fails, nothing runs.
      let allowSeq = null;
      try {
        allowSeq = this.#log({ event: "decision", decision: "allow", reason: needsApproval ? "ALLOWED_WITH_APPROVAL" : "ALLOWED", executed: false, approvalId: approvalId || null, descriptorHash, ...meta() }).seq;
      } catch {
        throw new Deny("AUDIT_UNAVAILABLE", "the decision could not be recorded, so the call was not made");
      }

      let raw;
      try {
        raw = await this.#client.request("tools/call", { name: toolName, arguments: args });
      } catch (e) {
        if (e instanceof Deny) {
          const rec = this.#safeLog({ event: "outcome", outcome: e.reason, executed: false, ...meta() });
          return { decision: "allow", reason: e.reason, executed: false, upstreamFailed: true, auditSeq: rec ? rec.seq : allowSeq };
        }
        throw e;
      }

      const checked = this.#validateOutput(descriptor, raw);
      if (!checked.ok) {
        const rec = this.#safeLog({ event: "outcome", outcome: "OUTPUT_INVALID", detail: checked.error, executed: true, ...meta() });
        return { decision: "allow", reason: "OUTPUT_INVALID", executed: true, outputWithheld: true, detail: checked.error, auditSeq: rec ? rec.seq : allowSeq };
      }
      if (entry.taintsSession) ctx.session.tainted = true; // content from outside the trust boundary is now in the model's context
      if (checked.flags.includes("instruction_like_content")) ctx.session.tainted = true;
      const rec = this.#safeLog({ event: "outcome", outcome: "OK", executed: true, flags: checked.flags, taintedAfter: ctx.session.tainted, ...meta() });
      return { decision: "allow", reason: needsApproval ? "ALLOWED_WITH_APPROVAL" : "ALLOWED", executed: true, result: checked.result, auditSeq: rec ? rec.seq : allowSeq };
    } catch (e) {
      if (!(e instanceof Deny)) throw e;
      let auditFailed = false; let auditSeq = null;
      try { auditSeq = this.#log({ event: "decision", decision: "deny", reason: e.reason, detail: e.detail.slice(0, 200), executed: false, descriptorHash, ...meta() }).seq; } catch { auditFailed = true; }
      return { decision: "deny", reason: e.reason, detail: e.detail, executed: false, auditFailed, auditSeq };
    }
  }

  #safeLog(fields) {
    try { return this.#log(fields); } catch { return null; /* the decision record already exists; an outcome record can be lost */ }
  }

  /** The human decision surface. Not reachable from the agent: approver ids come from policy, never from the model. */
  approve(approvalId, approverId, verdict = "approve") {
    const approval = this.#approvals.get(approvalId);
    let outcome;
    if (!approval) outcome = { ok: false, reason: "APPROVAL_INVALID" };
    else if (!this.#policy.approvers.includes(approverId) || approverId === approval.agentId) outcome = { ok: false, reason: "APPROVER_NOT_AUTHORIZED" };
    else if (approval.state !== "pending") outcome = { ok: false, reason: approval.state === "consumed" ? "APPROVAL_CONSUMED" : "APPROVAL_INVALID" };
    else if (this.#now() > approval.expiresAt) outcome = { ok: false, reason: "APPROVAL_EXPIRED" };
    else { approval.state = verdict === "approve" ? "approved" : "denied"; approval.approverId = approverId; outcome = { ok: true, reason: approval.state === "approved" ? "APPROVED" : "APPROVAL_DENIED" }; }
    this.#safeLog({ event: "approval", approvalId, approverId: String(approverId).slice(0, 64), reason: outcome.reason, ok: outcome.ok, tool: approval?.tool || "<unknown>" });
    return outcome;
  }

  #validateOutput(descriptor, raw) {
    const out = this.#policy.output;
    const fail = (error) => ({ ok: false, error });
    if (!isRecord(raw) || !Array.isArray(raw.content) || raw.content.length > 8) return fail("content must be a short array");
    if (raw.isError !== undefined && typeof raw.isError !== "boolean") return fail("isError must be boolean");
    let bytes = 0;
    const flags = [];
    const content = [];
    for (const item of raw.content) {
      if (!isRecord(item) || item.type !== "text" || typeof item.text !== "string" || Object.keys(item).sort().join() !== "text,type") return fail("only plain text content is accepted");
      if (BAD_CONTROL.test(item.text)) return fail("control characters in output");
      bytes += Buffer.byteLength(item.text);
      let text = item.text;
      text = text.replace(/https?:\/\/([A-Za-z0-9.-]+)[^\s)"']*/g, (url, host) => {
        if ((out.allowedHosts || []).includes(host.toLowerCase())) return url;
        if (!flags.includes("links_removed")) flags.push("links_removed");
        return "[link removed: host not allowed]";
      });
      if (INJECTION_HINT.test(text) && !flags.includes("instruction_like_content")) flags.push("instruction_like_content");
      content.push({ type: "text", text });
    }
    if (bytes > out.maxBytes) return fail(`output ${bytes} bytes exceeds ${out.maxBytes}`);
    const result = { content, isError: raw.isError === true, provenance: "tool_output", flags };
    if (descriptor.outputSchema && !result.isError) {
      if (raw.structuredContent === undefined) return fail("outputSchema declared but structuredContent missing");
      const errors = validate(descriptor.outputSchema, raw.structuredContent);
      if (errors.length) return fail(`structuredContent invalid: ${errors[0]}`);
      result.structuredContent = raw.structuredContent;
    } else if (raw.structuredContent !== undefined) {
      return fail("structuredContent returned without an outputSchema");
    }
    return { ok: true, result, flags };
  }
}

module.exports = { Deny, Gateway, validatePolicy };
