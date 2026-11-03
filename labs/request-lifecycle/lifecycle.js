"use strict";

// Tested local teaching model. Context authentication and durable idempotency are
// deliberately external; this is not AWS Lambda, Vault or an event-source emulator.
class SecretCache {
  constructor(provider, clock, maxAgeMs = 1000) {
    this.provider = provider;
    this.clock = clock;
    this.maxAgeMs = maxAgeMs;
    this.cached = null;
  }
  async get() {
    const now = this.clock();
    if (this.cached && now < this.cached.expires) return this.cached.value;
    // Never return an expired value if refresh fails.
    this.cached = null;
    const value = await this.provider();
    if (!value || typeof value.value !== "string" || typeof value.version !== "string") {
      throw new Error("SECRET_UNAVAILABLE");
    }
    this.cached = {value, expires: now + this.maxAgeMs};
    return value;
  }
}

class EventHandler {
  constructor({clock, secrets, execute}) {
    this.clock = clock;
    this.secrets = secrets;
    this.execute = execute;
    this.completed = new Map();
    this.audit = [];
    this.pending = Promise.resolve();
  }
  handle(context, event) {
    // Serialize the toy in-process ledger. A real consumer needs durable atomic
    // idempotency and reconciliation at the actual downstream side effect.
    const result = this.pending.then(() => this.process(context, event));
    this.pending = result.catch(() => {});
    return result;
  }
  async process(context, event) {
    const deny = code => {
      this.audit.push({event: "event_decision", outcome: "deny", code});
      throw new Error(code);
    };
    if (!context || context.verified !== true || context.producer !== "owned-queue") deny("PRODUCER_DENIED");
    if (!event || typeof event !== "object" || Array.isArray(event) ||
        Object.keys(event).sort().join(",") !== "id,issuedAt,tenant,value" ||
        !/^[a-z0-9-]{1,40}$/.test(event.id) || !Number.isSafeInteger(event.issuedAt) ||
        typeof event.value !== "string" || event.value.length > 100) deny("EVENT_INVALID");
    if (!context.tenant || context.tenant !== event.tenant) deny("TENANT_DENIED");
    if (event.issuedAt > this.clock() || this.clock() - event.issuedAt > 1000) deny("EVENT_STALE");
    const key = JSON.stringify([context.tenant, event.id]);
    if (this.completed.has(key)) {
      if (this.completed.get(key) !== JSON.stringify(event)) deny("IDEMPOTENCY_CONFLICT");
      this.audit.push({event: "event_decision", outcome: "duplicate"});
      return {status: "duplicate"};
    }
    const secret = await this.secrets.get();
    // No tenant/event retained in a shared global for later invocations.
    await this.execute({tenant: context.tenant, value: event.value, secret: secret.value});
    this.completed.set(key, JSON.stringify(event));
    this.audit.push({event: "event_decision", outcome: "allow", secretVersion: secret.version});
    return {status: "completed"};
  }
}

module.exports = {EventHandler, SecretCache};
