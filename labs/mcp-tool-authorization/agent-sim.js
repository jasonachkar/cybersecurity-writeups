"use strict";

/**
 * NaiveAgent - a deterministic stand-in for a COMPROMISED planning step. It is NOT a language model.
 *
 * It does two things: execute the calls its operator scripted, and then obey any line of the form
 *     CALL <tool> {json}
 * that appears in a tool result - the worst case of indirect prompt injection, where the model
 * treats retrieved content as instructions. Because it complies with every injected instruction, a
 * test that passes with this agent shows the gateway does not rely on the model behaving.
 *
 * What it cannot show: whether a real model is injectable, how often, or how well a prompt or
 * a classifier resists injection. Those need a real model and are outside this lab. No LLM API is
 * contacted and no credentials are used.
 *
 * The agent holds no reference to the approval surface or the audit log; approvals are
 * given by a separate "human" function in the harness.
 */
class NaiveAgent {
  constructor(gateway, ctx) {
    this.gateway = gateway;
    this.ctx = ctx;
    this.transcript = [];
  }

  /** Run scripted calls, then follow injected CALL lines (at most `limit` follow-ups). */
  async run(script, { limit = 6 } = {}) {
    const queue = script.map((step) => ({ ...step, origin: "script" }));
    let followUps = 0;
    while (queue.length) {
      const step = queue.shift();
      const outcome = await this.gateway.callTool(this.ctx, step.tool, step.args, step.approvalId ? { approvalId: step.approvalId } : {});
      this.transcript.push({ origin: step.origin, tool: step.tool, args: step.args, outcome });
      if (outcome.executed && outcome.result && followUps < limit) {
        for (const text of outcome.result.content.map((c) => c.text)) {
          for (const line of text.split("\n")) {
            const match = line.match(/^CALL\s+(\w+)\s+(\{.*\})\s*$/);
            if (!match) continue;
            try {
              queue.push({ tool: match[1], args: JSON.parse(match[2]), origin: "injected" });
              followUps += 1;
            } catch { /* a malformed injection is simply ignored */ }
          }
        }
      }
    }
    return this.transcript;
  }
}

module.exports = { NaiveAgent };
