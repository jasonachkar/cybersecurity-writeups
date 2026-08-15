---
id: ai-agent-security
title: AI Agent External Tool-Broker Lab
navTitle: AI-agent security
domain: appsec
order: 40
summary: Exercises action-bound approval, replay resistance, kill-switch behavior, and unknown-argument denial in a local tool broker.
implementationStatus: tested
related:
  research: [ai-agent-security]
sourceFiles:
  - { path: labs/ai-agent-security/broker.js, label: Broker implementation, language: javascript, primary: true }
  - { path: labs/ai-agent-security/tests/broker.test.js, label: Tests, language: javascript }
runCommands: [node --test labs/ai-agent-security/tests/broker.test.js]
---

# AI Agent External Tool-Broker Lab

Status: **tested teaching implementation**. The surrounding production architecture in [`appsec/ai-agent-security.md`](../../appsec/ai-agent-security.md) is **conceptual and partially tested**.

This dependency-free Node.js lab demonstrates one narrow security boundary: a model may propose an action, but a broker outside the model decides whether a fake executor receives it. The executor stores an in-memory record and returns `status: simulated`; it performs no network, filesystem, financial, cloud, or other external action.

## Security properties exercised

The broker receives `authenticatedContext` separately from `proposedCall` and then:

- resolves a static server-side policy for the authenticated principal;
- rejects an unauthorized principal, tenant, tool, destination, or amount;
- accepts only a closed argument schema;
- requires approval at or above the configured impact threshold;
- asks an injected approval verifier for the authoritative approval record;
- binds approval to principal, tenant, tool, amount, and destination;
- consumes approval before execution to reject replay;
- checks an independently injected execution kill switch;
- emits sanitized decision and outcome events to an in-memory audit sink;
- invokes a fake executor only after all controls allow the call.

The tests assert that the fake executor's invocation count stays zero for denied actions. This distinction matters: a model may still propose a forbidden action, but it must not acquire authority by doing so.

## Run

From the repository root with Node.js 22 or newer:

```powershell
node --test labs/ai-agent-security/tests/broker.test.js
```

No package installation, environment variable, credential, service, container, or network connection is required.

## Files

- `broker.js` contains the broker and stable denial codes.
- `tests/broker.test.js` has tests for both what should work and what should get denied, plus the fake policy, approval store, audit sink, kill switch, and executor.

## Deliberate limitations

This is not a production authorization library. In particular:

- `authenticatedContext` is assumed to come from a trusted gateway. The lab does not validate a session, workload certificate, issuer, signature, audience, freshness, revocation, or tenant membership source.
- The policy is an in-process fixture. It has no administrative authorization, durable version, distribution, cache, or outage behavior.
- The approval verifier reads an in-memory map. It does not authenticate an approver, verify a signature, enforce separation of duties, or persist single-use state across processes.
- Replay state, audit events, and fake execution records are memory-only.
- The broker validates one teaching schema for a simulated payment-like action. A real broker needs a reviewed, versioned schema and constraints per tool.
- The lab does not implement MCP, OAuth, token exchange, downstream reauthorization, idempotency reconciliation, a sandbox, secret delivery, egress control, rate limiting, or durable incident evidence.

For production, derive identity and tenant outside the model, use a maintained authorization implementation, bind short-lived credentials to the selected resource, make the downstream service authorize again, and test fail-closed behavior at every boundary.
