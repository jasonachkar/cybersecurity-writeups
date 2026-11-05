---
id: mcp-tool-authorization
title: MCP tool-authorization gateway lab
navTitle: MCP tool authorization
domain: ai-security
order: 140
summary: A policy gateway between an agent runtime and a mock MCP-style stdio server, tested against a deliberately compromised stand-in agent for allowlists, scoped identity, taint, approval gates, descriptor pinning, output validation and tamper-evident audit.
implementationStatus: partially-tested
related:
  research: [mcp-tool-authorization-lab, evidence-driven-agent-security, ai-agent-security]
  labs: [ai-agent-security, mcp-tool-ssrf]
sourceFiles:
  - { path: labs/mcp-tool-authorization/gateway.js, label: Policy gateway, language: javascript, primary: true }
  - { path: labs/mcp-tool-authorization/policy.json, label: Policy with pinned descriptors, language: json }
  - { path: labs/mcp-tool-authorization/audit.js, label: Hash-chained audit log, language: javascript }
  - { path: labs/mcp-tool-authorization/lib/scope.js, label: Scope and path matching, language: javascript }
  - { path: labs/mcp-tool-authorization/agent-sim.js, label: Compromised-agent stand-in, language: javascript }
  - { path: labs/mcp-tool-authorization/mock-server.js, label: Mock MCP-style server, language: javascript }
  - { path: labs/mcp-tool-authorization/tests/gateway.test.js, label: Mechanism tests, language: javascript }
  - { path: labs/mcp-tool-authorization/scripts/run-scenarios.js, label: Decision matrix runner, language: javascript }
runCommands:
  - node --test labs/mcp-tool-authorization/tests/gateway.test.js
  - node labs/mcp-tool-authorization/scripts/run-scenarios.js
---

# MCP tool-authorization gateway lab

**Status: partially tested.** Dependency-free Node.js; the tests run in `npm run validate`. The analysis, diagrams and
the mapping to the MCP specification are in the article: [MCP Tool Authorization Lab](../../ai-security/mcp-tool-authorization-lab.md).

> **There is no language model here.** The "agent" is a deterministic stand-in that obeys any `CALL tool {json}` line found in a
> tool result: the worst case of a compromised planner. It shows that the gateway's decisions do not depend on model behaviour.
> It cannot show whether a real model is injectable or how often. No LLM API is contacted, no credential is used, and every
> tool effect is an in-memory array append in a local child process. The `.test` domains are reserved for testing; all data is synthetic.

Evidence labels: `tested locally` (executed here; output in [`evidence/`](https://github.com/jasonachkar/cybersecurity-writeups/tree/main/labs/mcp-tool-authorization/evidence)),
`policy model` (decision logic evaluated against a stand-in, not a real model or identity provider), `source-reviewed`, `requires-review`.

## Scope

The authorization decision for an agent-proposed tool call: which tools exist, whose authority applies, when a human must decide,
what the tool may return, and what is recorded. Out of scope: authenticating users or agents (the context is a trusted input here), token
issuance and exchange, the MCP authorization flow, transport security, sandboxing the tool server, and any real model behaviour. This extends the
[AI-agent external tool-broker lab](../ai-agent-security/README.md) (action-bound approval, replay resistance) to an MCP-shaped server with taint,
descriptor pinning, output validation and an audit chain; it does not replace it, and the [SSRF lab](../mcp-tool-ssrf/README.md) covers URL-fetching tools.

## What I built

| Path | Purpose |
| --- | --- |
| `mock-server.js` | Newline-delimited JSON-RPC 2.0 over stdio: `initialize`, `tools/list`, `tools/call`; five tools on in-memory data; modes `normal`, `rugpull`, `hostile_output`, `slow`, `crash`; side effects reported on stderr so tests observe them independently |
| `gateway.js` | The single enforcement point: allowlist, descriptor pin, closed-schema check, path/recipient validation, user-AND-agent scope intersection, destination allowlist, risk gating with taint, approval verification, execution rate limit, audit-before-execute, timeout, output validation |
| `policy.json` | Deny-by-default policy; each tool's reviewed descriptor is pinned by SHA-256 |
| `audit.js` | Hash-chained append-only log with `verifyChain` |
| `lib/` | Canonical hashing, a closed JSON-Schema subset, strict scope and path matching |
| `agent-sim.js` | `NaiveAgent`, the compromised-planner stand-in |
| `tests/gateway.test.js` | 33 tests against a real spawned server process |
| `scripts/run-scenarios.js` | 16 scenarios, expectations declared before each step, decision matrix written to JSON and Markdown |
| `scripts/pin.js`, `scripts/run-lab.sh` | Pin check/update; run everything |

## Validation

Recorded run (`evidence/versions.txt`): Node.js v22.23.4, Linux 6.18.44, policy version `2026-11-05.1`.

```bash
node --test labs/mcp-tool-authorization/tests/gateway.test.js     # 33 tests
node labs/mcp-tool-authorization/scripts/run-scenarios.js         # 16 scenarios, 31 proposed calls
bash labs/mcp-tool-authorization/scripts/run-lab.sh               # pins + tests + scenarios
```

| Check | Observed |
| --- | --- |
| Descriptor pins | all five match the benign server |
| Mechanism tests | 33 passed, 0 failed (includes a check that every reason code the gateway can emit was exercised) |
| Scenario matrix | 16 scenarios, 31 proposed calls: **11 allow, 5 approval required, 15 deny**; every expectation met; every audit chain verifies |
| Side effects | observed on a channel separate from the protocol: nothing happened for any denied or unapproved call |

The matrix, with a read-across to reasons and audit sequence numbers, is in the [article](../../ai-security/mcp-tool-authorization-lab.md#findings-and-interpretation).

## What was not tested

- A real language model, real prompt injection, or any measure of how injectable a model is. The stand-in obeys every injected instruction by construction.
- Authentication of the user, the agent or the approver; token validation; the MCP authorization specification; OAuth flows.
- A conformant MCP server or client: the mock implements four methods and no pagination, capabilities negotiation, resources, prompts or sampling.
- Remote (HTTP) MCP transport; only stdio.
- A compromised gateway host, a compromised approval UI, or an attacker with access to the audit store. The audit chain's tail-truncation gap is demonstrated, not closed.
- Concurrency, performance and rate-limit behaviour under load; approval-fatigue effects on real reviewers.
- Cloud, production data or credentials. None is used.

## Production considerations

See the [article](../../ai-security/mcp-tool-authorization-lab.md#production-considerations): rollout (observe before enforce, onboard a tool by reviewing its pin), detection (alert on drift, repeated denials,
approval floods), operability (audit outage is tool outage, by design), false positives (taint gating creates approval work), blast radius and rollback.

## References

- Model Context Protocol, specification revision 2025-11-25, source of [Tools](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-11-25/server/tools.mdx) (message shapes, annotations untrusted, security considerations) and [Transports](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-11-25/basic/transports.mdx) (stdio framing).
- Node.js version: the runtime's own output, in `evidence/versions.txt`.

## Related maintained investigations

- [MCP Tool Authorization Lab (article)](../../ai-security/mcp-tool-authorization-lab.md)
- [Evidence-Driven AI Agent and MCP Security](../../ai-security/evidence-driven-agent-security.md)
- [Threat-Driven Security Architecture for AI Agents](../../appsec/ai-agent-security.md)
- [AI-agent external tool-broker lab](../ai-agent-security/README.md)
