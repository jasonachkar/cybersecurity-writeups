---
title: "Layered Runtime Application Protection: WAF, In-Process Controls and eBPF Enforcement"
id: "runtime-protection-rasp-waf"
navTitle: "Runtime protection"
order: 50
type: "appsec"
tags:
  - appsec
  - runtime
  - protection
  - rasp
  - waf
date: "2026-07-25"
lastReviewed: "2026-11-02"
reviewStatus: "requires-review"
validatedAgainst:
  - "2026-11-02 research-protocol and local-test audit; retained product claims require independent renewed source review"
  - "Tetragon TracingPolicy API reference — https://tetragon.io/docs/reference/tracing-policy/"
  - "Tetragon selector and action semantics — https://tetragon.io/docs/concepts/tracing-policy/selectors/"
  - "Tetragon policy enforcement guide — https://tetragon.io/docs/getting-started/enforcement/"
  - "Tetragon v1.7.0 release — https://github.com/cilium/tetragon/releases/tag/v1.7.0"
  - "Tetragon v1.7.0 namespaced policy CRD — https://github.com/cilium/tetragon/blob/v1.7.0/install/kubernetes/tetragon/crds-yaml/cilium.io_tracingpoliciesnamespaced.yaml"
  - "AWS WAF web ACL behavior and rule model — https://docs.aws.amazon.com/waf/latest/developerguide/web-acl.html"
sourceQuality: "requires-review"
implementationStatus: "illustrative"
reviewIntervalDays: 90
---

# Layered Runtime Application Protection: WAF, In-Process Controls and eBPF Enforcement

No runtime control is an application security boundary by itself. Use these controls to reduce exploitability, detect abuse, and contain selected behavior while continuing to patch vulnerable components, fix authorization, isolate workloads, and test the application.

## The core decision

Select enforcement at the point that has the required context and an acceptable failure mode:

- Use a **WAF** for request-layer filtering, rate controls, managed signatures, and virtual patching where its parser and placement match the traffic path.
- Use **in-process controls** where language/runtime hooks can observe a dangerous sink with enough application context and the agent is supportable.
- Use **eBPF or kernel runtime policy** for selected process, file, capability, and network events that can be represented at that boundary.

Default to detection or count mode, establish baseline and bypass tests, then enforce narrowly. A control that can terminate a process or block a syscall can also cause an outage.

## Scope and threat model

The model assumes an internet-facing application running in containers. Relevant threats include malformed requests, automated abuse, known exploit patterns, application parser confusion, injection reaching a runtime sink, unexpected child processes, and post-exploitation actions. It does not assume every exploit arrives through HTTP or that every runtime event reveals business intent.

Model bypasses separately: alternate ingress, protocol upgrades, asynchronous consumers, direct service calls, unsupported runtime code, agent disablement, host access, kernel incompatibility, and trusted-but-compromised operators.

## Control comparison

| Dimension | WAF / edge filter | In-process control (RASP or instrumented guard) | eBPF / runtime policy |
|----|----|----|----|
| Enforcement location | Proxy, CDN, load balancer, or gateway | Application process or runtime | Selected kernel hooks or runtime events on the node |
| Available context | Decoded request fields, connection metadata, reputation, rate and managed-rule state | Runtime objects, framework route, call stack, sink arguments, application state exposed by hooks | Process lineage, binary/path, syscall arguments, namespaces, capabilities, sockets, workload metadata |
| Supported protocols/runtimes | Only protocols and encodings the deployment parses | Only supported languages, frameworks, versions and instrumented paths | Only supported kernels, hooks, argument types and product features |
| Parser alignment | May disagree with intermediaries or the application | Closer to selected runtime sinks but still dependent on hooks and transformations | Sees kernel-level representation, not the complete application parse |
| Bypass conditions | Alternate route, parser differential, uninspected body, allowlisted source, rule gap | Uninstrumented code, native call, agent failure, unsupported framework, tampering | Unobserved hook, alternate binary/interpreter, direct syscall, unsupported kernel, policy scope gap |
| Failure behavior | Fail-open or fail-closed depends on topology and service mode | May fail startup, add latency, throw, log only, or block in-process | May fail policy load, miss events, kill a process, override a call, or destabilize a workload if mis-scoped |
| Performance / availability | Rule count, body inspection, regex, network placement and managed service capacity matter | Hook density, runtime overhead, allocation and agent health matter | Probe cost, event volume, maps, kernel support and selector complexity matter |
| Operational ownership | Edge/platform plus application teams | Application and runtime owners | Platform, kernel/runtime and workload owners |
| Telemetry | Request, rule, action, labels, sampled body subject to redaction | Sink, stack, route and runtime decision subject to product coverage | Process, syscall, namespace, capability and workload metadata subject to hook semantics |
| Rollback | Rule disable, scope change, count mode, web ACL detach | Agent/config disable or application redeploy | Policy disable/delete, monitor mode, workload rollback |
| Cannot see | Complete business authorization and code paths outside inspected traffic | Unsupported code and infrastructure behavior outside the process | Complete user intent, tenant ownership, application object state, or semantic authorization |

## WAF boundary

Modern WAFs can combine signatures, rate-based rules, reputation, behavioral logic, managed rules, and organization-specific controls. Their context is not universally “low,” and their latency is not always negligible. Inspection limits, body handling, normalization, rule ordering, regex complexity, and false positives must be measured for the actual request mix.

The core risk is parser alignment: an intermediary can normalize or interpret an input differently from the application. Include double encoding, duplicate parameters, ambiguous content types, invalid Unicode, decompression, oversized bodies, chunking, and alternate routes in regression tests. Preserve the raw and normalized fields needed for investigation without logging secrets.

## In-process controls

An in-process product may observe selected framework operations or sinks after some application parsing. It does not necessarily see the “final interpreted payload,” and coverage varies by language, runtime, framework, library, native code, reflection, and agent version. A control might block a tested SQL execution path while missing another database driver or deserialization route.

Treat prevention claims as testable hypotheses. Test startup failure, agent loss, unsupported versions, exception behavior, instrumentation gaps, asynchronous work, native extensions, tampering, fail-open/fail-closed behavior, and rollback. Keep authorization and input handling in application code; the runtime agent is defense in depth.

## eBPF and kernel runtime boundary

eBPF-based controls can observe or act on selected kernel events with useful process and workload context. That does not make them application authorization. A kernel policy generally cannot decide whether user A may update tenant B's invoice, and the visible syscall may be far removed from the vulnerable business operation.

Selector meaning is exact. Tetragon `matchNamespaces` refers to Linux namespaces; it is not a Kubernetes namespace-name selector. Kubernetes scoping is represented by `TracingPolicyNamespaced`, its `metadata.namespace`, and supported workload selectors. Confirm hook availability and semantics on the deployed kernel.

## Tetragon v1.7.0 schema-validated example

**Evidence label: schema-validated example; no live enforcement test.** The source was pinned to Tetragon [v1.7.0](https://github.com/cilium/tetragon/releases/tag/v1.7.0) (tag checkout commit `1de2ed8ebea18e56257dc59597aa13bf8f0e471e`). The manifest was validated offline against that release's official [`TracingPolicyNamespaced` CRD](https://github.com/cilium/tetragon/blob/v1.7.0/install/kubernetes/tetragon/crds-yaml/cilium.io_tracingpoliciesnamespaced.yaml).

The prompt-shaped draft used `operator: In`, but the pinned v1.7.0 CRD does not permit that operator for `matchArgs`. Validation caught the mismatch; the published policy uses `Equal`, whose documented value list matches any listed value.

``` yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: detect-shell-from-web-runtime
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: web
  kprobes:
    - call: sys_execve
      syscall: true
      args:
        - index: 0
          type: string
      selectors:
        - matchArgs:
            - index: 0
              operator: Equal
              values:
                - /bin/sh
                - /bin/bash
                - /usr/bin/sh
                - /usr/bin/bash
          matchActions:
            - action: Sigkill
```

[Download the schema-validated Tetragon v1.7.0 policy](tetragon-v1.7.0-shell-policy.yaml){download=""}.

This narrow demonstration matches four exact path strings passed to `execve`. Tetragon documents `Sigkill` as terminating the matching process; it does not promise to terminate the pod. Kubernetes may restart a container according to its lifecycle only if the killed process causes the container to exit.

The rule is not a complete remote-code-execution control. It can miss other shells, interpreters, copied or renamed binaries, relative or alternate paths, scripts, already-running processes, direct syscalls, and behavior that does not invoke a shell. It can also kill legitimate operational or startup activity. Test it in observe-only conditions first, then in an authorized disposable cluster with representative workloads and recovery behavior.

## Failure modes

| Failure | Impact | Required control |
|----|----|----|
| WAF unavailable or bypassed | Requests reach the application without expected filtering | Application remains securely coded and authorized; health and route monitoring detect bypass |
| Managed-rule update | False positives or changed coverage | Count/canary rollout, sampled decisions, version/change tracking, rapid rollback |
| RASP hook or agent failure | Missed detection or application impact | Health signal independent of application success; tested startup and degradation policy |
| Tetragon policy rejected | No intended observation or enforcement | CRD/schema check plus controller/agent status and policy-load alert |
| Kernel or workload mismatch | Silent coverage gap or excessive events | Compatibility matrix and representative node tests |
| Over-broad kill policy | Availability incident | Narrow selectors, canary namespaces, SLO guardrail, immediate policy disable procedure |

## Telemetry and operations

Correlate edge request ID, WAF rule/action/version, application route, runtime decision, workload identity, pod UID, node, binary, parent process, arguments subject to redaction, policy name/version, and kernel action. Detect telemetry loss separately from “no detections.” Limit body and argument capture, apply access controls and retention, and test that emergency rollback evidence survives.

## Rollout, rollback and tests

1. Write the exploit and legitimate-traffic hypotheses for each control.
2. Baseline in log/count mode and measure parser coverage, overhead, event loss, and false positives.
3. Canary one route, runtime, namespace, and node pool; run negative and bypass cases.
4. Enforce the smallest high-confidence rule and bound its maximum availability impact.
5. Exercise rollback: disable the exact rule or policy without removing unrelated controls.

Required negative cases include alternate ingress, unsupported content type, oversized body, encoded payload variants, uninstrumented library path, agent disabled, policy load failure, other interpreter paths, renamed binary, direct syscall, legitimate administrative shell, and node/kernel mismatch.

The local validation performed here was structural CRD validation only. A live test would additionally apply the official v1.7.0 CRDs and policy to an authorized disposable cluster, verify policy status, execute both matching and non-matching processes in a selected pod, confirm process-versus-container behavior, inspect events, and remove the policy.

## What's still not solved

Zero-days outside your rule coverage, parser differentials, a compromised allowlisted client, runtimes the agent doesn't support, native code, bugs in the agent or kernel module itself, whoever has privileged node access, telemetry loss, false positives, exception abuse, and plain old malicious behavior dressed up as a legitimate business operation — none of that goes away. Runtime enforcement narrows specific paths; it's not a replacement for patching, secure coding, authorization, sandboxing, or tenant isolation.

## Research question and hypothesis

**Question:** Does application-level destination enforcement reject the same internal-fetch requests even when edge filtering is absent?

**Falsifiable hypothesis (bounded experiment):** A local gateway rejects direct internal URLs and redirects independently of a WAF; returning a protected marker through the remediated path refutes this application boundary.

## Research threat model

| Element | Declared scope |
| --- | --- |
| Actor | Request sender or compromised web process |
| Assets | Internal service, application sinks, runtime policy and availability |
| Entry points | HTTP payload, direct service access and process execution |
| Trust boundaries | Edge parser → application sink → kernel/network authority |
| Impact under investigation | Internal access or a control-induced availability incident |
| Trusted assumptions | Owned test host, reviewed fixture/code and independently established identity context; deployment administrators remain outside the local attacker model |

## Method and evidence requirements

Follow the [evidence standards](../research-methodology/evidence-standards.md).
The [related lab](../labs/mcp-tool-ssrf/README.md) owns setup, prerequisites, expected
output, safety, evidence collection and teardown. From repository root:

```sh
python3 vulnerability-research/mcp-tool-ssrf/lab/test_fetcher.py
```

This command is a **tested local check**, with the scope below. Review test inputs
and failure assertions before interpreting a pass. For a deployment study, capture
exact versions/configuration, one allowed control, every intended denial, state
before/after and independent audit evidence. A policy file or syntax check is T1,
not enforcement proof. Do not deploy cloud resources from repository validation.

## Findings and interpretation

| Claim class | Evidence tier and boundary |
| --- | --- |
| Observed local result | T2/T3 within the linked harness: This is application destination-policy evidence only. The retained Tetragon example remains schema evidence, not a live kernel prevention result. |
| Architecture explanation in this article | T0: sourced explanation or engineering judgment under its stated assumptions |
| Configuration/schema examples | At most T1 unless a linked runtime test explicitly covers that example |
| Production effectiveness | Not established by this repository's local result |

## Practical guidance and failure containment

Do not use a generic runtime event as business authorization. Canary enforcement with benign and alternate-path cases; keep exact-rule rollback available.

Count exercised allow/deny cases against the declared corpus, keeping structural,
native-policy and runtime results separate. Preserve failure, unknown and missing
telemetry states. Roll back the exact reviewed control change while retaining
evidence; broad privilege or global bypass is not an automatic recovery path.

## Limitations and what was not tested

The local experiment does not validate the complete reference architecture, live
cloud enforcement, hosted CI, production data, independent audit storage or
representative adversarial coverage. Retained implementation and historical
source-inspection descriptions are not newly reproduced results. Review status
remains `requires-review` until a reviewer rechecks the retained product claims
against `validatedAgainst` and the linked evidence.

Time to detect, time to contain, population false-positive/negative rates, pipeline
impact and monthly operational cost are **not measured in this article**. Use the
[measurement contract](../research-methodology/evidence-standards.md#measurement-contract)
to define clocks, denominators, repeated workloads and residual capabilities before
claiming those outcomes. Report local fixture counts separately from live coverage.

## Open questions

Which parser, native-code or alternate-ingress path bypasses the selected runtime hook on the target kernel/version?

## References

- [Tetragon TracingPolicy API reference](https://tetragon.io/docs/reference/tracing-policy/)
- [Tetragon selector and action semantics](https://tetragon.io/docs/concepts/tracing-policy/selectors/)
- [Tetragon policy enforcement guide](https://tetragon.io/docs/getting-started/enforcement/)
- [Tetragon v1.7.0 release](https://github.com/cilium/tetragon/releases/tag/v1.7.0)
- [Tetragon v1.7.0 namespaced policy CRD](https://github.com/cilium/tetragon/blob/v1.7.0/install/kubernetes/tetragon/crds-yaml/cilium.io_tracingpoliciesnamespaced.yaml)
- [AWS WAF web ACL behavior and rule model](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl.html)
- [AWS WAF oversize request-component handling](https://docs.aws.amazon.com/waf/latest/developerguide/oversize-web-request-components.html)
- [OWASP ModSecurity Core Rule Set project](https://owasp.org/www-project-modsecurity-core-rule-set/)
