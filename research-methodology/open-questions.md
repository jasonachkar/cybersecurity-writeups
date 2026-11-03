# Open research questions

These are proposed experiments, not findings. All use owned local targets or a
separately authorized disposable cloud environment. Record the full case corpus
and preserve failed hypotheses as well as successful controls.

| Area | Specific question | Experiment and falsifier |
| --- | --- | --- |
| Cloud federation | Can an environment-bound role distinguish an unapproved branch when the subject contains only the environment? | Negative exchanges across branch/environment pairs after configuring protection rules; an unapproved exchange refutes the assumed protection |
| Cloud identity | How long can an already issued session act after trust is removed? | Record exchange, trust change and repeated bounded reads; continued access disproves immediate revocation |
| Kubernetes | Does the selected CNI block same-node, cross-node and IPv6 traffic under the same policy? | Isolated kind/CNI matrix with positive controls; any forbidden connection is a gap |
| Kubernetes | Can tenant RBAC modify the admission or service-account boundary it relies on? | Negative API calls with an actual tenant identity; a successful mutation refutes isolation |
| API authorization | Do bulk export and agent wrappers enforce the same tenant/object/action predicate as CRUD? | Endpoint × principal × tenant × object matrix; a single unauthorized returned or mutated row refutes consistency |
| API authorization | Can a pooled connection preserve tenant context after an exception? | Reuse one connection after commit, rollback and cancellation; foreign rows refute context lifetime |
| AI agents and MCP | Does a validated hostname stay bound to its vetted address when DNS changes? | Controlled resolver returning public then private answers plus connection observation; a second resolution is a potential gap |
| AI agents and MCP | Can a model-influenced tool input broaden authority beyond the verified user's grants? | Tool wrappers and direct calls with identical sessions; a wrapper-only success is a delegation defect |
| Supply chain | Can a compromised build replace both the report and its claimed verifier result? | Tamper with evidence at the release boundary; acceptance refutes independence |
| DevSecOps | Can an authorized deployment role persist by editing workflow, federation or runtime code? | Enumerate update APIs and deny cases; a successful identity/workflow change refutes the proposed boundary |
| Detection | Does the detector distinguish failed IAM attempts from successful changes? | Labeled error/success fixtures and duplicate delivery; compare exact expected alerts |
| Detection | Can loss of source telemetry be detected when the SIEM query itself is healthy? | Stop synthetic delivery and keep the query running; absent freshness alert refutes end-to-end coverage |
| Privacy | Can denied-attempt logs retain useful correlation without URLs, tokens or document content? | Seed sentinel data through each input/error path and scan all logs; retained sentinel data refutes minimization |
| Privacy | Does deletion of a tenant remove exported and queued copies within the declared retention window? | Local queue/cache/archive inventory before and after deletion; remaining undeclared copies refute the lifecycle claim |

Time to detect, time to contain, production false-positive rates and monthly cloud
cost are **not measured** by this question list. Each future experiment must name
its clock, denominator, workload and independent observer.

## References

- [Evidence and measurement contract](evidence-standards.md)
- [Vulnerability-research methodology](../vulnerability-research/methodology.md)
