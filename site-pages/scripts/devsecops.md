# DevSecOps scripts

The devsecops scripts and packages I've written, with their source shown directly below — no need to open GitHub to read them.

<div id="kyverno-policy-schema-check" class="section" aria-labelledby="kyverno-policy-schema-check-heading">

## Kyverno policy schema validator

<span class="docs-badge">Python</span><span class="docs-badge">Read-only</span><span class="docs-badge">Runs in CI against the pinned Kyverno v1.18.2 CRD</span>

### What it does

Checks a Kyverno ImageValidatingPolicy against the pinned Kyverno v1.18.2 CRD's structural schema — a quick way to catch a typo'd field or wrong apiVersion without needing a live cluster.

### Why I wrote it

I wanted some confidence the Kubernetes lab's policy YAML was structurally valid against the real CRD before I trusted it enough to keep in the repo, without standing up a cluster just to find out.

### How it works

It loads the CRD and the policy YAML, confirms the policy's apiVersion/kind actually match what the CRD serves, then runs the CRD's openAPIV3Schema through the \`jsonschema\` library against the policy document.

### Requirements

- Python 3
- jsonschema
- PyYAML
- A pinned copy of the target CRD's YAML

### Permissions and safety

None — it only reads the two local files you pass it. It never touches a cluster.

### Usage

    python scripts/validate-kyverno-policy.py <crd.yaml> <policy.yaml>

### Inputs

Two file paths: the CRD YAML and the policy YAML to check.

### Outputs

Exits cleanly (no output) on success; raises an AssertionError or a jsonschema.ValidationError with a description of the mismatch on failure.

### What I tested

Runs in CI against the fixtures in labs/kubernetes-security on every change.

### Limitations

- This is schema validation only — it says nothing about signature verification, registry access, transparency-log inclusion, or how the policy behaves under live admission.
- It validates structure against one pinned CRD version; a different Kyverno version may accept or reject different fields.

### Related research

- Related research: [Kubernetes isolation](/cloud-security/kubernetes-multi-tenancy/)
- Related lab: [Kubernetes security lab](/labs/kubernetes-security/)

</div>

<div id="tetragon-policy-schema-check" class="section" aria-labelledby="tetragon-policy-schema-check-heading">

## Tetragon policy schema validator

<span class="docs-badge">Python</span><span class="docs-badge">Read-only</span><span class="docs-badge">Runs in CI against the pinned Tetragon v1.7.0 CRD</span>

### What it does

The same idea as the Kyverno checker, aimed at Cilium Tetragon's TracingPolicyNamespaced CRD: catch a malformed eBPF tracing policy before it's ever pointed at a real cluster.

### Why I wrote it

Same reasoning as the Kyverno checker, applied to the runtime-protection write-up's Tetragon policy instead.

### How it works

Loads the CRD and policy YAML, confirms apiVersion/kind/scope line up with what the CRD declares, then validates the policy against the CRD's openAPIV3Schema with \`jsonschema\`. Kubernetes CRD structural schemas are a restricted subset of JSON Schema, so this is a faithful offline check.

### Requirements

- Python 3
- jsonschema
- PyYAML
- A pinned copy of the target CRD's YAML

### Permissions and safety

None — reads the two local files only, no cluster access.

### Usage

    python scripts/validate-tetragon-policy.py <crd.yaml> <policy.yaml>

### Inputs

Two file paths: the CRD YAML and the policy YAML to check.

### Outputs

Exits cleanly on success; raises an assertion or validation error describing the mismatch on failure.

### What I tested

Runs in CI against the published policy in appsec/runtime-protection-rasp-waf on every change.

### Limitations

- Schema validation only — not a live admission or enforcement test, and it says nothing about whether the eBPF program actually behaves as the policy describes at runtime.
- Tied to one pinned CRD version.

### Related research

- Related research: [Runtime protection (WAF/RASP/eBPF)](/appsec/runtime-protection-rasp-waf/)

</div>
