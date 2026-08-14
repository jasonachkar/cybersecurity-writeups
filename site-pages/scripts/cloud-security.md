# Cloud Security scripts

The cloud security scripts and packages I've written, with their source shown directly below — no need to open GitHub to read them.

<div id="k8s-rbac-auditor" class="section" aria-labelledby="k8s-rbac-auditor-heading">

## Kubernetes RBAC privilege-escalation auditor

<span class="docs-badge">Go</span><span class="docs-badge">Read-only</span><span class="docs-badge">Go test suite (48 cases)</span>

### What it does

It checks a batch of exported Role/ClusterRole and (Cluster)RoleBinding YAML for the RBAC patterns that lead to privilege escalation: binding scope mismatches (RoleBinding referencing a ClusterRole-only resource), and the special verbs (bind, escalate, impersonate) that let a principal grant itself more than its own role appears to allow.

### Why I wrote it

The Kubernetes isolation write-up kept coming back to the same question — does this binding actually grant what it looks like it grants? — so I wrote something that answers that mechanically instead of by eye.

### How it works

It indexes the supplied roles by kind/namespace/name, resolves each binding's roleRef against that index, and evaluates each PolicyRule against a small table of known built-in resource scopes plus the special-verb cases. Unknown or custom resources are never assigned a fabricated scope — they come back unknown rather than guessed.

### Requirements

- Go 1.22+
- No cluster or kubeconfig access — it never calls the Kubernetes API.

### Permissions and safety

None. It is a pure function over data structures you provide; it does not read files, make network calls, or need any credentials.

### Usage

    go test ./cloud-security/scripts/k8s-rbac/...

### Inputs

In-memory RoleLike / BindingLike values (in the shipped tests, built from fixture data). There is no CLI entry point today — it is a package you import or exercise via its test suite, not a standalone binary.

### Outputs

A \[\]Finding slice describing each risky binding: the role, the binding scope, and a human-readable reason.

### What I tested

The 48 test cases in auditor_test.go cover both roles that should be flagged and roles that should come back clean, across ordinary resources, the special verbs, and unresolved/unknown bindings.

### Limitations

- This is a static heuristic over role/binding objects you hand it, not a full effective-permissions engine.
- It does not evaluate SubjectAccessReview, SelfSubjectRulesReview, aggregated ClusterRoles, admission policy, or live API discovery.
- It has no CLI or YAML-loading entry point yet — wiring in a real \`kubectl get -o yaml\` export is on my list, not something this does today.

### Related research

- Related research: [Kubernetes isolation](/cloud-security/kubernetes-multi-tenancy/)
- Related lab: [Kubernetes security lab](/labs/kubernetes-security/)

</div>
