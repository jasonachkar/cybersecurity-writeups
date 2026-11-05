# Offline manifest policy for labs/kubernetes-security. Evaluated with `opa eval`
# against {"objects": [...]} built from a directory of manifests; no cluster needed.
#
# Two entry points, because they answer different questions:
#   pod_violations     - properties of a single pod spec (admission-style)
#   policy_violations  - properties of a manifest SET: RBAC, namespaces, NetworkPolicy
#   deny               - both
package lab.k8s.workload

import rego.v1

controllers := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}

# ---- normalised pod specs --------------------------------------------------------

pods contains p if {
	some o in input.objects
	o.kind == "Pod"
	p := {"id": sprintf("Pod/%s", [o.metadata.name]), "ns": object.get(o.metadata, "namespace", "default"), "spec": o.spec, "meta": o.metadata}
}

pods contains p if {
	some o in input.objects
	o.kind in controllers
	p := {"id": sprintf("%s/%s", [o.kind, o.metadata.name]), "ns": object.get(o.metadata, "namespace", "default"), "spec": o.spec.template.spec, "meta": object.get(o.spec.template, "metadata", {})}
}

containers(spec) := array.concat(
	array.concat(object.get(spec, "containers", []), object.get(spec, "initContainers", [])),
	object.get(spec, "ephemeralContainers", []),
)

sc(x) := object.get(x, "securityContext", {})

violation(rule, id, msg) := {"rule": rule, "object": id, "message": msg}

# ---- pod-level rules ---------------------------------------------------------------

pod_violations contains violation("privileged", p.id, "container runs privileged") if {
	some p in pods
	some c in containers(p.spec)
	sc(c).privileged == true
}

pod_violations contains violation("host-namespace", p.id, sprintf("%s is true", [f])) if {
	some p in pods
	some f in ["hostNetwork", "hostPID", "hostIPC"]
	p.spec[f] == true
}

pod_violations contains violation("hostpath", p.id, "hostPath volume") if {
	some p in pods
	some v in object.get(p.spec, "volumes", [])
	v.hostPath
}

effective_run_as_non_root(spec, c) := object.get(sc(c), "runAsNonRoot", object.get(sc(spec), "runAsNonRoot", false))

effective_uid(spec, c) := object.get(sc(c), "runAsUser", object.get(sc(spec), "runAsUser", -1))

pod_violations contains violation("run-as-root", p.id, sprintf("container %s may run as root", [c.name])) if {
	some p in pods
	some c in containers(p.spec)
	not effective_run_as_non_root(p.spec, c) == true
}

pod_violations contains violation("run-as-root", p.id, sprintf("container %s runs as uid 0", [c.name])) if {
	some p in pods
	some c in containers(p.spec)
	effective_uid(p.spec, c) == 0
}

pod_violations contains violation("privilege-escalation", p.id, sprintf("container %s does not set allowPrivilegeEscalation=false", [c.name])) if {
	some p in pods
	some c in containers(p.spec)
	not object.get(sc(c), "allowPrivilegeEscalation", true) == false
}

pod_violations contains violation("capabilities", p.id, sprintf("container %s does not drop ALL capabilities", [c.name])) if {
	some p in pods
	some c in containers(p.spec)
	not "ALL" in object.get(object.get(sc(c), "capabilities", {}), "drop", [])
}

pod_violations contains violation("capabilities", p.id, sprintf("container %s adds capabilities", [c.name])) if {
	some p in pods
	some c in containers(p.spec)
	count(object.get(object.get(sc(c), "capabilities", {}), "add", [])) > 0
}

seccomp_ok(spec, c) if object.get(object.get(sc(c), "seccompProfile", {}), "type", "") in {"RuntimeDefault", "Localhost"}

seccomp_ok(spec, c) if {
	not object.get(sc(c), "seccompProfile", false)
	object.get(object.get(sc(spec), "seccompProfile", {}), "type", "") in {"RuntimeDefault", "Localhost"}
}

pod_violations contains violation("seccomp", p.id, sprintf("container %s has no RuntimeDefault or Localhost seccomp profile", [c.name])) if {
	some p in pods
	some c in containers(p.spec)
	not seccomp_ok(p.spec, c)
}

pod_violations contains violation("resource-limits", p.id, sprintf("container %s lacks cpu or memory limits", [c.name])) if {
	some p in pods
	some c in containers(p.spec)
	limits := object.get(object.get(c, "resources", {}), "limits", {})
	not limits.cpu
}

pod_violations contains violation("resource-limits", p.id, sprintf("container %s lacks cpu or memory limits", [c.name])) if {
	some p in pods
	some c in containers(p.spec)
	limits := object.get(object.get(c, "resources", {}), "limits", {})
	not limits.memory
}

pod_violations contains violation("resource-limits", p.id, sprintf("container %s has no resources block", [c.name])) if {
	some p in pods
	some c in containers(p.spec)
	not c.resources
}

pod_violations contains violation("image-tag", p.id, sprintf("image %s is not digest-pinned and has no explicit non-latest tag", [c.image])) if {
	some p in pods
	some c in containers(p.spec)
	not image_pinned(c.image)
}

image_pinned(image) if contains(image, "@sha256:")

image_pinned(image) if {
	regex.match(`^[^@]*:[^:/@]+$`, image)
	not endswith(image, ":latest")
}

pod_violations contains violation("read-only-rootfs", p.id, sprintf("container %s has a writable root filesystem", [c.name])) if {
	some p in pods
	some c in containers(p.spec)
	not object.get(sc(c), "readOnlyRootFilesystem", false) == true
}

# A pod has an API token if it projects one explicitly, or if automounting is not
# explicitly disabled (the default is true). The offline view must model the
# default because the ServiceAccount admission plugin injects the volume later.
token_present(spec) if {
	some v in object.get(spec, "volumes", [])
	some s in object.get(object.get(v, "projected", {}), "sources", [])
	s.serviceAccountToken
}

token_present(spec) if not object.get(spec, "automountServiceAccountToken", true) == false

token_approved(p) if {
	object.get(object.get(p.meta, "labels", {}), "lab.example/api-access", "") == "approved"
	object.get(p.spec, "serviceAccountName", "default") != "default"
}

pod_violations contains violation("service-account-token", p.id, "API token present without reviewed approval label and non-default ServiceAccount") if {
	some p in pods
	token_present(p.spec)
	not token_approved(p)
}

# ---- manifest-set rules -----------------------------------------------------------

namespaces_with_workloads contains p.ns if some p in pods

policy_violations contains violation("psa-enforce", sprintf("Namespace/%s", [ns]), "namespace with workloads does not enforce baseline or restricted Pod Security") if {
	some ns in namespaces_with_workloads
	not psa_enforced(ns)
}

psa_enforced(ns) if {
	some o in input.objects
	o.kind == "Namespace"
	o.metadata.name == ns
	o.metadata.labels["pod-security.kubernetes.io/enforce"] in {"baseline", "restricted"}
}

policy_violations contains violation("default-deny-network", sprintf("Namespace/%s", [ns]), "namespace with workloads has no default-deny ingress+egress NetworkPolicy") if {
	some ns in namespaces_with_workloads
	not default_deny(ns)
}

default_deny(ns) if {
	some o in input.objects
	o.kind == "NetworkPolicy"
	object.get(o.metadata, "namespace", "default") == ns
	count(object.get(o.spec, "podSelector", {"x": 1})) == 0
	{"Ingress", "Egress"} == {t | some t in object.get(o.spec, "policyTypes", [])}
	count(object.get(o.spec, "ingress", [])) == 0
	count(object.get(o.spec, "egress", [])) == 0
}

rbac_rules contains r if {
	some o in input.objects
	o.kind in {"Role", "ClusterRole"}
	some rule in object.get(o, "rules", [])
	r := {"id": sprintf("%s/%s", [o.kind, o.metadata.name]), "kind": o.kind, "rule": rule}
}

policy_violations contains violation("rbac-wildcard", r.id, "rule uses a wildcard in verbs, resources or apiGroups") if {
	some r in rbac_rules
	some field in ["verbs", "resources", "apiGroups"]
	"*" in object.get(r.rule, field, [])
}

policy_violations contains violation("rbac-secrets-read", r.id, "cluster-wide read access to secrets") if {
	some r in rbac_rules
	r.kind == "ClusterRole"
	"secrets" in object.get(r.rule, "resources", [])
	some verb in ["get", "list", "watch"]
	verb in object.get(r.rule, "verbs", [])
}

policy_violations contains violation("rbac-exec", r.id, "pods/exec create allows code execution in other pods") if {
	some r in rbac_rules
	"pods/exec" in object.get(r.rule, "resources", [])
	"create" in object.get(r.rule, "verbs", [])
}

policy_violations contains violation("rbac-privilege-verbs", r.id, sprintf("grants %s", [verb])) if {
	some r in rbac_rules
	some verb in ["escalate", "bind", "impersonate"]
	verb in object.get(r.rule, "verbs", [])
}

policy_violations contains violation("rbac-binding-creation", r.id, "can create RoleBindings or ClusterRoleBindings") if {
	some r in rbac_rules
	some resource in ["rolebindings", "clusterrolebindings"]
	resource in object.get(r.rule, "resources", [])
	"create" in object.get(r.rule, "verbs", [])
}

policy_violations contains violation("rbac-cluster-admin", sprintf("%s/%s", [o.kind, o.metadata.name]), "binds cluster-admin") if {
	some o in input.objects
	o.kind in {"RoleBinding", "ClusterRoleBinding"}
	o.roleRef.name == "cluster-admin"
}

policy_violations contains violation("rbac-broad-subject", sprintf("%s/%s", [o.kind, o.metadata.name]), sprintf("binds broad subject %s", [s.name])) if {
	some o in input.objects
	o.kind in {"RoleBinding", "ClusterRoleBinding"}
	some s in object.get(o, "subjects", [])
	s.name in {"system:authenticated", "system:unauthenticated", "system:serviceaccounts"}
}

policy_violations contains violation("rbac-default-serviceaccount", sprintf("%s/%s", [o.kind, o.metadata.name]), "binds the default ServiceAccount") if {
	some o in input.objects
	o.kind in {"RoleBinding", "ClusterRoleBinding"}
	some s in object.get(o, "subjects", [])
	s.kind == "ServiceAccount"
	s.name == "default"
}

deny := pod_violations | policy_violations
