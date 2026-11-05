package lab.k8s.workload_test

import data.lab.k8s.workload
import rego.v1

good_pod := {
	"kind": "Pod",
	"metadata": {"name": "good", "namespace": "ns"},
	"spec": {
		"serviceAccountName": "app",
		"automountServiceAccountToken": false,
		"securityContext": {"runAsNonRoot": true, "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
		"containers": [{
			"name": "c",
			"image": "registry.example/app:1.2.3",
			"securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}},
			"resources": {"limits": {"cpu": "1", "memory": "64Mi"}},
		}],
	},
}

rules_for(objects) := {v.rule | some v in workload.pod_violations with input as {"objects": objects}}

# Replace (not merge) one key of the first container; object.union would keep old nested values.
set_container(pod, key, value) := object.union(pod, {"spec": {"containers": [object.union(object.remove(pod.spec.containers[0], [key]), {key: value})]}})

test_good_pod_has_no_pod_violations if {
	count(rules_for([good_pod])) == 0
}

test_privileged_flagged if {
	pod := set_container(good_pod, "securityContext", {"privileged": true, "allowPrivilegeEscalation": true, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}})
	"privileged" in rules_for([pod])
}

test_missing_limits_flagged if {
	pod := set_container(good_pod, "resources", {})
	"resource-limits" in rules_for([pod])
}

test_latest_and_untagged_flagged if {
	"image-tag" in rules_for([set_container(good_pod, "image", "registry.example/app:latest")])
	"image-tag" in rules_for([set_container(good_pod, "image", "registry.example/app")])
	"image-tag" in rules_for([set_container(good_pod, "image", "registry.example:5000/app")])
}

test_digest_pin_accepted if {
	pinned := set_container(good_pod, "image", "registry.example/app@sha256:0000000000000000000000000000000000000000000000000000000000000000")
	not "image-tag" in rules_for([pinned])
}

test_uid_zero_flagged_even_when_run_as_non_root_is_true if {
	pod := object.union(good_pod, {"spec": {"securityContext": {"runAsUser": 0}}})
	"run-as-root" in rules_for([pod])
}

test_defaulted_token_flagged if {
	pod := json.remove(good_pod, ["spec/automountServiceAccountToken"])
	"service-account-token" in rules_for([pod])
}

test_token_needs_label_and_non_default_serviceaccount if {
	labelled := object.union(good_pod, {"metadata": {"labels": {"lab.example/api-access": "approved"}}, "spec": {"automountServiceAccountToken": true}})
	not "service-account-token" in rules_for([labelled])
	default_sa := object.union(labelled, {"spec": {"serviceAccountName": "default"}})
	"service-account-token" in rules_for([default_sa])
}

test_workload_controller_template_is_inspected if {
	deployment := {"kind": "Deployment", "metadata": {"name": "d", "namespace": "ns"}, "spec": {"template": {"metadata": {}, "spec": good_pod.spec}}}
	count(rules_for([deployment])) == 0
	bad := {"kind": "Deployment", "metadata": {"name": "d", "namespace": "ns"}, "spec": {"template": {"metadata": {}, "spec": object.union(good_pod.spec, {"hostNetwork": true})}}}
	"host-namespace" in rules_for([bad])
}

policy_rules(objects) := {v.rule | some v in workload.policy_violations with input as {"objects": objects}}

test_default_deny_must_have_no_rules if {
	ns := {"kind": "Namespace", "metadata": {"name": "ns", "labels": {"pod-security.kubernetes.io/enforce": "restricted"}}}
	deny_all := {"kind": "NetworkPolicy", "metadata": {"name": "d", "namespace": "ns"}, "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}}
	not "default-deny-network" in policy_rules([ns, good_pod, deny_all])

	# Selecting every pod but allowing all egress is NOT a default deny.
	leaky := object.union(deny_all, {"spec": {"egress": [{}]}})
	"default-deny-network" in policy_rules([ns, good_pod, leaky])

	# Ingress-only default deny leaves egress open.
	ingress_only := object.union(deny_all, {"spec": {"policyTypes": ["Ingress"]}})
	"default-deny-network" in policy_rules([ns, good_pod, ingress_only])
}

test_privileged_namespace_flagged if {
	ns := {"kind": "Namespace", "metadata": {"name": "ns", "labels": {"pod-security.kubernetes.io/enforce": "privileged"}}}
	"psa-enforce" in policy_rules([ns, good_pod])
	"psa-enforce" in policy_rules([good_pod])
}

test_rbac_findings if {
	wildcard := {"kind": "ClusterRole", "metadata": {"name": "w"}, "rules": [{"apiGroups": [""], "resources": ["*"], "verbs": ["get"]}]}
	"rbac-wildcard" in policy_rules([wildcard])
	secrets := {"kind": "ClusterRole", "metadata": {"name": "s"}, "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}]}
	"rbac-secrets-read" in policy_rules([secrets])

	# The same read, scoped to one named object in a Role, is not flagged.
	scoped := {"kind": "Role", "metadata": {"name": "r", "namespace": "ns"}, "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["one"], "verbs": ["get"]}]}
	count(policy_rules([scoped])) == 0
	admin := {"kind": "ClusterRoleBinding", "metadata": {"name": "a"}, "roleRef": {"name": "cluster-admin"}, "subjects": [{"kind": "ServiceAccount", "name": "default"}]}
	"rbac-cluster-admin" in policy_rules([admin])
	"rbac-default-serviceaccount" in policy_rules([admin])
}
