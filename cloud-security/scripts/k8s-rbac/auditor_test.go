package k8srbac_test

import (
	"strings"
	"testing"

	k8srbac "github.com/jasonachkar/cybersecurity-writeups/cloud-security/scripts/k8s-rbac"
)

func bindRole(ns, bindingName, roleName string, subjects ...string) k8srbac.BindingLike {
	return k8srbac.BindingLike{
		Kind:      "RoleBinding",
		Name:      bindingName,
		Namespace: ns,
		RoleRef:   k8srbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: roleName},
		Subjects:  subjects,
	}
}

func bindClusterRoleViaRoleBinding(ns, bindingName, clusterRoleName string, subjects ...string) k8srbac.BindingLike {
	return k8srbac.BindingLike{
		Kind:      "RoleBinding",
		Name:      bindingName,
		Namespace: ns,
		RoleRef:   k8srbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: clusterRoleName},
		Subjects:  subjects,
	}
}

func bindClusterRole(bindingName, clusterRoleName string, subjects ...string) k8srbac.BindingLike {
	return k8srbac.BindingLike{
		Kind:     "ClusterRoleBinding",
		Name:     bindingName,
		RoleRef:  k8srbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: clusterRoleName},
		Subjects: subjects,
	}
}

func findingsWithCode(findings []k8srbac.Finding, code string) []k8srbac.Finding {
	var out []k8srbac.Finding
	for _, finding := range findings {
		if finding.Code == code {
			out = append(out, finding)
		}
	}
	return out
}

func TestWildcardAPIGroupResourcesAndVerbs(t *testing.T) {
	roles := []k8srbac.RoleLike{{
		Kind: "ClusterRole",
		Name: "superuser",
		Rules: []k8srbac.PolicyRule{{
			APIGroups: []string{"*"},
			Resources: []string{"*"},
			Verbs:     []string{"*"},
		}},
	}}
	bindings := []k8srbac.BindingLike{bindClusterRole("bind", "superuser", "system:serviceaccount:kube-system:admin")}
	findings := k8srbac.Audit(roles, bindings)

	if !k8srbac.HasCode(findings, "all-resources-all-verbs") {
		t.Fatalf("expected all-resources-all-verbs, got %#v", findings)
	}
	// Derived risk classes should also evaluate under full wildcards.
	for _, code := range []string{"sa-token-create", "secrets-read", "pod-interactive", "rbac-bind-escalate"} {
		if !k8srbac.HasCode(findings, code) {
			t.Fatalf("expected derived risk %s under wildcards, got %#v", code, findings)
		}
	}
	got := findingsWithCode(findings, "all-resources-all-verbs")
	if got[0].Severity != "critical" {
		t.Fatalf("severity = %q, want critical", got[0].Severity)
	}
}

func TestSameRoleNameDifferentNamespaces(t *testing.T) {
	roles := []k8srbac.RoleLike{
		{
			Kind:      "Role",
			Name:      "reader",
			Namespace: "alpha",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get"},
			}},
		},
		{
			Kind:      "Role",
			Name:      "reader",
			Namespace: "beta",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"create"},
			}},
		},
	}
	bindings := []k8srbac.BindingLike{
		bindRole("alpha", "a", "reader", "system:serviceaccount:alpha:sa"),
		bindRole("beta", "b", "reader", "system:serviceaccount:beta:sa"),
	}
	findings := k8srbac.Audit(roles, bindings)

	secretFindings := findingsWithCode(findings, "secrets-read")
	if len(secretFindings) != 1 {
		t.Fatalf("secrets-read findings = %#v", secretFindings)
	}
	if secretFindings[0].RoleKey.Namespace != "alpha" || secretFindings[0].BindingScope != "alpha" {
		t.Fatalf("secrets finding keyed wrong: %#v", secretFindings[0])
	}

	podFindings := findingsWithCode(findings, "pod-create")
	if len(podFindings) != 1 {
		t.Fatalf("pod-create findings = %#v", podFindings)
	}
	if podFindings[0].RoleKey.Namespace != "beta" || podFindings[0].BindingScope != "beta" {
		t.Fatalf("pod finding keyed wrong: %#v", podFindings[0])
	}
}

func TestRoleBindingReferencesRole(t *testing.T) {
	roles := []k8srbac.RoleLike{{
		Kind:      "Role",
		Name:      "secret-reader",
		Namespace: "app",
		Rules: []k8srbac.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get"},
		}},
	}}
	bindings := []k8srbac.BindingLike{
		bindRole("app", "bind", "secret-reader", "system:serviceaccount:app:worker"),
	}
	findings := k8srbac.Audit(roles, bindings)
	got := findingsWithCode(findings, "secrets-read")
	if len(got) != 1 {
		t.Fatalf("expected one secrets-read finding, got %#v", findings)
	}
	if got[0].RoleKey != (k8srbac.RoleKey{Kind: "Role", Namespace: "app", Name: "secret-reader"}) {
		t.Fatalf("RoleKey = %#v", got[0].RoleKey)
	}
	if got[0].BindingKind != "RoleBinding" || got[0].BindingScope != "app" {
		t.Fatalf("binding metadata = %#v", got[0])
	}
}

func TestRoleBindingReferencesClusterRole(t *testing.T) {
	roles := []k8srbac.RoleLike{{
		Kind: "ClusterRole",
		Name: "secret-reader",
		Rules: []k8srbac.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"list"},
		}},
	}}
	bindings := []k8srbac.BindingLike{
		bindClusterRoleViaRoleBinding("team", "bind", "secret-reader", "system:serviceaccount:team:worker"),
	}
	findings := k8srbac.Audit(roles, bindings)
	got := findingsWithCode(findings, "secrets-read")
	if len(got) != 1 {
		t.Fatalf("expected secrets-read, got %#v", findings)
	}
	if got[0].RoleKey.Kind != "ClusterRole" || got[0].RoleKey.Namespace != "" {
		t.Fatalf("RoleKey = %#v", got[0].RoleKey)
	}
	if got[0].BindingScope != "team" {
		t.Fatalf("BindingScope = %q, want team (namespaced grant of cluster role)", got[0].BindingScope)
	}
}

func TestClusterRoleBindingReferencesClusterRole(t *testing.T) {
	roles := []k8srbac.RoleLike{{
		Kind: "ClusterRole",
		Name: "node-proxy",
		Rules: []k8srbac.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"nodes/proxy"},
			Verbs:     []string{"get"},
		}},
	}}
	bindings := []k8srbac.BindingLike{
		bindClusterRole("bind", "node-proxy", "system:serviceaccount:kube-system:proxy"),
	}
	findings := k8srbac.Audit(roles, bindings)
	got := findingsWithCode(findings, "nodes-proxy")
	if len(got) != 1 {
		t.Fatalf("expected nodes-proxy, got %#v", findings)
	}
	if got[0].BindingKind != "ClusterRoleBinding" || got[0].BindingScope != "cluster" {
		t.Fatalf("binding metadata = %#v", got[0])
	}
}

func TestInvalidClusterRoleBindingToRole(t *testing.T) {
	roles := []k8srbac.RoleLike{{
		Kind:      "Role",
		Name:      "local",
		Namespace: "app",
		Rules: []k8srbac.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get"},
		}},
	}}
	bindings := []k8srbac.BindingLike{{
		Kind: "ClusterRoleBinding",
		Name: "bad",
		RoleRef: k8srbac.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "local",
		},
		Subjects: []string{"user:attacker"},
	}}
	findings := k8srbac.Audit(roles, bindings)
	if !k8srbac.HasCode(findings, "invalid-binding") {
		t.Fatalf("expected invalid-binding, got %#v", findings)
	}
	if k8srbac.HasCode(findings, "secrets-read") {
		t.Fatal("invalid ClusterRoleBinding→Role must not evaluate Role rules")
	}
}

func TestNamespaceLimitedClusterRoleViaRoleBinding(t *testing.T) {
	roles := []k8srbac.RoleLike{{
		Kind: "ClusterRole",
		Name: "pod-creator",
		Rules: []k8srbac.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"create"},
		}},
	}}
	bindings := []k8srbac.BindingLike{
		bindClusterRoleViaRoleBinding("payments", "ns-grant", "pod-creator", "system:serviceaccount:payments:ci"),
	}
	findings := k8srbac.Audit(roles, bindings)
	got := findingsWithCode(findings, "pod-create")
	if len(got) != 1 {
		t.Fatalf("expected pod-create, got %#v", findings)
	}
	if got[0].BindingScope != "payments" {
		t.Fatalf("BindingScope = %q, want payments", got[0].BindingScope)
	}
	if got[0].RoleKey.Kind != "ClusterRole" {
		t.Fatalf("RoleKey.Kind = %q, want ClusterRole", got[0].RoleKey.Kind)
	}
}

func TestResourceNamesPreserved(t *testing.T) {
	roles := []k8srbac.RoleLike{{
		Kind: "ClusterRole",
		Name: "signer",
		Rules: []k8srbac.PolicyRule{{
			APIGroups:     []string{"certificates.k8s.io"},
			Resources:     []string{"signers"},
			ResourceNames: []string{"kubernetes.io/kubelet-serving"},
			Verbs:         []string{"approve"},
		}},
	}}
	bindings := []k8srbac.BindingLike{
		bindClusterRole("bind", "signer", "system:serviceaccount:kube-system:csr"),
	}
	findings := k8srbac.Audit(roles, bindings)
	got := findingsWithCode(findings, "csr-signer-approve")
	if len(got) != 1 {
		t.Fatalf("expected csr-signer-approve, got %#v", findings)
	}
	if len(got[0].ResourceNames) != 1 || got[0].ResourceNames[0] != "kubernetes.io/kubelet-serving" {
		t.Fatalf("ResourceNames = %#v", got[0].ResourceNames)
	}
	if !strings.Contains(got[0].Description, "resourceNames") {
		t.Fatalf("description must mention resourceNames constraint: %q", got[0].Description)
	}
	if strings.Contains(strings.ToLower(got[0].Description), "safe") &&
		!strings.Contains(got[0].Description, "do not make the permission safe") {
		t.Fatalf("must not claim resourceNames makes permission safe: %q", got[0].Description)
	}
}

func TestUnresolvedRoleReferences(t *testing.T) {
	bindings := []k8srbac.BindingLike{
		bindRole("app", "missing-role", "no-such-role", "system:serviceaccount:app:sa"),
		bindClusterRole("missing-cr", "no-such-clusterrole", "user:admin"),
	}
	findings := k8srbac.Audit(nil, bindings)
	unresolved := findingsWithCode(findings, "unresolved-role-ref")
	if len(unresolved) != 2 {
		t.Fatalf("expected 2 unresolved-role-ref findings, got %#v", findings)
	}
}

func TestDuplicateBindingsSubjectDedup(t *testing.T) {
	roles := []k8srbac.RoleLike{{
		Kind:      "Role",
		Name:      "secret-reader",
		Namespace: "app",
		Rules: []k8srbac.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get"},
		}},
	}}
	bindings := []k8srbac.BindingLike{
		{
			Kind:      "RoleBinding",
			Name:      "bind",
			Namespace: "app",
			RoleRef:   k8srbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "secret-reader"},
			Subjects:  []string{"user:a", "user:a", "user:b"},
		},
		{
			Kind:      "RoleBinding",
			Name:      "bind",
			Namespace: "app",
			RoleRef:   k8srbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "secret-reader"},
			Subjects:  []string{"user:b", "user:c"},
		},
	}
	findings := k8srbac.Audit(roles, bindings)
	got := findingsWithCode(findings, "secrets-read")
	if len(got) != 1 {
		t.Fatalf("expected merged secrets-read finding, got %#v", findings)
	}
	if len(got[0].Subjects) != 3 {
		t.Fatalf("subjects = %#v, want 3 unique", got[0].Subjects)
	}
	joined := strings.Join(got[0].Subjects, ",")
	if joined != "user:a,user:b,user:c" {
		t.Fatalf("subjects = %q", joined)
	}
}

func TestRiskClasses(t *testing.T) {
	tests := []struct {
		name    string
		role    k8srbac.RoleLike
		want    string
		notWant string
	}{
		{
			name: "serviceaccounts token create",
			role: k8srbac.RoleLike{Kind: "Role", Name: "r", Namespace: "ns", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts/token"},
				Verbs:     []string{"create"},
			}}},
			want: "sa-token-create",
		},
		{
			name: "CSR approval subresource",
			role: k8srbac.RoleLike{Kind: "Role", Name: "r", Namespace: "ns", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"certificates.k8s.io"},
				Resources: []string{"certificatesigningrequests/approval"},
				Verbs:     []string{"update"},
			}}},
			want: "csr-approval",
		},
		{
			name: "CSR create alone is not approval",
			role: k8srbac.RoleLike{Kind: "Role", Name: "r", Namespace: "ns", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"certificates.k8s.io"},
				Resources: []string{"certificatesigningrequests"},
				Verbs:     []string{"create", "update", "patch"},
			}}},
			notWant: "csr-approval",
		},
		{
			name: "signer approve",
			role: k8srbac.RoleLike{Kind: "ClusterRole", Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups:     []string{"certificates.k8s.io"},
				Resources:     []string{"signers"},
				ResourceNames: []string{"kubernetes.io/kubelet-serving"},
				Verbs:         []string{"approve"},
			}}},
			want: "csr-signer-approve",
		},
		{
			name: "tokenreviews is oracle not minting",
			role: k8srbac.RoleLike{Kind: "ClusterRole", Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			}}},
			want: "tokenreview-oracle",
		},
		{
			name: "impersonate users",
			role: k8srbac.RoleLike{Kind: "ClusterRole", Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"users"},
				Verbs:     []string{"impersonate"},
			}}},
			want: "impersonate",
		},
		{
			name: "bind escalate",
			role: k8srbac.RoleLike{Kind: "ClusterRole", Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
				Verbs:     []string{"bind", "escalate"},
			}}},
			want: "rbac-bind-escalate",
		},
		{
			name: "workload controller mutate",
			role: k8srbac.RoleLike{Kind: "Role", Name: "r", Namespace: "ns", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
				Verbs:     []string{"create", "patch"},
			}}},
			want: "workload-controller-mutate",
		},
		{
			name: "pod create heuristic",
			role: k8srbac.RoleLike{Kind: "Role", Name: "r", Namespace: "ns", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"create"},
			}}},
			want: "pod-create",
		},
		{
			name: "pods exec",
			role: k8srbac.RoleLike{Kind: "Role", Name: "r", Namespace: "ns", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"pods/exec"},
				Verbs:     []string{"create"},
			}}},
			want: "pod-interactive",
		},
		{
			name: "bare pods get is not interactive",
			role: k8srbac.RoleLike{Kind: "Role", Name: "r", Namespace: "ns", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			}}},
			notWant: "pod-interactive",
		},
		{
			name: "secrets read",
			role: k8srbac.RoleLike{Kind: "Role", Name: "r", Namespace: "ns", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "list"},
			}}},
			want: "secrets-read",
		},
		{
			name: "nodes proxy",
			role: k8srbac.RoleLike{Kind: "ClusterRole", Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"nodes/proxy"},
				Verbs:     []string{"get", "create"},
			}}},
			want: "nodes-proxy",
		},
		{
			name: "admission webhook mutate",
			role: k8srbac.RoleLike{Kind: "ClusterRole", Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"admissionregistration.k8s.io"},
				Resources: []string{"mutatingwebhookconfigurations"},
				Verbs:     []string{"update"},
			}}},
			want: "admission-policy-mutate",
		},
		{
			name: "wildcard resources with read verbs",
			role: k8srbac.RoleLike{Kind: "Role", Name: "r", Namespace: "ns", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"*"},
				Verbs:     []string{"get"},
			}}},
			want: "secrets-read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var binding k8srbac.BindingLike
			if tt.role.Kind == "ClusterRole" || tt.role.Namespace == "" {
				tt.role.Kind = "ClusterRole"
				tt.role.Namespace = ""
				binding = bindClusterRole("b", tt.role.Name, "user:test")
			} else {
				binding = bindRole(tt.role.Namespace, "b", tt.role.Name, "user:test")
			}
			findings := k8srbac.Audit([]k8srbac.RoleLike{tt.role}, []k8srbac.BindingLike{binding})
			if tt.want != "" && !k8srbac.HasCode(findings, tt.want) {
				t.Fatalf("missing %s in %#v", tt.want, findings)
			}
			if tt.notWant != "" && k8srbac.HasCode(findings, tt.notWant) {
				t.Fatalf("unexpected %s in %#v", tt.notWant, findings)
			}
		})
	}
}
