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
	for _, code := range []string{"sa-token-create", "secrets-read", "pod-interactive", "rbac-bind", "rbac-escalate", "impersonate"} {
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
			role: k8srbac.RoleLike{Kind: "ClusterRole", Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"certificates.k8s.io"},
				Resources: []string{"certificatesigningrequests/approval"},
				Verbs:     []string{"update"},
			}}},
			want: "csr-approval",
		},
		{
			name: "CSR create alone is not approval",
			role: k8srbac.RoleLike{Kind: "ClusterRole", Name: "r", Rules: []k8srbac.PolicyRule{{
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
			want: "rbac-bind",
		},
		{
			name: "escalate clusterroles",
			role: k8srbac.RoleLike{Kind: "ClusterRole", Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
				Verbs:     []string{"escalate"},
			}}},
			want: "rbac-escalate",
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

func assertHas(t *testing.T, findings []k8srbac.Finding, code string) {
	t.Helper()
	if !k8srbac.HasCode(findings, code) {
		t.Fatalf("missing %s in %#v", code, findings)
	}
}

func assertNotHas(t *testing.T, findings []k8srbac.Finding, codes ...string) {
	t.Helper()
	for _, code := range codes {
		if k8srbac.HasCode(findings, code) {
			t.Fatalf("unexpected false-positive %s in %#v", code, findings)
		}
	}
}

func TestBindingValidation(t *testing.T) {
	secretRole := k8srbac.RoleLike{
		Kind: "ClusterRole", Name: "secret-reader",
		Rules: []k8srbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}},
	}
	namespacedRole := k8srbac.RoleLike{
		Kind: "Role", Name: "secret-reader", Namespace: "app",
		Rules: []k8srbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}},
	}

	t.Run("RoleBinding Role resolves", func(t *testing.T) {
		findings := k8srbac.Audit([]k8srbac.RoleLike{namespacedRole}, []k8srbac.BindingLike{
			bindRole("app", "ok", "secret-reader", "user:a"),
		})
		assertHas(t, findings, "secrets-read")
		assertNotHas(t, findings, "invalid-binding")
	})
	t.Run("RoleBinding ClusterRole resolves", func(t *testing.T) {
		findings := k8srbac.Audit([]k8srbac.RoleLike{secretRole}, []k8srbac.BindingLike{
			bindClusterRoleViaRoleBinding("app", "ok", "secret-reader", "user:a"),
		})
		assertHas(t, findings, "secrets-read")
		assertNotHas(t, findings, "invalid-binding")
	})
	t.Run("ClusterRoleBinding ClusterRole resolves", func(t *testing.T) {
		findings := k8srbac.Audit([]k8srbac.RoleLike{secretRole}, []k8srbac.BindingLike{
			bindClusterRole("ok", "secret-reader", "user:a"),
		})
		assertHas(t, findings, "secrets-read")
		assertNotHas(t, findings, "invalid-binding")
	})

	cases := []struct {
		name    string
		roles   []k8srbac.RoleLike
		binding k8srbac.BindingLike
		wantMsg string
	}{
		{
			name:  "wrong apiGroup",
			roles: []k8srbac.RoleLike{secretRole},
			binding: k8srbac.BindingLike{
				Kind: "ClusterRoleBinding", Name: "bad",
				RoleRef:  k8srbac.RoleRef{APIGroup: "rbac.authorization.k8s.io.wrong", Kind: "ClusterRole", Name: "secret-reader"},
				Subjects: []string{"user:a"},
			},
			wantMsg: "roleRef.apiGroup must be rbac.authorization.k8s.io",
		},
		{
			name:  "empty apiGroup",
			roles: []k8srbac.RoleLike{secretRole},
			binding: k8srbac.BindingLike{
				Kind: "RoleBinding", Name: "bad", Namespace: "app",
				RoleRef:  k8srbac.RoleRef{APIGroup: "", Kind: "ClusterRole", Name: "secret-reader"},
				Subjects: []string{"user:a"},
			},
			wantMsg: "roleRef.apiGroup must be rbac.authorization.k8s.io",
		},
		{
			name:  "RoleBinding empty kind",
			roles: []k8srbac.RoleLike{secretRole},
			binding: k8srbac.BindingLike{
				Kind: "RoleBinding", Name: "bad", Namespace: "app",
				RoleRef:  k8srbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "", Name: "secret-reader"},
				Subjects: []string{"user:a"},
			},
			wantMsg: "RoleBinding roleRef.kind must be Role or ClusterRole",
		},
		{
			name:  "RoleBinding unknown kind",
			roles: []k8srbac.RoleLike{secretRole},
			binding: k8srbac.BindingLike{
				Kind: "RoleBinding", Name: "bad", Namespace: "app",
				RoleRef:  k8srbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ServiceAccount", Name: "secret-reader"},
				Subjects: []string{"user:a"},
			},
			wantMsg: "RoleBinding roleRef.kind must be Role or ClusterRole",
		},
		{
			name:  "ClusterRoleBinding references Role",
			roles: []k8srbac.RoleLike{namespacedRole},
			binding: k8srbac.BindingLike{
				Kind: "ClusterRoleBinding", Name: "bad",
				RoleRef:  k8srbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "secret-reader"},
				Subjects: []string{"user:a"},
			},
			wantMsg: "ClusterRoleBinding roleRef.kind must be ClusterRole",
		},
		{
			name:  "ClusterRoleBinding empty kind",
			roles: []k8srbac.RoleLike{secretRole},
			binding: k8srbac.BindingLike{
				Kind: "ClusterRoleBinding", Name: "bad",
				RoleRef:  k8srbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "", Name: "secret-reader"},
				Subjects: []string{"user:a"},
			},
			wantMsg: "ClusterRoleBinding roleRef.kind must be ClusterRole",
		},
		{
			name:  "ClusterRoleBinding unknown kind",
			roles: []k8srbac.RoleLike{secretRole},
			binding: k8srbac.BindingLike{
				Kind: "ClusterRoleBinding", Name: "bad",
				RoleRef:  k8srbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Pod", Name: "secret-reader"},
				Subjects: []string{"user:a"},
			},
			wantMsg: "ClusterRoleBinding roleRef.kind must be ClusterRole",
		},
		{
			name:  "RoleBinding missing namespace",
			roles: []k8srbac.RoleLike{secretRole},
			binding: k8srbac.BindingLike{
				Kind: "RoleBinding", Name: "bad", Namespace: "",
				RoleRef:  k8srbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "secret-reader"},
				Subjects: []string{"user:a"},
			},
			wantMsg: "RoleBinding requires a namespace",
		},
		{
			name:  "ClusterRoleBinding with namespace",
			roles: []k8srbac.RoleLike{secretRole},
			binding: k8srbac.BindingLike{
				Kind: "ClusterRoleBinding", Name: "bad", Namespace: "app",
				RoleRef:  k8srbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "secret-reader"},
				Subjects: []string{"user:a"},
			},
			wantMsg: "ClusterRoleBinding must not declare a namespace",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			findings := k8srbac.Audit(tt.roles, []k8srbac.BindingLike{tt.binding})
			got := findingsWithCode(findings, "invalid-binding")
			if len(got) != 1 {
				t.Fatalf("expected invalid-binding, got %#v", findings)
			}
			if !strings.Contains(got[0].Description, tt.wantMsg) {
				t.Fatalf("description = %q, want substring %q", got[0].Description, tt.wantMsg)
			}
			assertNotHas(t, findings, "secrets-read")
		})
	}
}

func TestRoleBindingDoesNotActivateClusterScopedRisks(t *testing.T) {
	tests := []struct {
		name    string
		rules   []k8srbac.PolicyRule
		notWant []string
		want    []string
	}{
		{
			name:    "nodes/proxy",
			rules:   []k8srbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"nodes/proxy"}, Verbs: []string{"get", "create"}}},
			notWant: []string{"nodes-proxy"},
		},
		{
			name:    "tokenreviews",
			rules:   []k8srbac.PolicyRule{{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{"create"}}},
			notWant: []string{"tokenreview-oracle"},
		},
		{
			name:    "csr approval",
			rules:   []k8srbac.PolicyRule{{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}}},
			notWant: []string{"csr-approval"},
		},
		{
			name:    "signers",
			rules:   []k8srbac.PolicyRule{{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"signers"}, Verbs: []string{"approve"}}},
			notWant: []string{"csr-signer-approve"},
		},
		{
			name: "clusterroles bind is effective; escalate is not",
			rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
				Verbs:     []string{"bind", "escalate"},
			}},
			want:    []string{"rbac-bind"},
			notWant: []string{"rbac-escalate"},
		},
		{
			name:    "admission webhooks",
			rules:   []k8srbac.PolicyRule{{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingwebhookconfigurations"}, Verbs: []string{"update"}}},
			notWant: []string{"admission-policy-mutate"},
		},
		{
			name:    "secrets still effective",
			rules:   []k8srbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}},
			want:    []string{"secrets-read"},
			notWant: []string{"nodes-proxy", "tokenreview-oracle"},
		},
		{
			name:  "pods/exec still effective",
			rules: []k8srbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}}},
			want:  []string{"pod-interactive"},
		},
		{
			name:  "serviceaccounts/token still effective",
			rules: []k8srbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, Verbs: []string{"create"}}},
			want:  []string{"sa-token-create"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roles := []k8srbac.RoleLike{{Kind: "ClusterRole", Name: "cr", Rules: tt.rules}}
			bindings := []k8srbac.BindingLike{
				bindClusterRoleViaRoleBinding("team", "ns-bind", "cr", "system:serviceaccount:team:sa"),
			}
			findings := k8srbac.Audit(roles, bindings)
			for _, code := range tt.want {
				assertHas(t, findings, code)
			}
			assertNotHas(t, findings, tt.notWant...)
		})
	}
}

func TestClusterRoleBindingActivatesClusterScopedRisks(t *testing.T) {
	roles := []k8srbac.RoleLike{{
		Kind: "ClusterRole",
		Name: "dangerous",
		Rules: []k8srbac.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"nodes/proxy"}, Verbs: []string{"get"}},
			{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{"create"}},
			{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}},
			{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"signers"}, Verbs: []string{"approve"}},
			{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"}, Verbs: []string{"bind"}},
			{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"mutatingwebhookconfigurations"}, Verbs: []string{"update"}},
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		},
	}}
	findings := k8srbac.Audit(roles, []k8srbac.BindingLike{
		bindClusterRole("cluster-bind", "dangerous", "user:admin"),
	})
	for _, code := range []string{
		"nodes-proxy", "tokenreview-oracle", "csr-approval", "csr-signer-approve",
		"rbac-bind", "admission-policy-mutate", "secrets-read",
	} {
		assertHas(t, findings, code)
	}
}

func TestNamespacedWildcardOmitsClusterScopedFindings(t *testing.T) {
	roles := []k8srbac.RoleLike{{
		Kind: "ClusterRole",
		Name: "wildcard",
		Rules: []k8srbac.PolicyRule{{
			APIGroups: []string{"*"},
			Resources: []string{"*"},
			Verbs:     []string{"*"},
		}},
	}}
	nsFindings := k8srbac.Audit(roles, []k8srbac.BindingLike{
		bindClusterRoleViaRoleBinding("app", "ns-wild", "wildcard", "system:serviceaccount:app:sa"),
	})
	assertHas(t, nsFindings, "all-resources-all-verbs")
	assertHas(t, nsFindings, "secrets-read")
	assertHas(t, nsFindings, "pod-interactive")
	assertHas(t, nsFindings, "sa-token-create")
	assertHas(t, nsFindings, "pod-create")
	assertHas(t, nsFindings, "workload-controller-mutate")
	// Special verbs: bind on roles/clusterroles and escalate on roles remain effective.
	assertHas(t, nsFindings, "rbac-bind")
	assertHas(t, nsFindings, "rbac-escalate")
	assertNotHas(t, nsFindings,
		"nodes-proxy", "tokenreview-oracle", "csr-approval", "csr-signer-approve",
		"admission-policy-mutate", "impersonate",
	)

	clusterFindings := k8srbac.Audit(roles, []k8srbac.BindingLike{
		bindClusterRole("cluster-wild", "wildcard", "user:admin"),
	})
	assertHas(t, clusterFindings, "all-resources-all-verbs")
	assertHas(t, clusterFindings, "secrets-read")
	assertHas(t, clusterFindings, "nodes-proxy")
	assertHas(t, clusterFindings, "tokenreview-oracle")
	assertHas(t, clusterFindings, "csr-approval")
	assertHas(t, clusterFindings, "admission-policy-mutate")
	assertHas(t, clusterFindings, "rbac-bind")
	assertHas(t, clusterFindings, "rbac-escalate")
	assertHas(t, clusterFindings, "impersonate")
}

func TestSpecialBindSemantics(t *testing.T) {
	t.Run("RoleBinding bind on clusterroles is effective in namespace", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "ClusterRole", Name: "binder",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
				Verbs:     []string{"bind"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{
			bindClusterRoleViaRoleBinding("payments", "ns-bind", "binder", "system:serviceaccount:payments:sa"),
		})
		got := findingsWithCode(findings, "rbac-bind")
		if len(got) != 1 {
			t.Fatalf("expected rbac-bind, got %#v", findings)
		}
		if got[0].BindingKind != "RoleBinding" || got[0].BindingScope != "payments" {
			t.Fatalf("binding metadata = %#v", got[0])
		}
		if !strings.Contains(got[0].Description, "bind on clusterroles") {
			t.Fatalf("description = %q", got[0].Description)
		}
		assertNotHas(t, findings, "rbac-escalate")
	})

	t.Run("RoleBinding bind on roles is effective", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "Role", Name: "binder", Namespace: "app",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"roles"},
				Verbs:     []string{"bind"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{
			bindRole("app", "b", "binder", "user:a"),
		})
		assertHas(t, findings, "rbac-bind")
		got := findingsWithCode(findings, "rbac-bind")
		if got[0].BindingScope != "app" {
			t.Fatalf("BindingScope = %q", got[0].BindingScope)
		}
	})

	t.Run("ClusterRoleBinding bind on clusterroles is effective", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "ClusterRole", Name: "binder",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
				Verbs:     []string{"bind"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{
			bindClusterRole("b", "binder", "user:a"),
		})
		got := findingsWithCode(findings, "rbac-bind")
		if len(got) != 1 || got[0].BindingKind != "ClusterRoleBinding" || got[0].BindingScope != "cluster" {
			t.Fatalf("unexpected finding %#v", findings)
		}
	})

	t.Run("bind on rolebindings is not a special binding risk", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "ClusterRole", Name: "binder",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"rolebindings"},
				Verbs:     []string{"bind"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{bindClusterRole("b", "binder", "user:a")})
		assertNotHas(t, findings, "rbac-bind", "rbac-escalate")
	})

	t.Run("bind on clusterrolebindings is not a special binding risk", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "ClusterRole", Name: "binder",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterrolebindings"},
				Verbs:     []string{"bind"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{bindClusterRole("b", "binder", "user:a")})
		assertNotHas(t, findings, "rbac-bind", "rbac-escalate")
	})

	t.Run("resourceNames retained for bind on clusterroles", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "ClusterRole", Name: "binder",
			Rules: []k8srbac.PolicyRule{{
				APIGroups:     []string{"rbac.authorization.k8s.io"},
				Resources:     []string{"clusterroles"},
				ResourceNames: []string{"view", "edit"},
				Verbs:         []string{"bind"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{
			bindClusterRoleViaRoleBinding("payments", "b", "binder", "user:a"),
		})
		got := findingsWithCode(findings, "rbac-bind")
		if len(got) != 1 {
			t.Fatalf("expected rbac-bind, got %#v", findings)
		}
		if len(got[0].ResourceNames) != 2 {
			t.Fatalf("ResourceNames = %#v", got[0].ResourceNames)
		}
		if !strings.Contains(got[0].Description, "resourceNames") ||
			!strings.Contains(got[0].Description, "does not make the permission safe") {
			t.Fatalf("description = %q", got[0].Description)
		}
	})
}

func TestSpecialEscalateSemantics(t *testing.T) {
	t.Run("RoleBinding escalate on roles is effective", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "Role", Name: "esc", Namespace: "app",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"roles"},
				Verbs:     []string{"escalate"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{bindRole("app", "b", "esc", "user:a")})
		assertHas(t, findings, "rbac-escalate")
		assertNotHas(t, findings, "rbac-bind")
	})

	t.Run("RoleBinding escalate on clusterroles is not effective", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "ClusterRole", Name: "esc",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
				Verbs:     []string{"escalate"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{
			bindClusterRoleViaRoleBinding("app", "b", "esc", "user:a"),
		})
		assertNotHas(t, findings, "rbac-escalate", "rbac-bind")
	})

	t.Run("ClusterRoleBinding escalate on clusterroles is effective", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "ClusterRole", Name: "esc",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
				Verbs:     []string{"escalate"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{bindClusterRole("b", "esc", "user:a")})
		assertHas(t, findings, "rbac-escalate")
	})

	t.Run("escalate on rolebindings is not a special escalation risk", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "ClusterRole", Name: "esc",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"rolebindings"},
				Verbs:     []string{"escalate"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{bindClusterRole("b", "esc", "user:a")})
		assertNotHas(t, findings, "rbac-escalate", "rbac-bind")
	})

	t.Run("escalate on clusterrolebindings is not a special escalation risk", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "ClusterRole", Name: "esc",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterrolebindings"},
				Verbs:     []string{"escalate"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{bindClusterRole("b", "esc", "user:a")})
		assertNotHas(t, findings, "rbac-escalate", "rbac-bind")
	})

	t.Run("RoleBinding bind+escalate on clusterroles reports only bind", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "ClusterRole", Name: "both",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
				Verbs:     []string{"bind", "escalate"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{
			bindClusterRoleViaRoleBinding("payments", "b", "both", "user:a"),
		})
		assertHas(t, findings, "rbac-bind")
		assertNotHas(t, findings, "rbac-escalate")
		got := findingsWithCode(findings, "rbac-bind")
		if strings.Contains(got[0].Description, "escalate") {
			t.Fatalf("bind finding must not use vague joined-verb wording: %q", got[0].Description)
		}
	})
}

func TestImpersonationScope(t *testing.T) {
	targets := []struct {
		name  string
		group string
	}{
		{"users", ""},
		{"groups", ""},
		{"serviceaccounts", ""},
		{"userextras", "authentication.k8s.io"},
	}

	for _, target := range targets {
		t.Run("RoleBinding impersonate "+target.name+" suppressed", func(t *testing.T) {
			roles := []k8srbac.RoleLike{{
				Kind: "ClusterRole", Name: "imp",
				Rules: []k8srbac.PolicyRule{{
					APIGroups: []string{target.group},
					Resources: []string{target.name},
					Verbs:     []string{"impersonate"},
				}},
			}}
			findings := k8srbac.Audit(roles, []k8srbac.BindingLike{
				bindClusterRoleViaRoleBinding("app", "b", "imp", "user:a"),
			})
			assertNotHas(t, findings, "impersonate")
		})

		t.Run("ClusterRoleBinding impersonate "+target.name+" effective", func(t *testing.T) {
			roles := []k8srbac.RoleLike{{
				Kind: "ClusterRole", Name: "imp",
				Rules: []k8srbac.PolicyRule{{
					APIGroups: []string{target.group},
					Resources: []string{target.name},
					Verbs:     []string{"impersonate"},
				}},
			}}
			findings := k8srbac.Audit(roles, []k8srbac.BindingLike{bindClusterRole("b", "imp", "user:a")})
			assertHas(t, findings, "impersonate")
		})
	}

	t.Run("userextras under core API group rejected", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "ClusterRole", Name: "imp",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"userextras"},
				Verbs:     []string{"impersonate"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{bindClusterRole("b", "imp", "user:a")})
		assertNotHas(t, findings, "impersonate")
	})

	t.Run("users under unrelated API group rejected", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "ClusterRole", Name: "imp",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"example.com"},
				Resources: []string{"users"},
				Verbs:     []string{"impersonate"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{bindClusterRole("b", "imp", "user:a")})
		assertNotHas(t, findings, "impersonate")
	})

	t.Run("namespaced wildcard RoleBinding does not produce impersonate", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "ClusterRole", Name: "wild",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{
			bindClusterRoleViaRoleBinding("app", "b", "wild", "user:a"),
		})
		assertNotHas(t, findings, "impersonate")
	})

	t.Run("ClusterRoleBinding wildcards produce impersonate", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "ClusterRole", Name: "wild",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{bindClusterRole("b", "wild", "user:a")})
		assertHas(t, findings, "impersonate")
	})
}

func TestTokenRequestAPIGroup(t *testing.T) {
	t.Run("core group serviceaccounts/token create", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "Role", Name: "tok", Namespace: "ns",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts/token"},
				Verbs:     []string{"create"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{bindRole("ns", "b", "tok", "user:a")})
		assertHas(t, findings, "sa-token-create")
	})

	t.Run("wildcard API group serviceaccounts/token create", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "Role", Name: "tok", Namespace: "ns",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"*"},
				Resources: []string{"serviceaccounts/token"},
				Verbs:     []string{"create"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{bindRole("ns", "b", "tok", "user:a")})
		assertHas(t, findings, "sa-token-create")
	})

	t.Run("authentication.k8s.io serviceaccounts/token does not mint", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "Role", Name: "tok", Namespace: "ns",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"serviceaccounts/token"},
				Verbs:     []string{"create"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{bindRole("ns", "b", "tok", "user:a")})
		assertNotHas(t, findings, "sa-token-create")
	})

	t.Run("bare serviceaccounts create is not TokenRequest", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "Role", Name: "sa", Namespace: "ns",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"create"},
			}},
		}}
		findings := k8srbac.Audit(roles, []k8srbac.BindingLike{bindRole("ns", "b", "sa", "user:a")})
		assertNotHas(t, findings, "sa-token-create")
	})

	t.Run("bare serviceaccounts impersonate follows impersonation rules", func(t *testing.T) {
		roles := []k8srbac.RoleLike{{
			Kind: "ClusterRole", Name: "imp",
			Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"impersonate"},
			}},
		}}
		nsFindings := k8srbac.Audit(roles, []k8srbac.BindingLike{
			bindClusterRoleViaRoleBinding("app", "b", "imp", "user:a"),
		})
		assertNotHas(t, nsFindings, "impersonate", "sa-token-create")

		clusterFindings := k8srbac.Audit(roles, []k8srbac.BindingLike{bindClusterRole("b", "imp", "user:a")})
		assertHas(t, clusterFindings, "impersonate")
		assertNotHas(t, clusterFindings, "sa-token-create")
	})
}
