package k8srbac_test

import (
	"testing"

	k8srbac "github.com/jasonachkar/cybersecurity-writeups/cloud-security/scripts/k8s-rbac"
)

func TestRiskClasses(t *testing.T) {
	tests := []struct {
		name    string
		role    k8srbac.RoleLike
		want    string
		notWant string
	}{
		{
			name: "serviceaccounts token create",
			role: k8srbac.RoleLike{Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts/token"},
				Verbs:     []string{"create"},
			}}},
			want: "sa-token-create",
		},
		{
			name: "CSR approval subresource",
			role: k8srbac.RoleLike{Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"certificates.k8s.io"},
				Resources: []string{"certificatesigningrequests/approval"},
				Verbs:     []string{"update"},
			}}},
			want: "csr-approval",
		},
		{
			name: "CSR create alone is not approval",
			role: k8srbac.RoleLike{Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"certificates.k8s.io"},
				Resources: []string{"certificatesigningrequests"},
				Verbs:     []string{"create", "update", "patch"},
			}}},
			notWant: "csr-approval",
		},
		{
			name: "signer approve",
			role: k8srbac.RoleLike{Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups:     []string{"certificates.k8s.io"},
				Resources:     []string{"signers"},
				ResourceNames: []string{"kubernetes.io/kubelet-serving"},
				Verbs:         []string{"approve"},
			}}},
			want: "csr-signer-approve",
		},
		{
			name: "tokenreviews is oracle not minting",
			role: k8srbac.RoleLike{Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			}}},
			want: "tokenreview-oracle",
		},
		{
			name: "impersonate users",
			role: k8srbac.RoleLike{Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"users"},
				Verbs:     []string{"impersonate"},
			}}},
			want: "impersonate",
		},
		{
			name: "bind escalate",
			role: k8srbac.RoleLike{Name: "r", ClusterWide: true, Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
				Verbs:     []string{"bind", "escalate"},
			}}},
			want: "rbac-bind-escalate",
		},
		{
			name: "workload controller mutate",
			role: k8srbac.RoleLike{Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
				Verbs:     []string{"create", "patch"},
			}}},
			want: "workload-controller-mutate",
		},
		{
			name: "pod create heuristic",
			role: k8srbac.RoleLike{Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"create"},
			}}},
			want: "pod-create",
		},
		{
			name: "pods exec",
			role: k8srbac.RoleLike{Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"pods/exec"},
				Verbs:     []string{"create"},
			}}},
			want: "pod-interactive",
		},
		{
			name: "secrets read",
			role: k8srbac.RoleLike{Name: "r", Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "list"},
			}}},
			want: "secrets-read",
		},
		{
			name: "nodes proxy",
			role: k8srbac.RoleLike{Name: "r", ClusterWide: true, Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"nodes/proxy"},
				Verbs:     []string{"get", "create"},
			}}},
			want: "nodes-proxy",
		},
		{
			name: "admission webhook mutate",
			role: k8srbac.RoleLike{Name: "r", ClusterWide: true, Rules: []k8srbac.PolicyRule{{
				APIGroups: []string{"admissionregistration.k8s.io"},
				Resources: []string{"mutatingwebhookconfigurations"},
				Verbs:     []string{"update"},
			}}},
			want: "admission-policy-mutate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := k8srbac.Audit([]k8srbac.RoleLike{tt.role}, nil)
			if tt.want != "" && !k8srbac.HasCode(findings, tt.want) {
				t.Fatalf("missing %s in %#v", tt.want, findings)
			}
			if tt.notWant != "" && k8srbac.HasCode(findings, tt.notWant) {
				t.Fatalf("unexpected %s in %#v", tt.notWant, findings)
			}
		})
	}
}

func TestBindingSubjectsAttached(t *testing.T) {
	roles := []k8srbac.RoleLike{{
		Name: "secret-reader",
		Rules: []k8srbac.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get"},
		}},
	}}
	bindings := []k8srbac.BindingLike{{
		Name:     "bind",
		RoleRef:  "secret-reader",
		Subjects: []string{"system:serviceaccount:app:worker"},
	}}
	findings := k8srbac.Audit(roles, bindings)
	if !k8srbac.HasCode(findings, "secrets-read") {
		t.Fatal("expected secrets-read")
	}
	if len(findings[0].Subjects) != 1 || findings[0].Subjects[0] != "system:serviceaccount:app:worker" {
		t.Fatalf("subjects not attached: %#v", findings[0].Subjects)
	}
}

func TestPodsExecDoesNotMatchBarePodsGet(t *testing.T) {
	role := k8srbac.RoleLike{Name: "r", Rules: []k8srbac.PolicyRule{{
		APIGroups: []string{""},
		Resources: []string{"pods"},
		Verbs:     []string{"get", "list"},
	}}}
	findings := k8srbac.Audit([]k8srbac.RoleLike{role}, nil)
	if k8srbac.HasCode(findings, "pod-interactive") {
		t.Fatal("bare pods get must not imply pods/exec")
	}
}
