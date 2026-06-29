// Purpose: Scans Kubernetes RBAC (Roles and ClusterRoles) configurations for high-risk permissions, wildcard verbs, and administrative escalation vectors.
package main

import (
	"fmt"
	"strings"
)

// PolicyRule matches a single rule in a Kubernetes Role/ClusterRole.
type PolicyRule struct {
	APIGroups []string
	Resources []string
	Verbs     []string
}

// Role represents a Role or ClusterRole object.
type Role struct {
	Name      string
	Namespace string // Empty for ClusterRole
	IsCluster bool
	Rules     []PolicyRule
}

// Subject represents a binding target (User, Group, or ServiceAccount).
type Subject struct {
	Kind      string // User, Group, ServiceAccount
	Name      string
	Namespace string
}

// RoleBinding represents a RoleBinding or ClusterRoleBinding.
type RoleBinding struct {
	Name      string
	Namespace string // Empty for ClusterRoleBinding
	RoleRef   string
	Subjects  []Subject
}

// High-risk verbs and resources mapping for K8s privilege escalation.
// Ref: https://kubernetes.io/docs/concepts/security/rbac-good-practices/
var highRiskCombinations = []struct {
	Resources []string
	Verbs     []string
	Severity  string
	Reason    string
}{
	{
		Resources: []string{"*"},
		Verbs:     []string{"*"},
		Severity:  "CRITICAL",
		Reason:    "Full cluster-admin access equivalent. Complete compromise vector.",
	},
	{
		Resources: []string{"roles", "clusterroles", "rolebindings", "clusterrolebindings"},
		Verbs:     []string{"bind", "escalate", "*"},
		Severity:  "CRITICAL",
		Reason:    "Can bypass RBAC checks to bind high-privilege roles or escalate privileges.",
	},
	{
		Resources: []string{"secrets"},
		Verbs:     []string{"get", "list", "watch", "*"},
		Severity:  "HIGH",
		Reason:    "Allows harvesting credential tokens, service accounts, and database secrets.",
	},
	{
		Resources: []string{"pods"},
		Verbs:     []string{"create", "update", "patch", "*"},
		Severity:  "HIGH",
		Reason:    "Can spawn pods with hostPath mounts, hostNetwork, or privileged mode to break containment.",
	},
	{
		Resources: []string{"deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"},
		Verbs:     []string{"create", "update", "patch", "*"},
		Severity:  "HIGH",
		Reason:    "Allows indirect workload creation (e.g. creating malicious pods via deployment spec).",
	},
	{
		Resources: []string{"certificatesigningrequests"},
		Verbs:     []string{"create", "update", "patch", "*"},
		Severity:  "HIGH",
		Reason:    "Can approve custom certificates to impersonate cluster admins/nodes.",
	},
	{
		Resources: []string{"serviceaccounts/token", "tokenreviews"},
		Verbs:     []string{"create", "*"},
		Severity:  "HIGH",
		Reason:    "Can generate tokens for other service accounts, facilitating identity theft.",
	},
}

// Helper to check if a list contains a wildcard or specific value
func contains(list []string, val string) bool {
	for _, item := range list {
		if item == "*" || strings.ToLower(item) == strings.ToLower(val) {
			return true
		}
	}
	return false
}

// Audits a single role against high-risk rules.
func AuditRole(role Role) []string {
	var alerts []string

	for _, rule := range role.Rules {
		for _, risk := range highRiskCombinations {
			// Check if any rule resource matches the risk resource
			resourceMatch := false
			var matchedResource string
			for _, rRes := range rule.Resources {
				for _, riskRes := range risk.Resources {
					if rRes == "*" || strings.ToLower(rRes) == strings.ToLower(riskRes) {
						resourceMatch = true
						matchedResource = rRes
						break
					}
				}
				if resourceMatch {
					break
				}
			}

			// Check if any rule verb matches the risk verb
			verbMatch := false
			var matchedVerb string
			for _, rVerb := range rule.Verbs {
				for _, riskVerb := range risk.Verbs {
					if rVerb == "*" || strings.ToLower(rVerb) == strings.ToLower(riskVerb) {
						verbMatch = true
						matchedVerb = rVerb
						break
					}
				}
				if verbMatch {
					break
				}
			}

			if resourceMatch && verbMatch {
				alerts = append(alerts, fmt.Sprintf("[%s] Role '%s' allows resource '%s' with verb '%s': %s",
					risk.Severity, role.Name, matchedResource, matchedVerb, risk.Reason))
			}
		}
	}
	return alerts
}

func main() {
	fmt.Println("==================================================")
	fmt.Println("Kubernetes RBAC Security Audit Utility")
	fmt.Println("==================================================")

	// Simulated Kubernetes Roles
	roles := []Role{
		{
			Name:      "cluster-admin-role",
			IsCluster: true,
			Rules: []PolicyRule{
				{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
			},
		},
		{
			Name:      "secrets-harvester",
			Namespace: "default",
			IsCluster: false,
			Rules: []PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list", "get"}},
			},
		},
		{
			Name:      "pod-deployer",
			Namespace: "kube-system",
			IsCluster: false,
			Rules: []PolicyRule{
				{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create"}},
			},
		},
		{
			Name:      "read-only",
			Namespace: "default",
			IsCluster: false,
			Rules: []PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods", "services"}, Verbs: []string{"get", "list"}},
			},
		},
	}

	// Simulated Bindings
	bindings := []RoleBinding{
		{
			Name:      "admin-binding",
			RoleRef:   "cluster-admin-role",
			Subjects:  []Subject{{Kind: "Group", Name: "system:masters"}},
		},
		{
			Name:      "app-deploy-binding",
			Namespace: "kube-system",
			RoleRef:   "pod-deployer",
			Subjects:  []Subject{{Kind: "ServiceAccount", Name: "jenkins-ci-sa", Namespace: "kube-system"}},
		},
		{
			Name:      "read-binding",
			Namespace: "default",
			RoleRef:   "read-only",
			Subjects:  []Subject{{Kind: "User", Name: "alice@company.com"}},
		},
	}

	// Step 1: Audit all Roles
	fmt.Println("\n--- Stage 1: Scanning Roles & ClusterRoles for Risks ---")
	findingsMap := make(map[string][]string)
	for _, role := range roles {
		alerts := AuditRole(role)
		if len(alerts) > 0 {
			findingsMap[role.Name] = alerts
			for _, alert := range alerts {
				fmt.Println(alert)
			}
		}
	}
	if len(findingsMap) == 0 {
		fmt.Println("No high-risk roles identified.")
	}

	// Step 2: Correlate bindings with high-risk roles
	fmt.Println("\n--- Stage 2: Binding Correlation & Exposure Analysis ---")
	for _, binding := range bindings {
		alerts, exists := findingsMap[binding.RoleRef]
		if exists {
			fmt.Printf("\n[WARNING] High-Risk Role '%s' is bound by '%s' to subjects:\n", binding.RoleRef, binding.Name)
			for _, sub := range binding.Subjects {
				nsStr := ""
				if sub.Namespace != "" {
					nsStr = fmt.Sprintf(" in namespace '%s'", sub.Namespace)
				}
				fmt.Printf("   - %s: '%s'%s\n", sub.Kind, sub.Name, nsStr)
			}
			fmt.Println("   Impact Details:")
			for _, alert := range alerts {
				fmt.Printf("     * %s\n", alert)
			}
		}
	}
}
