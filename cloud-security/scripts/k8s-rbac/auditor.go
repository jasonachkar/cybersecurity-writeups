// Package k8srbac is a bounded static RBAC-risk heuristic for educational
// Role/ClusterRole fixtures. It is not a full effective-permissions analysis
// and does not evaluate SubjectAccessReview or admission policies.
package k8srbac

import (
	"fmt"
	"strings"
)

// PolicyRule mirrors a subset of rbac.authorization.k8s.io PolicyRule.
type PolicyRule struct {
	APIGroups     []string `json:"apiGroups"`
	Resources     []string `json:"resources"`
	ResourceNames []string `json:"resourceNames"`
	Verbs         []string `json:"verbs"`
}

// RoleLike is a Role or ClusterRole fixture.
type RoleLike struct {
	Name        string       `json:"name"`
	Namespace   string       `json:"namespace,omitempty"` // empty means cluster-scoped ClusterRole
	ClusterWide bool         `json:"clusterWide"`
	Rules       []PolicyRule `json:"rules"`
}

// BindingLike is a RoleBinding or ClusterRoleBinding fixture.
type BindingLike struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace,omitempty"`
	RoleRef   string   `json:"roleRef"`
	Subjects  []string `json:"subjects"`
}

// Finding is one heuristic risk observation.
type Finding struct {
	Code        string
	Severity    string
	Description string
	Role        string
	Subjects    []string
}

// Audit evaluates roles and bindings and returns heuristic findings.
func Audit(roles []RoleLike, bindings []BindingLike) []Finding {
	roleIndex := map[string]RoleLike{}
	for _, role := range roles {
		roleIndex[role.Name] = role
	}

	subjectsForRole := map[string][]string{}
	for _, binding := range bindings {
		subjectsForRole[binding.RoleRef] = append(subjectsForRole[binding.RoleRef], binding.Subjects...)
	}

	var findings []Finding
	for _, role := range roles {
		subjects := unique(subjectsForRole[role.Name])
		for _, rule := range role.Rules {
			findings = append(findings, evaluateRule(role, rule, subjects)...)
		}
	}
	return findings
}

func evaluateRule(role RoleLike, rule PolicyRule, subjects []string) []Finding {
	var findings []Finding
	add := func(code, severity, description string) {
		findings = append(findings, Finding{
			Code:        code,
			Severity:    severity,
			Description: description,
			Role:        role.Name,
			Subjects:    subjects,
		})
	}

	for _, resource := range expandResources(rule.Resources) {
		apiGroups := rule.APIGroups
		if len(apiGroups) == 0 {
			apiGroups = []string{""}
		}
		for _, group := range apiGroups {
			resourceName := resource.name
			subresource := resource.subresource

			if matches(group, "", "authentication.k8s.io") && resourceName == "serviceaccounts" && subresource == "token" && hasAnyVerb(rule.Verbs, "create", "*") {
				add("sa-token-create", "high", "create on serviceaccounts/token can mint TokenRequest-bound service-account tokens")
			}
			if matches(group, "certificates.k8s.io") && resourceName == "certificatesigningrequests" && subresource == "approval" && hasAnyVerb(rule.Verbs, "update", "patch", "*") {
				add("csr-approval", "high", "update/patch on certificatesigningrequests/approval can approve certificate requests")
			}
			if matches(group, "certificates.k8s.io") && resourceName == "signers" && hasAnyVerb(rule.Verbs, "approve", "*") {
				add("csr-signer-approve", "high", "approve on certificatesigningrequests signers grants signer approval authority")
			}
			if matches(group, "authentication.k8s.io") && resourceName == "tokenreviews" && subresource == "" && hasAnyVerb(rule.Verbs, "create", "*") {
				add("tokenreview-oracle", "medium", "create on tokenreviews is a token-authentication oracle capability; it does not mint service-account tokens")
			}
			if matches(group, "", "authentication.k8s.io") && (resourceName == "users" || resourceName == "groups" || resourceName == "serviceaccounts" || resourceName == "userextras") && hasAnyVerb(rule.Verbs, "impersonate", "*") {
				add("impersonate", "high", fmt.Sprintf("impersonate on %s expands identity authority", resourceName))
			}
			if matches(group, "rbac.authorization.k8s.io") && (resourceName == "roles" || resourceName == "clusterroles" || resourceName == "rolebindings" || resourceName == "clusterrolebindings") && hasAnyVerb(rule.Verbs, "bind", "escalate", "*") {
				add("rbac-bind-escalate", "high", fmt.Sprintf("%s on %s can expand RBAC authority beyond the role's own permissions", joinedVerbs(rule.Verbs), resourceName))
			}
			if matches(group, "apps", "batch", "extensions") && isWorkloadController(resourceName) && hasAnyVerb(rule.Verbs, "create", "update", "patch", "*") {
				add("workload-controller-mutate", "medium", fmt.Sprintf("mutate %s controllers; review pod templates and service-account bindings", resourceName))
			}
			if matches(group, "") && resourceName == "pods" && subresource == "" && hasAnyVerb(rule.Verbs, "create", "*") {
				add("pod-create", "medium", "create pods is a heuristic risk when combined with privileged service accounts or permissive admission; not proof of breakout alone")
			}
			if matches(group, "") && resourceName == "pods" && (subresource == "exec" || subresource == "attach" || subresource == "portforward") && hasAnyVerb(rule.Verbs, "create", "get", "*", "update") {
				add("pod-interactive", "high", fmt.Sprintf("pods/%s enables interactive access to running workloads", subresource))
			}
			if matches(group, "") && resourceName == "secrets" && hasAnyVerb(rule.Verbs, "get", "list", "watch", "*") {
				add("secrets-read", "high", "read access to secrets can expose credentials mounted or stored as Secret objects")
			}
			if matches(group, "") && resourceName == "nodes" && subresource == "proxy" && hasAnyVerb(rule.Verbs, "create", "get", "*", "update") {
				add("nodes-proxy", "high", "nodes/proxy can reach kubelet APIs and bypass some network controls")
			}
			if (matches(group, "admissionregistration.k8s.io") && (resourceName == "validatingwebhookconfigurations" || resourceName == "mutatingwebhookconfigurations")) ||
				(matches(group, "kyverno.io", "constraints.gatekeeper.sh", "templates.gatekeeper.sh", "policy") && hasAnyVerb(rule.Verbs, "create", "update", "patch", "delete", "*")) {
				if hasAnyVerb(rule.Verbs, "create", "update", "patch", "delete", "*") {
					add("admission-policy-mutate", "high", fmt.Sprintf("mutation of %s can weaken or bypass admission controls", resourceName))
				}
			}
		}
	}
	return findings
}

type resourceRef struct {
	name        string
	subresource string
}

func expandResources(resources []string) []resourceRef {
	if len(resources) == 0 {
		return nil
	}
	var out []resourceRef
	for _, item := range resources {
		if item == "*" {
			out = append(out, resourceRef{name: "*"})
			continue
		}
		name, sub, ok := strings.Cut(item, "/")
		if ok {
			out = append(out, resourceRef{name: name, subresource: sub})
		} else {
			out = append(out, resourceRef{name: item})
		}
	}
	return out
}

func matches(actual string, allowed ...string) bool {
	if actual == "*" {
		return true
	}
	for _, item := range allowed {
		if item == "*" || item == actual {
			return true
		}
	}
	return false
}

func hasAnyVerb(verbs []string, wanted ...string) bool {
	for _, verb := range verbs {
		if verb == "*" {
			return true
		}
		for _, want := range wanted {
			if verb == want {
				return true
			}
		}
	}
	return false
}

func isWorkloadController(name string) bool {
	switch name {
	case "deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs", "*":
		return true
	default:
		return false
	}
}

func joinedVerbs(verbs []string) string {
	return strings.Join(verbs, ",")
}

func unique(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// HasCode reports whether any finding uses the code.
func HasCode(findings []Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
