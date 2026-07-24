// Package k8srbac is a bounded static RBAC-risk heuristic for educational
// Role/ClusterRole fixtures. It is not a full effective-permissions analysis
// and does not evaluate SubjectAccessReview, aggregation, or admission policies.
package k8srbac

import (
	"fmt"
	"sort"
	"strings"
)

// RoleKey uniquely identifies a Role or ClusterRole.
type RoleKey struct {
	Kind      string // "Role" or "ClusterRole"
	Namespace string // empty for ClusterRole
	Name      string
}

// RoleRef mirrors rbac RoleRef used by bindings.
type RoleRef struct {
	APIGroup string
	Kind     string
	Name     string
}

// PolicyRule mirrors a subset of rbac.authorization.k8s.io PolicyRule.
type PolicyRule struct {
	APIGroups     []string
	Resources     []string
	ResourceNames []string
	Verbs         []string
}

// RoleLike is a Role or ClusterRole fixture.
type RoleLike struct {
	Kind      string // Role or ClusterRole
	Name      string
	Namespace string
	Rules     []PolicyRule
}

// BindingLike is a RoleBinding or ClusterRoleBinding fixture.
type BindingLike struct {
	Kind      string // RoleBinding or ClusterRoleBinding
	Name      string
	Namespace string // RoleBinding namespace; empty for ClusterRoleBinding
	RoleRef   RoleRef
	Subjects  []string
}

// Finding is one heuristic risk observation.
type Finding struct {
	Code          string
	Severity      string
	Description   string
	RoleKey       RoleKey
	BindingKind   string
	BindingName   string
	BindingScope  string // namespace or "cluster"
	Subjects      []string
	ResourceNames []string
}

// Audit resolves bindings against roles and returns heuristic risk findings.
// Roles are indexed by RoleKey so identically named Roles in different
// namespaces are never conflated. Unbound roles are not scored; findings are
// produced from bindings (plus invalid/unresolved binding diagnostics).
func Audit(roles []RoleLike, bindings []BindingLike) []Finding {
	roleIndex := indexRoles(roles)

	var findings []Finding
	for _, binding := range bindings {
		subjects := unique(binding.Subjects)
		scope := bindingScope(binding)
		role, roleKey, diag := resolveBinding(binding, roleIndex)
		if diag != nil {
			diag.Subjects = subjects
			diag.BindingKind = binding.Kind
			diag.BindingName = binding.Name
			diag.BindingScope = scope
			findings = append(findings, *diag)
			continue
		}
		for _, rule := range role.Rules {
			findings = append(findings, evaluateRule(roleKey, binding, scope, subjects, rule)...)
		}
	}
	return mergeFindings(findings)
}

func indexRoles(roles []RoleLike) map[RoleKey]RoleLike {
	out := make(map[RoleKey]RoleLike, len(roles))
	for _, role := range roles {
		key := roleKeyFor(role)
		out[key] = role
	}
	return out
}

func roleKeyFor(role RoleLike) RoleKey {
	kind := role.Kind
	if kind == "" {
		if role.Namespace == "" {
			kind = "ClusterRole"
		} else {
			kind = "Role"
		}
	}
	ns := role.Namespace
	if kind == "ClusterRole" {
		ns = ""
	}
	return RoleKey{Kind: kind, Namespace: ns, Name: role.Name}
}

func bindingScope(binding BindingLike) string {
	if binding.Kind == "ClusterRoleBinding" {
		return "cluster"
	}
	return binding.Namespace
}

func resolveBinding(binding BindingLike, roles map[RoleKey]RoleLike) (RoleLike, RoleKey, *Finding) {
	ref := binding.RoleRef
	switch binding.Kind {
	case "ClusterRoleBinding":
		if ref.Kind == "Role" {
			return RoleLike{}, RoleKey{Kind: "Role", Name: ref.Name}, &Finding{
				Code:        "invalid-binding",
				Severity:    "high",
				Description: "ClusterRoleBinding must reference a ClusterRole; referencing a namespaced Role is invalid",
				RoleKey:     RoleKey{Kind: "Role", Name: ref.Name},
			}
		}
		key := RoleKey{Kind: "ClusterRole", Name: ref.Name}
		role, ok := roles[key]
		if !ok {
			return RoleLike{}, key, unresolvedFinding(key)
		}
		return role, key, nil

	case "RoleBinding":
		switch ref.Kind {
		case "Role":
			key := RoleKey{Kind: "Role", Namespace: binding.Namespace, Name: ref.Name}
			role, ok := roles[key]
			if !ok {
				return RoleLike{}, key, unresolvedFinding(key)
			}
			return role, key, nil
		case "ClusterRole":
			key := RoleKey{Kind: "ClusterRole", Name: ref.Name}
			role, ok := roles[key]
			if !ok {
				return RoleLike{}, key, unresolvedFinding(key)
			}
			return role, key, nil
		default:
			key := RoleKey{Kind: ref.Kind, Name: ref.Name, Namespace: binding.Namespace}
			return RoleLike{}, key, unresolvedFinding(key)
		}

	default:
		key := RoleKey{Kind: ref.Kind, Name: ref.Name, Namespace: binding.Namespace}
		return RoleLike{}, key, &Finding{
			Code:        "invalid-binding",
			Severity:    "high",
			Description: fmt.Sprintf("unsupported binding kind %q", binding.Kind),
			RoleKey:     key,
		}
	}
}

func unresolvedFinding(key RoleKey) *Finding {
	return &Finding{
		Code:        "unresolved-role-ref",
		Severity:    "medium",
		Description: fmt.Sprintf("binding references %s %q that was not provided in the role set", key.Kind, key.Name),
		RoleKey:     key,
	}
}

func evaluateRule(roleKey RoleKey, binding BindingLike, scope string, subjects []string, rule PolicyRule) []Finding {
	var findings []Finding
	add := func(code, severity, description string) {
		desc := description
		resourceNames := append([]string(nil), rule.ResourceNames...)
		if len(resourceNames) > 0 {
			desc = fmt.Sprintf(
				"%s; constrained to resourceNames %v (named constraints do not make the permission safe by themselves)",
				description,
				resourceNames,
			)
		}
		findings = append(findings, Finding{
			Code:          code,
			Severity:      severity,
			Description:   desc,
			RoleKey:       roleKey,
			BindingKind:   binding.Kind,
			BindingName:   binding.Name,
			BindingScope:  scope,
			Subjects:      append([]string(nil), subjects...),
			ResourceNames: resourceNames,
		})
	}

	if isAllResourcesAllVerbs(rule) {
		add("all-resources-all-verbs", "critical", "apiGroups/resources/verbs wildcards grant effectively unrestricted authorization within the binding scope")
	}

	apiGroups := rule.APIGroups
	if len(apiGroups) == 0 {
		apiGroups = []string{""}
	}

	for _, group := range apiGroups {
		for _, resource := range expandResources(rule.Resources) {
			if groupMatches(group, "", "authentication.k8s.io") &&
				resourceMatches(resource, "serviceaccounts", "token") &&
				hasAnyVerb(rule.Verbs, "create", "*") {
				add("sa-token-create", "high", "create on serviceaccounts/token can mint TokenRequest-bound service-account tokens")
			}
			if groupMatches(group, "certificates.k8s.io") &&
				resourceMatches(resource, "certificatesigningrequests", "approval") &&
				hasAnyVerb(rule.Verbs, "update", "patch", "*") {
				add("csr-approval", "high", "update/patch on certificatesigningrequests/approval can approve certificate requests")
			}
			if groupMatches(group, "certificates.k8s.io") &&
				resourceMatches(resource, "signers", "") &&
				hasAnyVerb(rule.Verbs, "approve", "*") {
				add("csr-signer-approve", "high", "approve on certificatesigningrequests signers grants signer approval authority")
			}
			if groupMatches(group, "authentication.k8s.io") &&
				resourceMatches(resource, "tokenreviews", "") &&
				hasAnyVerb(rule.Verbs, "create", "*") {
				add("tokenreview-oracle", "medium", "create on tokenreviews is a token-authentication oracle capability; it does not mint service-account tokens")
			}
			if groupMatches(group, "", "authentication.k8s.io") &&
				(resourceMatches(resource, "users", "") || resourceMatches(resource, "groups", "") ||
					resourceMatches(resource, "serviceaccounts", "") || resourceMatches(resource, "userextras", "")) &&
				hasAnyVerb(rule.Verbs, "impersonate", "*") {
				name := resource.name
				if name == "*" {
					name = "users|groups|serviceaccounts|userextras"
				}
				add("impersonate", "high", fmt.Sprintf("impersonate on %s expands identity authority", name))
			}
			if groupMatches(group, "rbac.authorization.k8s.io") &&
				(resourceMatches(resource, "roles", "") || resourceMatches(resource, "clusterroles", "") ||
					resourceMatches(resource, "rolebindings", "") || resourceMatches(resource, "clusterrolebindings", "")) &&
				hasAnyVerb(rule.Verbs, "bind", "escalate", "*") {
				name := resource.name
				if name == "*" {
					name = "roles|clusterroles|rolebindings|clusterrolebindings"
				}
				add("rbac-bind-escalate", "high", fmt.Sprintf("%s on %s can expand RBAC authority beyond the role's own permissions", joinedVerbs(rule.Verbs), name))
			}
			if groupMatches(group, "apps", "batch", "extensions") &&
				isWorkloadController(resource.name) &&
				hasAnyVerb(rule.Verbs, "create", "update", "patch", "*") {
				name := resource.name
				if name == "*" {
					name = "workload controllers"
				}
				add("workload-controller-mutate", "medium", fmt.Sprintf("mutate %s; review pod templates and service-account bindings", name))
			}
			if groupMatches(group, "") &&
				resourceMatches(resource, "pods", "") &&
				hasAnyVerb(rule.Verbs, "create", "*") {
				add("pod-create", "medium", "create pods is a heuristic risk when combined with privileged service accounts or permissive admission; not proof of breakout alone")
			}
			if groupMatches(group, "") &&
				(resourceMatches(resource, "pods", "exec") || resourceMatches(resource, "pods", "attach") || resourceMatches(resource, "pods", "portforward")) &&
				hasAnyVerb(rule.Verbs, "create", "get", "update", "*") {
				sub := resource.subresource
				if resource.name == "*" || sub == "" {
					sub = "exec|attach|portforward"
				}
				add("pod-interactive", "high", fmt.Sprintf("pods/%s enables interactive access to running workloads", sub))
			}
			if groupMatches(group, "") &&
				resourceMatches(resource, "secrets", "") &&
				hasAnyVerb(rule.Verbs, "get", "list", "watch", "*") {
				add("secrets-read", "high", "read access to secrets can expose credentials mounted or stored as Secret objects")
			}
			if groupMatches(group, "") &&
				resourceMatches(resource, "nodes", "proxy") &&
				hasAnyVerb(rule.Verbs, "create", "get", "update", "*") {
				add("nodes-proxy", "high", "nodes/proxy can reach kubelet APIs and bypass some network controls")
			}
			if groupMatches(group, "admissionregistration.k8s.io") &&
				(resourceMatches(resource, "validatingwebhookconfigurations", "") ||
					resourceMatches(resource, "mutatingwebhookconfigurations", "")) &&
				hasAnyVerb(rule.Verbs, "create", "update", "patch", "delete", "*") {
				name := resource.name
				if name == "*" {
					name = "admission webhook configurations"
				}
				add("admission-policy-mutate", "high", fmt.Sprintf("mutation of %s can weaken or bypass admission controls", name))
			}
			if groupMatches(group, "kyverno.io", "constraints.gatekeeper.sh", "templates.gatekeeper.sh", "policy") &&
				hasAnyVerb(rule.Verbs, "create", "update", "patch", "delete", "*") {
				name := resource.name
				if name == "" || name == "*" {
					name = "policy resources"
				}
				add("admission-policy-mutate", "high", fmt.Sprintf("mutation of %s can weaken or bypass admission controls", name))
			}
		}
	}
	return findings
}

func isAllResourcesAllVerbs(rule PolicyRule) bool {
	return contains(rule.APIGroups, "*") && contains(rule.Resources, "*") && contains(rule.Verbs, "*")
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

func groupMatches(actual string, allowed ...string) bool {
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

// resourceMatches treats resources:["*"] as covering every resource and
// subresource. A bare resource (no slash) never implies a subresource.
func resourceMatches(ref resourceRef, wantName, wantSub string) bool {
	if ref.name == "*" {
		return true
	}
	if ref.name != wantName {
		return false
	}
	if wantSub == "" {
		return ref.subresource == ""
	}
	return ref.subresource == wantSub || ref.subresource == "*"
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

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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

type findingKey struct {
	Code         string
	RoleKind     string
	RoleNS       string
	RoleName     string
	BindingKind  string
	BindingName  string
	BindingScope string
}

func mergeFindings(in []Finding) []Finding {
	order := make([]findingKey, 0, len(in))
	byKey := map[findingKey]*Finding{}
	for _, finding := range in {
		key := findingKey{
			Code:         finding.Code,
			RoleKind:     finding.RoleKey.Kind,
			RoleNS:       finding.RoleKey.Namespace,
			RoleName:     finding.RoleKey.Name,
			BindingKind:  finding.BindingKind,
			BindingName:  finding.BindingName,
			BindingScope: finding.BindingScope,
		}
		if existing, ok := byKey[key]; ok {
			existing.Subjects = unique(append(existing.Subjects, finding.Subjects...))
			existing.ResourceNames = unique(append(existing.ResourceNames, finding.ResourceNames...))
			continue
		}
		copyFinding := finding
		copyFinding.Subjects = unique(append([]string(nil), finding.Subjects...))
		copyFinding.ResourceNames = unique(append([]string(nil), finding.ResourceNames...))
		byKey[key] = &copyFinding
		order = append(order, key)
	}
	out := make([]Finding, 0, len(order))
	for _, key := range order {
		f := *byKey[key]
		sort.Strings(f.Subjects)
		sort.Strings(f.ResourceNames)
		out = append(out, f)
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
