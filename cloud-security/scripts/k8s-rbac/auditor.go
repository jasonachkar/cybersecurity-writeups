// Package k8srbac is a bounded static RBAC-risk heuristic for educational
// Role/ClusterRole fixtures.
//
// It validates roleRef API group and kind, distinguishes RoleBinding versus
// ClusterRoleBinding authorization scope, and classifies a fixed set of
// built-in resources as namespaced or cluster-scoped for the analyzer's known
// risk classes.
//
// It is not a full effective-permissions analysis and does not evaluate
// SubjectAccessReview, SelfSubjectRulesReview, aggregation, admission
// policies, or live API discovery. Unknown/custom resources are not assigned
// a fabricated scope.
package k8srbac

import (
	"fmt"
	"sort"
	"strings"
)

const rbacAPIGroup = "rbac.authorization.k8s.io"

// ResourceScope classifies a built-in resource for binding-effective analysis.
type ResourceScope int

const (
	// ResourceScopeUnknown means the analyzer does not claim namespaced or
	// cluster scope for the resource (typically custom/unknown APIs).
	ResourceScopeUnknown ResourceScope = iota
	// ResourceScopeNamespaced resources can take effect through a RoleBinding.
	ResourceScopeNamespaced
	// ResourceScopeCluster resources take effect only through ClusterRoleBinding
	// (or equivalent cluster-wide authorization), not through a namespaced RoleBinding.
	ResourceScopeCluster
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

func invalidBindingFinding(key RoleKey, description string) *Finding {
	return &Finding{
		Code:        "invalid-binding",
		Severity:    "high",
		Description: description,
		RoleKey:     key,
	}
}

func resolveBinding(binding BindingLike, roles map[RoleKey]RoleLike) (RoleLike, RoleKey, *Finding) {
	ref := binding.RoleRef
	refKey := RoleKey{Kind: ref.Kind, Name: ref.Name}

	switch binding.Kind {
	case "ClusterRoleBinding":
		if binding.Namespace != "" {
			return RoleLike{}, refKey, invalidBindingFinding(refKey, "ClusterRoleBinding must not declare a namespace")
		}
		if ref.APIGroup != rbacAPIGroup {
			return RoleLike{}, refKey, invalidBindingFinding(refKey, "roleRef.apiGroup must be rbac.authorization.k8s.io")
		}
		if ref.Kind == "" {
			return RoleLike{}, refKey, invalidBindingFinding(refKey, "ClusterRoleBinding roleRef.kind must be ClusterRole")
		}
		if ref.Kind != "ClusterRole" {
			if ref.Kind == "Role" {
				return RoleLike{}, RoleKey{Kind: "Role", Name: ref.Name}, invalidBindingFinding(
					RoleKey{Kind: "Role", Name: ref.Name},
					"ClusterRoleBinding roleRef.kind must be ClusterRole",
				)
			}
			return RoleLike{}, refKey, invalidBindingFinding(refKey, "ClusterRoleBinding roleRef.kind must be ClusterRole")
		}
		key := RoleKey{Kind: "ClusterRole", Name: ref.Name}
		role, ok := roles[key]
		if !ok {
			return RoleLike{}, key, unresolvedFinding(key)
		}
		return role, key, nil

	case "RoleBinding":
		if binding.Namespace == "" {
			return RoleLike{}, refKey, invalidBindingFinding(refKey, "RoleBinding requires a namespace")
		}
		if ref.APIGroup != rbacAPIGroup {
			return RoleLike{}, refKey, invalidBindingFinding(refKey, "roleRef.apiGroup must be rbac.authorization.k8s.io")
		}
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
		case "":
			return RoleLike{}, refKey, invalidBindingFinding(refKey, "RoleBinding roleRef.kind must be Role or ClusterRole")
		default:
			return RoleLike{}, refKey, invalidBindingFinding(refKey, "RoleBinding roleRef.kind must be Role or ClusterRole")
		}

	default:
		return RoleLike{}, refKey, invalidBindingFinding(refKey, fmt.Sprintf("unsupported binding kind %q", binding.Kind))
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

// knownResourceScope returns the analyzer's bounded classification for a
// built-in resource name (without subresource). Unknown APIs remain Unknown.
func knownResourceScope(apiGroup, resource string) ResourceScope {
	if resource == "" || resource == "*" {
		return ResourceScopeUnknown
	}
	switch apiGroup {
	case "", "core":
		switch resource {
		case "pods", "secrets", "serviceaccounts", "configmaps", "services",
			"endpoints", "events", "limitranges", "resourcequotas",
			"replicationcontrollers", "persistentvolumeclaims":
			return ResourceScopeNamespaced
		case "nodes", "namespaces", "persistentvolumes", "componentstatuses":
			return ResourceScopeCluster
		case "users", "groups", "userextras":
			// Impersonation targets are not namespaced RoleBinding-effective.
			return ResourceScopeCluster
		}
	case "apps", "batch", "extensions":
		switch resource {
		case "deployments", "statefulsets", "daemonsets", "replicasets",
			"jobs", "cronjobs":
			return ResourceScopeNamespaced
		}
	case "rbac.authorization.k8s.io":
		switch resource {
		case "roles", "rolebindings":
			return ResourceScopeNamespaced
		case "clusterroles", "clusterrolebindings":
			return ResourceScopeCluster
		}
	case "certificates.k8s.io":
		switch resource {
		case "certificatesigningrequests", "signers":
			return ResourceScopeCluster
		}
	case "authentication.k8s.io":
		switch resource {
		case "tokenreviews":
			return ResourceScopeCluster
		}
	case "authorization.k8s.io":
		switch resource {
		case "subjectaccessreviews", "selfsubjectaccessreviews",
			"selfsubjectrulesreviews", "localsubjectaccessreviews":
			// LocalSubjectAccessReviews are namespaced; the others are cluster-scoped.
			if resource == "localsubjectaccessreviews" {
				return ResourceScopeNamespaced
			}
			return ResourceScopeCluster
		}
	case "storage.k8s.io":
		switch resource {
		case "storageclasses", "csidrivers", "csinodes":
			return ResourceScopeCluster
		case "volumeattachments":
			return ResourceScopeCluster
		}
	case "admissionregistration.k8s.io":
		switch resource {
		case "validatingwebhookconfigurations", "mutatingwebhookconfigurations",
			"validatingadmissionpolicies", "validatingadmissionpolicybindings",
			"mutatingadmissionpolicies", "mutatingadmissionpolicybindings":
			return ResourceScopeCluster
		}
	}
	return ResourceScopeUnknown
}

// permissionEffective reports whether a matched resource can take effect
// through the binding under this bounded model.
func permissionEffective(binding BindingLike, apiGroup, resourceName string) bool {
	if binding.Kind == "ClusterRoleBinding" {
		return true
	}
	// Namespaced RoleBinding: only known namespaced resources are treated as effective.
	switch knownResourceScope(apiGroup, resourceName) {
	case ResourceScopeNamespaced:
		return true
	case ResourceScopeCluster, ResourceScopeUnknown:
		return false
	default:
		return false
	}
}

func evaluateRule(roleKey RoleKey, binding BindingLike, scope string, subjects []string, rule PolicyRule) []Finding {
	var findings []Finding
	add := func(code, severity, description, apiGroup, resourceName string) {
		if !permissionEffective(binding, apiGroup, resourceName) {
			return
		}
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
		// Wildcard grant is still meaningful inside a RoleBinding namespace, but
		// must not be described as granting cluster-scoped resources.
		desc := "apiGroups/resources/verbs wildcards grant unrestricted authorization within the binding scope for resources that can take effect there"
		if binding.Kind == "RoleBinding" {
			desc = "apiGroups/resources/verbs wildcards grant unrestricted authorization for namespaced resources within the RoleBinding namespace; known cluster-scoped resources are not treated as effective through this binding"
		}
		add("all-resources-all-verbs", "critical", desc, "", "pods")
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
				add("sa-token-create", "high", "create on serviceaccounts/token can mint TokenRequest-bound service-account tokens", "", "serviceaccounts")
			}
			if groupMatches(group, "certificates.k8s.io") &&
				resourceMatches(resource, "certificatesigningrequests", "approval") &&
				hasAnyVerb(rule.Verbs, "update", "patch", "*") {
				add("csr-approval", "high", "update/patch on certificatesigningrequests/approval can approve certificate requests", "certificates.k8s.io", "certificatesigningrequests")
			}
			if groupMatches(group, "certificates.k8s.io") &&
				resourceMatches(resource, "signers", "") &&
				hasAnyVerb(rule.Verbs, "approve", "*") {
				add("csr-signer-approve", "high", "approve on certificatesigningrequests signers grants signer approval authority", "certificates.k8s.io", "signers")
			}
			if groupMatches(group, "authentication.k8s.io") &&
				resourceMatches(resource, "tokenreviews", "") &&
				hasAnyVerb(rule.Verbs, "create", "*") {
				add("tokenreview-oracle", "medium", "create on tokenreviews is a token-authentication oracle capability; it does not mint service-account tokens", "authentication.k8s.io", "tokenreviews")
			}
			if groupMatches(group, "", "authentication.k8s.io") &&
				(resourceMatches(resource, "users", "") || resourceMatches(resource, "groups", "") ||
					resourceMatches(resource, "serviceaccounts", "") || resourceMatches(resource, "userextras", "")) &&
				hasAnyVerb(rule.Verbs, "impersonate", "*") {
				targets := []struct {
					name string
					api  string
				}{}
				if resource.name == "*" {
					targets = []struct {
						name string
						api  string
					}{
						{"users", ""},
						{"groups", ""},
						{"serviceaccounts", ""},
						{"userextras", ""},
					}
				} else {
					targets = []struct {
						name string
						api  string
					}{{resource.name, ""}}
				}
				for _, target := range targets {
					add("impersonate", "high",
						fmt.Sprintf("impersonate on %s expands identity authority", target.name),
						target.api, target.name)
				}
			}
			if groupMatches(group, "rbac.authorization.k8s.io") &&
				(resourceMatches(resource, "roles", "") || resourceMatches(resource, "clusterroles", "") ||
					resourceMatches(resource, "rolebindings", "") || resourceMatches(resource, "clusterrolebindings", "")) &&
				hasAnyVerb(rule.Verbs, "bind", "escalate", "*") {
				candidates := []string{"roles", "clusterroles", "rolebindings", "clusterrolebindings"}
				if resource.name != "*" {
					candidates = []string{resource.name}
				}
				for _, candidate := range candidates {
					add("rbac-bind-escalate", "high",
						fmt.Sprintf("%s on %s can expand RBAC authority beyond the role's own permissions", joinedVerbs(rule.Verbs), candidate),
						"rbac.authorization.k8s.io", candidate)
				}
			}
			if groupMatches(group, "apps", "batch", "extensions") &&
				isWorkloadController(resource.name) &&
				hasAnyVerb(rule.Verbs, "create", "update", "patch", "*") {
				name := resource.name
				effective := name
				if name == "*" {
					name = "workload controllers"
					effective = "deployments"
				}
				api := group
				if api == "*" {
					api = "apps"
				}
				add("workload-controller-mutate", "medium", fmt.Sprintf("mutate %s; review pod templates and service-account bindings", name), api, effective)
			}
			if groupMatches(group, "") &&
				resourceMatches(resource, "pods", "") &&
				hasAnyVerb(rule.Verbs, "create", "*") {
				add("pod-create", "medium", "create pods is a heuristic risk when combined with privileged service accounts or permissive admission; not proof of breakout alone", "", "pods")
			}
			if groupMatches(group, "") &&
				(resourceMatches(resource, "pods", "exec") || resourceMatches(resource, "pods", "attach") || resourceMatches(resource, "pods", "portforward")) &&
				hasAnyVerb(rule.Verbs, "create", "get", "update", "*") {
				sub := resource.subresource
				if resource.name == "*" || sub == "" {
					sub = "exec|attach|portforward"
				}
				add("pod-interactive", "high", fmt.Sprintf("pods/%s enables interactive access to running workloads", sub), "", "pods")
			}
			if groupMatches(group, "") &&
				resourceMatches(resource, "secrets", "") &&
				hasAnyVerb(rule.Verbs, "get", "list", "watch", "*") {
				add("secrets-read", "high", "read access to secrets can expose credentials mounted or stored as Secret objects", "", "secrets")
			}
			if groupMatches(group, "") &&
				resourceMatches(resource, "nodes", "proxy") &&
				hasAnyVerb(rule.Verbs, "create", "get", "update", "*") {
				add("nodes-proxy", "high", "nodes/proxy can reach kubelet APIs and bypass some network controls", "", "nodes")
			}
			if groupMatches(group, "admissionregistration.k8s.io") &&
				(resourceMatches(resource, "validatingwebhookconfigurations", "") ||
					resourceMatches(resource, "mutatingwebhookconfigurations", "")) &&
				hasAnyVerb(rule.Verbs, "create", "update", "patch", "delete", "*") {
				name := resource.name
				effective := name
				if name == "*" {
					name = "admission webhook configurations"
					effective = "validatingwebhookconfigurations"
				}
				add("admission-policy-mutate", "high", fmt.Sprintf("mutation of %s can weaken or bypass admission controls", name), "admissionregistration.k8s.io", effective)
			}
		}
	}

	findings = append(findings, evaluateCustomPolicyRules(roleKey, binding, scope, subjects, rule)...)
	return findings
}

func evaluateCustomPolicyRules(roleKey RoleKey, binding BindingLike, scope string, subjects []string, rule PolicyRule) []Finding {
	if binding.Kind != "ClusterRoleBinding" {
		return nil
	}
	var findings []Finding
	apiGroups := rule.APIGroups
	if len(apiGroups) == 0 {
		return nil
	}
	for _, group := range apiGroups {
		if !groupMatches(group, "kyverno.io", "constraints.gatekeeper.sh", "templates.gatekeeper.sh", "policy") {
			continue
		}
		if !hasAnyVerb(rule.Verbs, "create", "update", "patch", "delete", "*") {
			continue
		}
		for _, resource := range expandResources(rule.Resources) {
			name := resource.name
			if name == "" || name == "*" {
				name = "policy resources"
			}
			desc := fmt.Sprintf("mutation of %s can weaken or bypass admission controls", name)
			resourceNames := append([]string(nil), rule.ResourceNames...)
			if len(resourceNames) > 0 {
				desc = fmt.Sprintf(
					"%s; constrained to resourceNames %v (named constraints do not make the permission safe by themselves)",
					desc,
					resourceNames,
				)
			}
			findings = append(findings, Finding{
				Code:          "admission-policy-mutate",
				Severity:      "high",
				Description:   desc,
				RoleKey:       roleKey,
				BindingKind:   binding.Kind,
				BindingName:   binding.Name,
				BindingScope:  scope,
				Subjects:      append([]string(nil), subjects...),
				ResourceNames: resourceNames,
			})
			break
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
