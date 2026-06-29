// Purpose: Simulates and validates AWS Service Control Policy (SCP) evaluation logic across nested Organizational Units (OUs) to detect policy conflicts or unintended blocks.
package main

import (
	"fmt"
	"strings"
)

// Policy represents a simple SCP with its Statements.
type Policy struct {
	Name       string
	Statements []SCPStatement
}

// SCPStatement represents an individual SCP permission statement.
type SCPStatement struct {
	Effect   string   // Allow or Deny
	Action   []string // e.g. ["*"], ["s3:*"], ["iam:DeleteRole"]
	Resource []string // e.g. ["*"]
}

// OrgNode represents a level in the AWS Organizations hierarchy (Root, OU, or Account).
type OrgNode struct {
	Name     string
	Type     string // ROOT, OU, ACCOUNT
	Policies []Policy
	Parent   *OrgNode
}

// MatchesAction checks if an action matches the patterns in the statement.
func MatchesAction(action string, patterns []string) bool {
	action = strings.ToLower(action)
	for _, pattern := range patterns {
		pattern = strings.ToLower(pattern)
		if pattern == "*" {
			return true
		}
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(action, prefix) {
				return true
			}
		}
		if action == pattern {
			return true
		}
	}
	return false
}

// MatchesResource checks if a resource matches the patterns in the statement.
func MatchesResource(resource string, patterns []string) bool {
	// For simplicity in simulation, we support basic wildcard matching
	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}
		if strings.Contains(pattern, "*") {
			prefix := strings.Split(pattern, "*")[0]
			if strings.HasPrefix(resource, prefix) {
				return true
			}
		}
		if resource == pattern {
			return true
		}
	}
	return false
}

// EvaluateAction determines if an action is permitted through the organization hierarchy to the target account.
// AWS SCP Evaluation Rule:
// 1. Default is implicit deny.
// 2. An explicit Deny at any level blocks the request immediately.
// 3. For an action to be allowed, it must be explicitly allowed at every level of the hierarchy (e.g. via FullAWSAccess or custom allows).
func EvaluateAction(action string, resource string, leaf *OrgNode) (bool, string) {
	// Build the path from leaf to root
	var path []*OrgNode
	curr := leaf
	for curr != nil {
		path = append([]*OrgNode{curr}, path...) // prepend to preserve root-to-leaf order
		curr = curr.Parent
	}

	fmt.Printf("Evaluating path: ")
	for i, node := range path {
		if i > 0 {
			fmt.Print(" -> ")
		}
		fmt.Printf("[%s: %s]", node.Type, node.Name)
	}
	fmt.Println()

	// Step 1: Check for any explicit DENY across all levels (evaluated globally)
	for _, node := range path {
		for _, policy := range node.Policies {
			for _, stmt := range policy.Statements {
				if strings.ToLower(stmt.Effect) == "deny" {
					if MatchesAction(action, stmt.Action) && MatchesResource(resource, stmt.Resource) {
						return false, fmt.Sprintf("Blocked by explicit DENY in policy '%s' at level [%s: %s]", policy.Name, node.Type, node.Name)
					}
				}
			}
		}
	}

	// Step 2: Ensure there is an explicit ALLOW at each level of the hierarchy.
	// In AWS Organizations, if any level does not allow the action (either via FullAWSAccess or a specific rule), the evaluation fails (implicit deny).
	for _, node := range path {
		levelAllowed := false
		for _, policy := range node.Policies {
			for _, stmt := range policy.Statements {
				if strings.ToLower(stmt.Effect) == "allow" {
					if MatchesAction(action, stmt.Action) && MatchesResource(resource, stmt.Resource) {
						levelAllowed = true
						break
					}
				}
			}
			if levelAllowed {
				break
			}
		}
		if !levelAllowed {
			return false, fmt.Sprintf("Blocked by implicit DENY: Action not allowed at level [%s: %s]", node.Type, node.Name)
		}
	}

	return true, "Allowed by SCP tree verification"
}

func main() {
	fmt.Println("==================================================")
	fmt.Println("🛡️ AWS Organizations SCP Hierarchy Simulator")
	fmt.Println("==================================================")

	// Create policies
	fullAWSAccess := Policy{
		Name: "FullAWSAccess",
		Statements: []SCPStatement{
			{Effect: "Allow", Action: []string{"*"}, Resource: []string{"*"}},
		},
	}

	restrictiveS3 := Policy{
		Name: "RestrictiveS3Only",
		Statements: []SCPStatement{
			{Effect: "Allow", Action: []string{"s3:*"}, Resource: []string{"*"}},
		},
	}

	denyRootUser := Policy{
		Name: "DenyRootUserUsage",
		Statements: []SCPStatement{
			{Effect: "Deny", Action: []string{"*"}, Resource: []string{"*"}}, // Simplified; normally condition matches Root account user
		},
	}

	denyLeavingOrg := Policy{
		Name: "DenyLeaveOrganization",
		Statements: []SCPStatement{
			{Effect: "Deny", Action: []string{"organizations:LeaveOrganization"}, Resource: []string{"*"}},
		},
	}

	// Build hierarchy
	// Root -> SecurityOU -> ProdAccount
	rootNode := &OrgNode{Name: "Root-OU", Type: "ROOT", Policies: []Policy{fullAWSAccess, denyLeavingOrg}}
	
	securityOU := &OrgNode{
		Name:     "Security-Core-OU",
		Type:     "OU",
		Policies: []Policy{fullAWSAccess},
		Parent:   rootNode,
	}

	prodAccount := &OrgNode{
		Name:     "Production-App-Account",
		Type:     "ACCOUNT",
		Policies: []Policy{fullAWSAccess},
		Parent:   securityOU,
	}

	// SandboxOU (does not inherit FullAWSAccess if we replace it, but let's test a restricted OU)
	sandboxOU := &OrgNode{
		Name:     "Sandbox-OU",
		Type:     "OU",
		Policies: []Policy{restrictiveS3}, // Custom allowed list: only S3
		Parent:   rootNode,
	}

	devAccount := &OrgNode{
		Name:     "Dev-Test-Account",
		Type:     "ACCOUNT",
		Policies: []Policy{fullAWSAccess},
		Parent:   sandboxOU,
	}

	// Test Case 1: Standard permitted action in Production
	fmt.Println("\n[Test 1] Can Prod Account run 's3:CreateBucket'?")
	allowed, reason := EvaluateAction("s3:CreateBucket", "arn:aws:s3:::my-bucket", prodAccount)
	fmt.Printf("Result: %t. Reason: %s\n", allowed, reason)

	// Test Case 2: Action blocked by explicit deny in Root
	fmt.Println("\n[Test 2] Can Prod Account run 'organizations:LeaveOrganization'?")
	allowed, reason = EvaluateAction("organizations:LeaveOrganization", "*", prodAccount)
	fmt.Printf("Result: %t. Reason: %s\n", allowed, reason)

	// Test Case 3: Action blocked due to restriction in intermediate OU (Sandbox has only S3 allowed)
	fmt.Println("\n[Test 3] Can Dev Account run 'ec2:RunInstances'?")
	allowed, reason = EvaluateAction("ec2:RunInstances", "*", devAccount)
	fmt.Printf("Result: %t. Reason: %s\n", allowed, reason)

	// Test Case 4: Action allowed in Sandbox OU (S3 allowed at sandbox, full access at account)
	fmt.Println("\n[Test 4] Can Dev Account run 's3:ListBucket'?")
	allowed, reason = EvaluateAction("s3:ListBucket", "arn:aws:s3:::my-sandbox-bucket", devAccount)
	fmt.Printf("Result: %t. Reason: %s\n", allowed, reason)

	// Test Case 5: Root OU has root-denial policy added
	fmt.Println("\n[Test 5] Attaching explicit '*' deny policy at root to test global block.")
	rootNode.Policies = append(rootNode.Policies, denyRootUser)
	allowed, reason = EvaluateAction("s3:ListBucket", "*", prodAccount)
	fmt.Printf("Result: %t. Reason: %s\n", allowed, reason)
}
