// Purpose: Scans simulated or provided AWS IAM policy documents (in JSON format) for over-permissive configurations, wildcards, and privilege escalation paths.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PolicyDocument represents a standard AWS IAM policy structure.
type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Statement represents an individual policy statement block.
type Statement struct {
	Sid       string      `json:"Sid,omitempty"`
	Effect    string      `json:"Effect"`
	Action    interface{} `json:"Action"`   // Can be string or array of strings
	Resource  interface{} `json:"Resource"` // Can be string or array of strings
	Condition interface{} `json:"Condition,omitempty"`
}

// Helper to convert interface{} action/resource into standard string slice.
func getSlice(input interface{}) []string {
	if input == nil {
		return nil
	}
	switch val := input.(type) {
	case string:
		return []string{val}
	case []interface{}:
		var out []string
		for _, item := range val {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	case []string:
		return val
	}
	return nil
}

// List of AWS actions that can lead to privilege escalation.
// Source: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
var privEscActions = map[string]string{
	"iam:createpolicyversion":      "CreatePolicyVersion: Allows creating a new policy version, setting it to default, leading to full IAM privilege modification.",
	"iam:setdefaultpolicyversion":  "SetDefaultPolicyVersion: Allows setting an existing inactive policy version as default, bypassing checks.",
	"iam:passrole":                 "PassRole: Combined with EC2/Glue/Lambda creation, allows passing high-privilege roles to compute resources.",
	"iam:createaccesskey":          "CreateAccessKey: Allows creating new access keys for other users, bypassing their MFA configuration.",
	"iam:createuser":               "CreateUser: Allows creating arbitrary IAM users.",
	"iam:addusertogroup":           "AddUserToGroup: Allows adding current user or arbitrary user to administrative groups.",
	"iam:attachuserpolicy":         "AttachUserPolicy: Directly attaches administrative policies to user accounts.",
	"iam:attachgrouppolicy":        "AttachGroupPolicy: Attaches administrative policies to a group the user belongs to.",
	"iam:attachrolepolicy":         "AttachRolePolicy: Attaches administrative policies to a role the user can assume.",
	"iam:putuserpolicy":            "PutUserPolicy: Creates/updates inline administrative policies on user accounts.",
	"iam:putgrouppolicy":           "PutGroupPolicy: Creates/updates inline administrative policies on group accounts.",
	"iam:putrolepolicy":            "PutRolePolicy: Creates/updates inline administrative policies on roles.",
	"iam:updateassumerolepolicy":   "UpdateAssumeRolePolicy: Alters trust relationships of roles, allowing external cross-account access.",
	"iam:createloginprofile":       "CreateLoginProfile: Allows setting/resetting passwords for console access.",
	"iam:updateloginprofile":       "UpdateLoginProfile: Allows modifying console passwords for existing administrative users.",
}

func main() {
	// Sample policy demonstrating multiple critical misconfigurations.
	samplePolicyJSON := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "AllowAllGlobalActions",
				"Effect": "Allow",
				"Action": "*",
				"Resource": "*"
			},
			{
				"Sid": "PrivilegeEscalationVector1",
				"Effect": "Allow",
				"Action": ["iam:CreatePolicyVersion", "iam:PassRole"],
				"Resource": "arn:aws:iam::123456789012:role/admin-role"
			},
			{
				"Sid": "DangerousWildcardResource",
				"Effect": "Allow",
				"Action": "s3:GetObject",
				"Resource": "*"
			}
		]
	}`

	fmt.Println("==================================================")
	fmt.Println("AWS IAM Policy Analyzer & Privilege Escalation Scanner")
	fmt.Println("==================================================")

	var doc PolicyDocument
	err := json.Unmarshal([]byte(samplePolicyJSON), &doc)
	if err != nil {
		fmt.Printf("Error parsing policy: %v\n", err)
		return
	}

	findings := 0

	for _, stmt := range doc.Statement {
		if strings.ToLower(stmt.Effect) != "allow" {
			continue
		}

		actions := getSlice(stmt.Action)
		resources := getSlice(stmt.Resource)

		// 1. Audit Wildcard Action and Resource
		hasWildcardAction := false
		for _, action := range actions {
			if action == "*" {
				hasWildcardAction = true
				break
			}
		}

		hasWildcardResource := false
		for _, res := range resources {
			if res == "*" {
				hasWildcardResource = true
				break
			}
		}

		if hasWildcardAction && hasWildcardResource {
			fmt.Printf("[CRITICAL] Statement '%s' allows Administrator Access ('*' on '*').\n", stmt.Sid)
			findings++
		} else if hasWildcardAction {
			fmt.Printf("[HIGH] Statement '%s' contains wildcard action '*' over resources: %v.\n", stmt.Sid, resources)
			findings++
		}

		// 2. Audit Privilege Escalation Risks
		for _, action := range actions {
			loweredAction := strings.ToLower(action)
			if desc, exists := privEscActions[loweredAction]; exists {
				fmt.Printf("[HIGH] Privilege Escalation risk in statement '%s': %s (Target Resource: %v)\n", stmt.Sid, desc, resources)
				findings++
			}
		}

		// 3. Unsafe Resource Wildcard with sensitive operations
		for _, action := range actions {
			loweredAction := strings.ToLower(action)
			if hasWildcardResource && (strings.HasPrefix(loweredAction, "s3:") || strings.HasPrefix(loweredAction, "dynamodb:") || strings.HasPrefix(loweredAction, "rds:")) {
				if loweredAction != "s3:*" && !strings.Contains(loweredAction, "list") && !strings.Contains(loweredAction, "describe") {
					fmt.Printf("[MEDIUM] Data store action '%s' configured with wildcard '*' resource in statement '%s'.\n", action, stmt.Sid)
					findings++
				}
			}
		}
	}

	fmt.Printf("\nScan completed. Found %d issues.\n", findings)
}
