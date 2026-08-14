package terraform.security

import rego.v1

test_unknown_values_fail_closed if {
	plan := {
		"format_version": data.format_version,
		"terraform_version": data.terraform_version,
		"resource_changes": data.resource_changes,
	}
	results := deny with input as plan
	some result in results
	result.reason == "security-relevant database value is unknown at policy evaluation"
}
