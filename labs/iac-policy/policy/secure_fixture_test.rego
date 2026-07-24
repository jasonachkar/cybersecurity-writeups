package terraform.security

import rego.v1

test_secure_plan_is_accepted if {
	plan := {
		"format_version": data.format_version,
		"terraform_version": data.terraform_version,
		"resource_changes": data.resource_changes,
	}
	results := deny with input as plan
	count(results) == 0
}
