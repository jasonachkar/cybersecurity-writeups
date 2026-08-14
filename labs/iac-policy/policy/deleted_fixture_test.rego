package terraform.security

import rego.v1

test_deleted_security_control_is_rejected if {
	plan := {
		"format_version": data.format_version,
		"terraform_version": data.terraform_version,
		"resource_changes": data.resource_changes,
	}
	results := deny with input as plan
	some result in results
	result.reason == "plan deletes a modeled security control"
}
