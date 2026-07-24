package terraform.security

import rego.v1

fixture_plan := {
	"format_version": data.format_version,
	"terraform_version": data.terraform_version,
	"resource_changes": data.resource_changes,
}

test_public_storage_is_rejected if {
	results := deny with input as fixture_plan
	reasons := {result.reason | some result in results}
	"S3 bucket has a public ACL" in reasons
	"S3 bucket is missing a complete public-access block" in reasons
	"S3 bucket is missing server-side encryption configuration" in reasons
	"S3 bucket is missing access logging configuration" in reasons
}

test_public_network_database_iam_and_tags_are_rejected if {
	results := deny with input as fixture_plan
	reasons := {result.reason | some result in results}
	"security group exposes ingress to the public internet" in reasons
	"database is publicly accessible" in reasons
	"database storage encryption is disabled" in reasons
	"IAM policy allows wildcard action and resource" in reasons
	"authorization-driving Environment and Owner tags are required" in reasons
}
