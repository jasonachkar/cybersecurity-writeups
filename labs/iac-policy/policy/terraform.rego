package terraform.security

import rego.v1

active(resource) if {
	not "delete" in resource.change.actions
}

deleted(resource) if {
	"delete" in resource.change.actions
}

has_bucket_control(resource_type, bucket) if {
	some control in input.resource_changes
	control.type == resource_type
	active(control)
	control.change.after.bucket == bucket
}

has_required_tags(resource) if {
	is_object(resource.change.after.tags)
	is_string(resource.change.after.tags.Environment)
	resource.change.after.tags.Environment != ""
	is_string(resource.change.after.tags.Owner)
	resource.change.after.tags.Owner != ""
}

wildcard(value) if {
	is_string(value)
	value == "*"
}

wildcard(value) if {
	is_array(value)
	"*" in value
}

deny contains {
	"address": resource.address,
	"reason": "S3 bucket has a public ACL",
} if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_acl"
	active(resource)
	resource.change.after.acl in {"public-read", "public-read-write", "authenticated-read"}
}

deny contains {
	"address": resource.address,
	"reason": "S3 bucket is missing a complete public-access block",
} if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	active(resource)
	not has_bucket_control("aws_s3_bucket_public_access_block", resource.change.after.bucket)
}

deny contains {
	"address": resource.address,
	"reason": "S3 bucket is missing server-side encryption configuration",
} if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	active(resource)
	not has_bucket_control("aws_s3_bucket_server_side_encryption_configuration", resource.change.after.bucket)
}

deny contains {
	"address": resource.address,
	"reason": "S3 bucket is missing access logging configuration",
} if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	active(resource)
	not has_bucket_control("aws_s3_bucket_logging", resource.change.after.bucket)
}

deny contains {
	"address": resource.address,
	"reason": "security group exposes ingress to the public internet",
} if {
	some resource in input.resource_changes
	resource.type == "aws_security_group"
	active(resource)
	some ingress in resource.change.after.ingress
	some cidr in ingress.cidr_blocks
	cidr in {"0.0.0.0/0", "::/0"}
}

deny contains {
	"address": resource.address,
	"reason": "database is publicly accessible",
} if {
	some resource in input.resource_changes
	resource.type == "aws_db_instance"
	active(resource)
	resource.change.after.publicly_accessible == true
}

deny contains {
	"address": resource.address,
	"reason": "database storage encryption is disabled",
} if {
	some resource in input.resource_changes
	resource.type == "aws_db_instance"
	active(resource)
	resource.change.after.storage_encrypted != true
	not resource.change.after_unknown.storage_encrypted
}

deny contains {
	"address": resource.address,
	"reason": "security-relevant database value is unknown at policy evaluation",
} if {
	some resource in input.resource_changes
	resource.type == "aws_db_instance"
	active(resource)
	some field in {"publicly_accessible", "storage_encrypted"}
	resource.change.after_unknown[field] == true
}

deny contains {
	"address": resource.address,
	"reason": "IAM policy allows wildcard action and resource",
} if {
	some resource in input.resource_changes
	resource.type == "aws_iam_policy"
	active(resource)
	document := json.unmarshal(resource.change.after.policy)
	some statement in document.Statement
	statement.Effect == "Allow"
	wildcard(statement.Action)
	wildcard(statement.Resource)
}

deny contains {
	"address": resource.address,
	"reason": "authorization-driving Environment and Owner tags are required",
} if {
	some resource in input.resource_changes
	resource.type in {"aws_s3_bucket", "aws_security_group", "aws_db_instance", "aws_iam_policy"}
	active(resource)
	not has_required_tags(resource)
}

deny contains {
	"address": resource.address,
	"reason": "plan deletes a modeled security control",
} if {
	some resource in input.resource_changes
	resource.type in {
		"aws_s3_bucket_public_access_block",
		"aws_s3_bucket_server_side_encryption_configuration",
		"aws_s3_bucket_logging",
	}
	deleted(resource)
}
