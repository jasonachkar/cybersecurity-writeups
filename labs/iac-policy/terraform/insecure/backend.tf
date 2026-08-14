terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  backend "s3" {
    bucket         = "example-insecure-state"
    key            = "shared/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "legacy-state-locks"
    encrypt        = false
  }
}

# INTENTIONALLY INSECURE FIXTURE:
# - DynamoDB locking is deprecated for the S3 backend.
# - S3 lockfile locking is not enabled.
# - State is shared and is not configured with a customer-managed KMS key.
