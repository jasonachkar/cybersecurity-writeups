terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  backend "s3" {
    bucket       = "example-security-state"
    key          = "production/security-platform/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    kms_key_id   = "arn:aws:kms:us-east-1:111122223333:key/<state-key-id>"
    use_lockfile = true
  }
}

# Bootstrap controls that cannot be expressed in this backend block:
# - enable bucket versioning and recovery procedures;
# - block public access and restrict state/tflock object paths;
# - allow GetObject/PutObject on state and Get/Put/DeleteObject on .tflock;
# - restrict KMS Encrypt/Decrypt/GenerateDataKey and audit both S3 and KMS access;
# - separate production state identities from lower-environment identities.
