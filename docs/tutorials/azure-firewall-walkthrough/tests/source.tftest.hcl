mock_provider "azurerm" {}

variables {
  subscription_id       = "00000000-0000-0000-0000-000000000000"
  vm_admin_password     = "<runtime-generated-lab-Password>"
  allowed_rdp_source_ip = "192.0.2.1/32"
}

run "single_synthetic_source" {
  command = plan
  assert {
    condition     = var.allowed_rdp_source_ip == "192.0.2.1/32"
    error_message = "The positive test must stay on a documentation address."
  }
}

run "wildcard_rejected" {
  command = plan
  variables { allowed_rdp_source_ip = "*" }
  expect_failures = [var.allowed_rdp_source_ip]
}

run "broad_prefix_rejected" {
  command = plan
  variables { allowed_rdp_source_ip = "0.0.0.0/0" }
  expect_failures = [var.allowed_rdp_source_ip]
}
