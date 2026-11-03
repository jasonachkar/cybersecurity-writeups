mock_provider "azurerm" {}

variables {
  tenant_id                  = "00000000-0000-0000-0000-000000000000"
  subscription_id            = "00000000-0000-0000-0000-000000000000"
  parent_management_group_id = "/providers/Microsoft.Management/managementGroups/synthetic-lab-parent"
  subject                    = "repo:lab-owner/lab-research:environment:lab"
}

run "audit_first_and_scoped_identity" {
  command = plan
  assert {
    condition     = jsondecode(azurerm_policy_definition.locations.policy_rule).then.effect == "audit"
    error_message = "Default must remain audit pending impact review."
  }
  assert {
    condition     = length(azurerm_management_group.children) == 3 && azurerm_role_assignment.read_evidence.role_definition_name == "Log Analytics Reader"
    error_message = "Preserve hierarchy and read-only evidence identity."
  }
  assert {
    condition     = azurerm_log_analytics_workspace.lab.daily_quota_gb == 1 && length(azurerm_monitor_diagnostic_setting.activity.enabled_log) == 3
    error_message = "Keep bounded logging with an explicit source set."
  }
}

run "disabled_policy_rejected" {
  command = plan
  variables { policy_effect = "Disabled" }
  expect_failures = [var.policy_effect]
}

run "wildcard_federation_rejected" {
  command = plan
  variables { subject = "repo:lab-owner/*:environment:lab" }
  expect_failures = [var.subject]
}
