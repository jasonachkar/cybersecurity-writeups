terraform {
  required_version = ">= 1.7.0, < 2.0.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.50.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id                 = var.subscription_id
  tenant_id                       = var.tenant_id
  use_oidc                        = true
  use_cli                         = false
  resource_provider_registrations = "none"
}

variable "tenant_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f-]{36}$", var.tenant_id))
    error_message = "Use a dedicated lab tenant UUID."
  }
}

variable "subscription_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f-]{36}$", var.subscription_id))
    error_message = "Use a dedicated lab subscription UUID."
  }
}

variable "parent_management_group_id" {
  type        = string
  description = "Existing isolated parent; never place the lab at the tenant root."
  validation {
    condition     = can(regex("^/providers/Microsoft.Management/managementGroups/[a-zA-Z0-9-]+$", var.parent_management_group_id))
    error_message = "Use the resource ID of the isolated existing parent."
  }
}

variable "prefix" {
  type    = string
  default = "research-lz"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,19}$", var.prefix))
    error_message = "Use a short lab-only resource prefix."
  }
}

variable "subject" {
  type        = string
  description = "Exact GitHub environment subject actually observed; no default."
  validation {
    condition     = can(regex("^repo:[^*?<> ]+/[^*?<> ]+:environment:lab$", var.subject))
    error_message = "Use an exact repository subject bound to the protected lab environment."
  }
}

variable "policy_effect" {
  type    = string
  default = "audit"
  validation {
    condition     = contains(["audit", "deny"], var.policy_effect)
    error_message = "Only audit or deny; Disabled is deliberately unavailable."
  }
}

resource "azurerm_management_group" "root" {
  name                       = var.prefix
  display_name               = "Isolated research landing-zone root"
  parent_management_group_id = var.parent_management_group_id
}

resource "azurerm_management_group" "children" {
  for_each                   = toset(["platform", "landing-zones", "sandbox"])
  name                       = "${var.prefix}-${each.key}"
  display_name               = each.key
  parent_management_group_id = azurerm_management_group.root.id
}

resource "azurerm_policy_definition" "locations" {
  name                = "${var.prefix}-locations"
  policy_type         = "Custom"
  mode                = "Indexed"
  display_name        = "Lab location guardrail"
  management_group_id = azurerm_management_group.root.id
  policy_rule = jsonencode({
    if = { allOf = [
      { field = "location", exists = "true" },
      { field = "location", notIn = ["canadacentral", "canadaeast", "global"] }
    ] }
    then = { effect = var.policy_effect }
  })
}

resource "azurerm_management_group_policy_assignment" "locations" {
  name                 = "${var.prefix}-locations"
  display_name         = "Lab location guardrail — impact review required before deny"
  policy_definition_id = azurerm_policy_definition.locations.id
  management_group_id  = azurerm_management_group.root.id
  enforce              = true
}

# The subscription stays in its existing hierarchy. No subscription moves,
# subscription vending, provider registration, networks or public endpoints.
resource "azurerm_resource_group" "logs" {
  name     = "${var.prefix}-logs"
  location = "canadacentral"
}

resource "azurerm_log_analytics_workspace" "lab" {
  name                = "${var.prefix}-workspace"
  resource_group_name = azurerm_resource_group.logs.name
  location            = azurerm_resource_group.logs.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
  daily_quota_gb      = 1
}

resource "azurerm_monitor_diagnostic_setting" "activity" {
  name                       = "${var.prefix}-activity"
  target_resource_id         = "/subscriptions/${var.subscription_id}"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id
  dynamic "enabled_log" {
    for_each = toset(["Administrative", "Policy", "Security"])
    content {
      category = enabled_log.value
    }
  }
}

resource "azurerm_user_assigned_identity" "reader" {
  name                = "${var.prefix}-evidence-reader"
  resource_group_name = azurerm_resource_group.logs.name
  location            = azurerm_resource_group.logs.location
}

resource "azurerm_federated_identity_credential" "github" {
  name                = "lab-evidence-review"
  resource_group_name = azurerm_resource_group.logs.name
  parent_id           = azurerm_user_assigned_identity.reader.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = "https://token.actions.githubusercontent.com"
  subject             = var.subject
}

resource "azurerm_role_assignment" "read_evidence" {
  scope                = azurerm_log_analytics_workspace.lab.id
  role_definition_name = "Log Analytics Reader"
  principal_id         = azurerm_user_assigned_identity.reader.principal_id
}

output "review_contract" {
  value = {
    root              = azurerm_management_group.root.id
    policy_effect     = var.policy_effect
    log_categories    = ["Administrative", "Policy", "Security"]
    subscription_move = "not configured; assignment inheritance for this subscription is not established"
    identity_scope    = "workspace read-only; bootstrap authority is external"
  }
}
