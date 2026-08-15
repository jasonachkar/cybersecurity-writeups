# =============================================================================
# Azure Firewall Demo - Terraform Configuration
# =============================================================================
# This Terraform config provisions the exact same resources demonstrated in the
# portal walkthrough video. It deploys an Azure Firewall with UDR-based traffic
# control, network/application/DNAT rules, and a workload VM for testing.
#
# Usage:
#   terraform init
#   terraform plan -out=tfplan
#   terraform apply tfplan
#
# Cleanup (important because a Firewall costs ~$1.25/hr):
#   terraform destroy
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

# =============================================================================
# Variables
# =============================================================================

variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "canadacentral"
}

variable "vm_admin_username" {
  description = "Admin username for the workload VM"
  type        = string
  default     = "azureadmin"
}

variable "vm_admin_password" {
  description = "Admin password for the workload VM (use a secrets manager in production)"
  type        = string
  sensitive   = true
}

variable "allowed_rdp_source_ip" {
  description = "Your public IP for RDP access via DNAT (use 'curl ifconfig.me' to find it)"
  type        = string
  default     = "*"
}

# =============================================================================
# Phase 1: Setting the Foundation (Network)
# =============================================================================

resource "azurerm_resource_group" "demo" {
  name     = "RG-Firewall-Demo"
  location = var.location
}

resource "azurerm_virtual_network" "core" {
  name                = "VNet-Core"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
}

# Azure requires this exact name and at least a /26 CIDR for the firewall subnet
resource "azurerm_subnet" "firewall" {
  name                 = "AzureFirewallSubnet"
  resource_group_name  = azurerm_resource_group.demo.name
  virtual_network_name = azurerm_virtual_network.core.name
  address_prefixes     = ["10.0.1.0/26"]
}

resource "azurerm_subnet" "workload" {
  name                 = "workload-SN"
  resource_group_name  = azurerm_resource_group.demo.name
  virtual_network_name = azurerm_virtual_network.core.name
  address_prefixes     = ["10.0.3.0/24"]
}

# =============================================================================
# Phase 2: Deploying the Resources
# =============================================================================

# --- Azure Firewall ---

resource "azurerm_public_ip" "fw" {
  name                = "PIP-FW-Core"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_firewall" "core" {
  name                = "FW-Core"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"
  firewall_policy_id  = azurerm_firewall_policy.demo.id

  ip_configuration {
    name                 = "fw-ip-config"
    subnet_id            = azurerm_subnet.firewall.id
    public_ip_address_id = azurerm_public_ip.fw.id
  }
}

# --- Workload VM (Windows Server) ---

resource "azurerm_network_interface" "workload" {
  name                = "NIC-Srv-Work"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.workload.id
    private_ip_address_allocation = "Dynamic"
  }

  # Phase 5: Custom DNS pointing to Google DNS (required for firewall-controlled resolution)
  dns_servers = ["8.8.8.8", "8.8.4.4"]
}

resource "azurerm_windows_virtual_machine" "workload" {
  name                = "Srv-Work"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
  size                = "Standard_B2s"
  admin_username      = var.vm_admin_username
  admin_password      = var.vm_admin_password

  network_interface_ids = [azurerm_network_interface.workload.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }
}

# =============================================================================
# Phase 3: Taking Control of Traffic (Routing)
# =============================================================================

resource "azurerm_route_table" "workload" {
  name                = "RT-Workload"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name

  # Prevent BGP from overriding our UDR (good practice for demo isolation)
  bgp_route_propagation_enabled = false
}

resource "azurerm_route" "to_firewall" {
  name                   = "Route-To-Firewall"
  resource_group_name    = azurerm_resource_group.demo.name
  route_table_name       = azurerm_route_table.workload.name
  address_prefix         = "0.0.0.0/0"
  next_hop_type          = "VirtualAppliance"
  next_hop_in_ip_address = azurerm_firewall.core.ip_configuration[0].private_ip_address
}

resource "azurerm_subnet_route_table_association" "workload" {
  subnet_id      = azurerm_subnet.workload.id
  route_table_id = azurerm_route_table.workload.id
}

# =============================================================================
# Phase 4: Configuring Firewall Rules
# =============================================================================

resource "azurerm_firewall_policy" "demo" {
  name                = "FWPolicy-Demo"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
}

resource "azurerm_firewall_policy_rule_collection_group" "demo" {
  name               = "DefaultRuleCollectionGroup"
  firewall_policy_id = azurerm_firewall_policy.demo.id
  priority           = 200

  # --- DNAT Rule: RDP into workload VM via Firewall public IP ---
  nat_rule_collection {
    name     = "DNAT-Rules"
    priority = 100
    action   = "Dnat"

    rule {
      name                = "Allow-RDP"
      protocols           = ["TCP"]
      source_addresses    = [var.allowed_rdp_source_ip]
      destination_address = azurerm_public_ip.fw.ip_address
      destination_ports   = ["3389"]
      translated_address  = azurerm_network_interface.workload.private_ip_address
      translated_port     = "3389"
    }
  }

  # --- Network Rule: Allow DNS to Google ---
  network_rule_collection {
    name     = "Network-Rules"
    priority = 200
    action   = "Allow"

    rule {
      name                  = "Allow-DNS"
      protocols             = ["UDP"]
      source_addresses      = ["10.0.3.0/24"]
      destination_addresses = ["8.8.8.8", "8.8.4.4"]
      destination_ports     = ["53"]
    }
  }

  # --- Application Rule: Allow only google.com over HTTP/HTTPS ---
  application_rule_collection {
    name     = "Application-Rules"
    priority = 300
    action   = "Allow"

    rule {
      name             = "Allow-Google"
      source_addresses = ["10.0.3.0/24"]
      destination_fqdns = ["www.google.com"]

      protocols {
        type = "Http"
        port = 80
      }

      protocols {
        type = "Https"
        port = 443
      }
    }
  }
}

# =============================================================================
# Outputs
# =============================================================================

output "firewall_public_ip" {
  description = "Public IP of the firewall (use this for RDP)"
  value       = azurerm_public_ip.fw.ip_address
}

output "firewall_private_ip" {
  description = "Private IP of the firewall (used as UDR next hop)"
  value       = azurerm_firewall.core.ip_configuration[0].private_ip_address
}

output "workload_vm_private_ip" {
  description = "Private IP of the workload VM"
  value       = azurerm_network_interface.workload.private_ip_address
}

output "rdp_connection_command" {
  description = "Connect to the workload VM via the firewall's public IP"
  value       = "mstsc /v:${azurerm_public_ip.fw.ip_address}"
}

output "estimated_hourly_cost" {
  description = "Reminder: Azure Firewall Standard costs ~$1.25/hr. Run 'terraform destroy' when done."
  value       = "~$1.25/hr for Azure Firewall + ~$0.05/hr for B2s VM"
}
