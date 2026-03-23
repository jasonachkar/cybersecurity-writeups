# Configuring Azure Firewall with UDR-Based Traffic Control

A hands-on walkthrough for deploying Azure Firewall, routing all workload traffic through it using User-Defined Routes (UDR), and enforcing granular network, application, and DNAT rules.

This guide covers the Azure Portal steps. A Terraform configuration that deploys the same environment is available in the `terraform/` folder.

---

## What You Will Build

- A hub-style network with a dedicated firewall subnet and a workload subnet
- An Azure Firewall inspecting all outbound traffic from the workload subnet
- A UDR forcing the default route (`0.0.0.0/0`) through the firewall
- Firewall rules that allow DNS resolution, permit access to `www.google.com`, and block everything else
- A DNAT rule enabling RDP access to a private VM through the firewall's public IP

By the end, navigating to `www.google.com` from the workload VM will succeed, while `www.bing.com` will be blocked -- demonstrating explicit allow-list enforcement at the network layer.

---

## Prerequisites

- An active Azure subscription
- Permissions to create resources (Contributor or Owner role on the subscription/resource group)
- Remote Desktop client for testing RDP access

---

## Phase 1: Setting the Foundation (Network)

### 1.1 Create the Resource Group

Navigate to **Resource Groups** > **Create**.

| Setting | Value |
|---|---|
| Name | `RG-Firewall-Demo` |
| Region | Your preferred region |

### 1.2 Create the Virtual Network

Navigate to **Virtual Networks** > **Create**.

| Setting | Value |
|---|---|
| Name | `VNet-Core` |
| Resource Group | `RG-Firewall-Demo` |
| Address Space | `10.0.0.0/16` |

### 1.3 Create the Subnets

Within `VNet-Core`, add two subnets:

| Subnet Name | Address Range | Notes |
|---|---|---|
| `AzureFirewallSubnet` | `10.0.1.0/26` | Azure requires this exact name and at least a /26 CIDR |
| `workload-SN` | `10.0.3.0/24` | Hosts the workload VM |

> **Why /26 for the firewall subnet?** Azure Firewall provisions multiple backend instances for availability. The /26 provides 64 addresses, which gives Azure enough room to scale the firewall internally. A smaller CIDR will fail validation.

---

## Phase 2: Deploying the Resources

### 2.1 Deploy the Workload VM

Navigate to **Virtual Machines** > **Create**.

| Setting | Value |
|---|---|
| Name | `Srv-Work` |
| Resource Group | `RG-Firewall-Demo` |
| Image | Windows Server 2022 Datacenter |
| Size | Standard_B2s (sufficient for testing) |
| Virtual Network | `VNet-Core` |
| Subnet | `workload-SN` |
| Public IP | None |

Set an admin username and password. Note the private IP once deployed (e.g., `10.0.3.4`).

> **No public IP on the VM.** The only way to reach this VM will be through the firewall's DNAT rule. This is the intended design: the firewall is the single ingress and egress point.

### 2.2 Deploy Azure Firewall

Navigate to **Firewalls** > **Create**.

| Setting | Value |
|---|---|
| Name | `FW-Core` |
| Resource Group | `RG-Firewall-Demo` |
| Virtual Network | `VNet-Core` |
| Subnet | `AzureFirewallSubnet` (auto-selected) |
| Public IP | Create new: `PIP-FW-Core` |
| SKU Tier | Standard |

Once deployed, note the firewall's private IP (e.g., `10.0.1.4`). You will need this for the route table.

> **Cost warning:** Azure Firewall Standard costs approximately $1.25/hr (~$30/day). Destroy all resources when you are done testing.

---

## Phase 3: Taking Control of Traffic (Routing)

This is the phase that makes the architecture work. Without the UDR, the workload subnet uses Azure's default system route for internet-bound traffic, which bypasses the firewall entirely.

### 3.1 Create the Route Table

Navigate to **Route Tables** > **Create**.

| Setting | Value |
|---|---|
| Name | `RT-Workload` |
| Resource Group | `RG-Firewall-Demo` |
| Propagate gateway routes | No |

### 3.2 Add the Default Route

Within `RT-Workload`, go to **Routes** > **Add**.

| Setting | Value |
|---|---|
| Route Name | `Route-To-Firewall` |
| Destination type | IP Addresses |
| Address prefix | `0.0.0.0/0` |
| Next hop type | Virtual appliance |
| Next hop address | `10.0.1.4` (private IP of `FW-Core`) |

### 3.3 Associate the Route Table with the Workload Subnet

Within `RT-Workload`, go to **Subnets** > **Associate**.

| Setting | Value |
|---|---|
| Virtual Network | `VNet-Core` |
| Subnet | `workload-SN` |

> **What just happened?** Every packet leaving `workload-SN` with a destination outside the VNet now gets routed to the firewall's private IP instead of going directly to the internet. The firewall becomes the chokepoint for all outbound traffic.

---

## Phase 4: Configuring Firewall Rules

With traffic now flowing through the firewall, everything is denied by default. You need to explicitly allow what should be permitted.

### 4.1 Network Rule: Allow DNS

Navigate to **FW-Core** > **Rules (classic)** or your Firewall Policy > **Network Rules** > **Add a rule collection**.

| Setting | Value |
|---|---|
| Collection Name | `Net-Rules` |
| Priority | 200 |
| Action | Allow |

| Rule Name | Protocol | Source | Destination | Destination Ports |
|---|---|---|---|---|
| `Allow-DNS` | UDP | `10.0.3.0/24` | `8.8.8.8`, `8.8.4.4` | `53` |

> **Why DNS first?** Application rules that filter by FQDN depend on DNS resolution. If the VM cannot resolve domain names, the application rules will never match. DNS is the foundation.

### 4.2 Application Rule: Allow Google

Navigate to **Application Rules** > **Add a rule collection**.

| Setting | Value |
|---|---|
| Collection Name | `App-Rules` |
| Priority | 300 |
| Action | Allow |

| Rule Name | Source | Protocol:Port | Target FQDN |
|---|---|---|---|
| `Allow-Google` | `10.0.3.0/24` | `HTTP:80`, `HTTPS:443` | `www.google.com` |

> **Implicit deny.** Azure Firewall denies all traffic that does not match an explicit allow rule. You do not need to create a "deny all" rule. Any FQDN not listed here (like `www.bing.com`) is automatically blocked.

### 4.3 DNAT Rule: RDP Access

Navigate to **DNAT Rules** > **Add a rule collection**.

| Setting | Value |
|---|---|
| Collection Name | `DNAT-Rules` |
| Priority | 100 |
| Action | DNAT |

| Rule Name | Protocol | Source | Destination IP | Destination Port | Translated Address | Translated Port |
|---|---|---|---|---|---|---|
| `Allow-RDP` | TCP | Your public IP (or `*`) | Public IP of `PIP-FW-Core` | `3389` | `10.0.3.4` | `3389` |

> **Lock down the source.** Using `*` as the source allows RDP from any IP on the internet. For anything beyond a quick test, replace this with your specific public IP. Run `curl ifconfig.me` from your terminal to find it.

---

## Phase 5: Final VM Configuration

The workload VM needs to use external DNS servers that the firewall's network rule permits.

1. Navigate to `Srv-Work` > **Networking** > click the NIC
2. Under **DNS servers**, select **Custom**
3. Enter `8.8.8.8` and `8.8.4.4`
4. **Restart** the `Srv-Work` VM for the DNS change to take effect

---

## Phase 6: Testing

### Connect to the VM

1. Open Remote Desktop Connection
2. Connect to the **firewall's public IP** (`PIP-FW-Core`), not the VM directly
3. Enter the admin credentials you set during VM creation

### Validate Firewall Rules

| Test | Expected Result |
|---|---|
| Open Edge, navigate to `www.google.com` | Page loads successfully |
| Navigate to `www.bing.com` | Blocked by firewall (connection timeout or reset) |
| Run `nslookup www.google.com` in Command Prompt | Resolves via `8.8.8.8` |

If `www.google.com` loads and `www.bing.com` is blocked, the firewall is enforcing your application rules correctly.

---

## Terraform Deployment

The `terraform/main.tf` file in this folder provisions the identical environment in a single `terraform apply`. It includes all six phases: networking, firewall, VM, routing, rules, and DNS configuration.

```bash
cd terraform/
terraform init
terraform plan -var="subscription_id=YOUR_SUB_ID" -var="vm_admin_password=YOUR_PASSWORD"
terraform apply -var="subscription_id=YOUR_SUB_ID" -var="vm_admin_password=YOUR_PASSWORD"
```

After testing, destroy all resources to avoid ongoing charges:

```bash
terraform destroy -var="subscription_id=YOUR_SUB_ID" -var="vm_admin_password=YOUR_PASSWORD"
```

---

## Key Concepts

**User-Defined Routes (UDR):** Override Azure's default routing behavior. In this walkthrough, the UDR forces all internet-bound traffic from the workload subnet to pass through the firewall instead of going directly out.

**Azure Firewall rule processing order:** DNAT rules are evaluated first, then network rules, then application rules. A packet matching a network rule is not evaluated against application rules. This matters when designing rule collections.

**Implicit deny:** Azure Firewall denies all traffic by default. Unlike NSGs (which have default allow rules for outbound internet), the firewall requires explicit allow rules for every permitted flow.

**DNAT for inbound access:** Since the workload VM has no public IP, the only way to reach it from the internet is through a DNAT rule on the firewall. The firewall translates the incoming connection from its public IP to the VM's private IP.

---

## Cleanup

Azure Firewall Standard costs approximately $1.25/hr. Delete the resource group when you are finished:

```bash
az group delete --name RG-Firewall-Demo --yes --no-wait
```

Or if using Terraform:

```bash
terraform destroy
```

---

## Author

This walkthrough is part of my [cybersecurity writeups repository](https://github.com/jasonachkar/cybersecurity-writeups), documenting hands-on security engineering across cloud security, identity, AppSec, and DevSecOps.