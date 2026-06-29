# <img src="/docs/assets/images/azure-logo.svg" alt="Azure Logo" width="36" height="36" style="vertical-align: middle; margin-right: 10px;"> AZ-900 Domain 1: Describe Cloud Concepts

This section covers the core cloud concepts required for the AZ-900 exam.

---

## 1. Cloud Computing Benefits

Cloud computing is the delivery of computing services over the internet on a pay-as-you-go consumption model.

### 1.1 High Availability (HA)
High availability ensures that your applications and resources remain accessible to users with minimal downtime, even in the event of hardware or system failures. In Azure, HA is structured around:
* **Service Level Agreements (SLAs):** Microsoft's commitment to uptime (e.g., 99.9%, 99.99%).
* **Composite SLAs:** When multiple services work together, their SLAs multiply.
    $$\text{Composite SLA} = \text{SLA}_{\text{Web App}} \times \text{SLA}_{\text{Database}}$$
    For instance:
    $$0.9995 \times 0.9999 = 99.94\%$$

### 1.2 Scalability (Vertical vs. Horizontal)
* **Vertical Scaling (Scale Up):** Adding more CPU or RAM to an existing Virtual Machine (e.g., upgrading from a Standard D2s to a Standard D4s). This usually requires a reboot.
* **Horizontal Scaling (Scale Out):** Adding more VM instances to handle traffic spikes (e.g., scaling a Scale Set from 2 to 5 instances). No downtime required.

### 1.3 Elasticity & Autoscale
Elasticity allows cloud resources to autoscale out (add instances) when traffic spikes, and scale in (remove instances) when traffic drops. This prevents over-provisioning and saves cost.

### 1.4 Agility & Deployability
Agility represents the speed and ease with which resources can be allocated. Developers can spin up VMs, databases, and networks in seconds using ARM templates or Terraform, bypassing long procurement lifecycles.

### 1.5 Fault Tolerance & Disaster Recovery
* **Fault Tolerance:** Resiliency against localized hardware faults (e.g., power or disk failures).
* **Disaster Recovery (DR):** The strategy for recovering from a catastrophic event (e.g., regional power grid failure) using data backups and multi-region replication.
    * *RPO (Recovery Point Objective):* Acceptable volume of data loss.
    * *RTO (Recovery Time Objective):* Acceptable system recovery duration.

---

## 2. CapEx vs. OpEx Financial Models

* **Capital Expenditure (CapEx):** Upfront capital spent on physical assets (building datacenters, purchasing hardware racks). Costs are depreciated over time.
* **Operational Expenditure (OpEx):** Continuing operating expenses (pay-as-you-go billing). Billed dynamically as operational costs, allowing immediate tax deductions.

---

## 3. The Shared Responsibility Model

Security and administration responsibilities are split between the cloud customer and Microsoft based on the service model deployed.

```
+-----------------------------------+----------+----------+----------+----------+
| Responsibility Area               | On-Prem  |   IaaS   |   PaaS   |   SaaS   |
+-----------------------------------+----------+----------+----------+----------+
| Data & User Directory             | Customer | Customer | Customer | Customer |
| Endpoints (Mobile/PC)             | Customer | Customer | Customer | Customer |
| Identity & Access Management      | Customer | Customer | Customer | Customer |
| Application Code                  | Customer | Customer | Customer | MSFT     |
| Operating System                  | Customer | Customer | MSFT     | MSFT     |
| Networking Controls (Routing/FW)  | Customer | Customer | Shared   | MSFT     |
| Physical Security (Hardware/DC)   | Customer | MSFT     | MSFT     | MSFT     |
+-----------------------------------+----------+----------+----------+----------+
```

### Cloud Service Models
1. **IaaS (Infrastructure as a Service):** Microsoft manages the physical servers and storage; you manage the OS, runtime, and software (e.g., Azure VMs).
2. **PaaS (Platform as a Service):** Microsoft manages host OS, runtime systems, and hardware; you only manage code and data (e.g., Azure App Service).
3. **SaaS (Software as a Service):** Microsoft manages everything; you consume the application directly (e.g., Microsoft 365, Dynamics 365).
