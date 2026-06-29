# <img src="../../assets/images/azure-logo.svg" width="36" height="36" style="vertical-align: middle; margin-right: 10px;"> AZ-900 Domain 2: Describe Azure Architecture & Services

This section details Azure's physical structure, resource management hierarchies, and core cloud services.

---

## 1. Physical Infrastructure Organization

### 1.1 Regions & Region Pairs
*   **Azure Regions:** A set of datacenters deployed within a latency-defined perimeter and connected through a dedicated, low-latency regional network.
*   **Region Pairs:** Each Azure region is paired with another region in the same geography (at least 300 miles away) to ensure high-availability failover. Examples: `East US` and `West US`.

### 1.2 Availability Zones (AZs)
*   Physically separate datacenters within a single Azure region.
*   Each Availability Zone has independent power, cooling, and network configurations.
*   Enables deployment of **zone-redundant** applications to protect against the loss of a single datacenter building.

---

## 2. Resource Management Hierarchy

Azure structures access control, billing, and resource containment inside four logical levels:

1.  **Management Groups:** Target boundaries for configuring access, policy, and compliance across multiple subscriptions.
2.  **Subscriptions:** Administrative containers managing billing invoices and access boundaries.
3.  **Resource Groups (RGs):** Logical folders grouping related resources. Every resource must exist in exactly one RG.
4.  **Resources:** The actual instances of services (VMs, storage accounts, VNets).

---

## 3. Core Azure Compute Services

### 3.1 Virtual Machines (VMs)
On-demand IaaS virtual machines. Offers full OS control, allowing custom software configurations and local file hosting.

### 3.2 Azure App Services
Fully managed PaaS hosting platform for running web applications, APIs, and microservices in isolated environments.

### 3.3 Container Hostings (ACI vs. AKS)
*   **Azure Container Instances (ACI):** Serverless container instances running on-demand without orchestrator overhead.
*   **Azure Kubernetes Service (AKS):** Managed enterprise container orchestration platform (Kubernetes).

### 3.4 Azure Functions
Serverless compute (Function-as-a-Service) where code executes on-demand in response to events (e.g. queue files, DB writes, HTTP requests).

---

## 4. Core Azure Networking Services

*   **Virtual Network (VNet):** Private network in Azure allowing secure private IP communications.
*   **VNet Peering:** Securely connects two separate VNets using private IP addresses.
*   **Load Balancer:** Highly performant **Layer 4** (TCP/UDP) routing tool.
*   **Application Gateway:** **Layer 7** routing gateway with SSL offloading and WAF integrations.
*   **VPN Gateway:** Encrypted Site-to-Site connections over the public internet.
*   **ExpressRoute:** Private, high-speed fiber-line connections directly to Azure bypassing the public internet.

---

## 5. Storage & Database Offerings

### 5.1 Azure Storage Services
*   **Azure Blob Storage:** Object store for unstructured data (images, log files, backups).
*   **Azure Files:** Managed file shares (SMB/NFS) accessible like local network drives.
*   **Azure Disk Storage:** Managed block storage disks attached directly to VMs.

### 5.2 Database Engines
*   **Azure SQL Database:** Managed PaaS SQL server engine (relational).
*   **Azure Cosmos DB:** Fully managed, globally distributed NoSQL database (documents, key-value, graph).
*   **Azure Synapse Analytics:** Enterprise data warehousing and big data analytics engine.
