# Domain 3: Security Architecture (SY0-701)

This section covers **18%** of the CompTIA Security+ SY0-701 exam, focusing on designing, building, and maintaining secure systems, networks, and enterprise infrastructure.

---

## 1. Security Implications of Architecture Models

### Cloud and Virtualization Concepts
- **Shared Responsibility Model:** Understanding what the Cloud Service Provider (CSP) is responsible for (Security *of* the cloud) versus what the customer is responsible for (Security *in* the cloud).
- **Deployment Models:**
  - *Public Cloud:* Available to anyone over the internet (e.g., AWS, Azure).
  - *Private Cloud:* Dedicated solely to one organization.
  - *Hybrid Cloud:* A mix of public and private clouds bound together by technology.
  - *Community Cloud:* Infrastructure shared by several organizations with common concerns (e.g., healthcare organizations).
- **Service Models:**
  - *IaaS (Infrastructure as a Service):* Provider manages hardware; you manage OS, data, apps (e.g., EC2).
  - *PaaS (Platform as a Service):* Provider manages hardware and OS; you manage apps and data.
  - *SaaS (Software as a Service):* Provider manages everything; you just use the software (e.g., Microsoft 365, Salesforce).

### Modern Infrastructure
- **Infrastructure as Code (IaC):** Managing and provisioning computer data centers through machine-readable definition files (e.g., Terraform, Ansible). Ensures consistency and prevents configuration drift.
- **Microservices & Containerization:** Breaking monolithic apps into smaller, independent services. Containers (like Docker) package the application and its dependencies, running on a shared OS kernel.
- **Serverless:** Executing code without managing the underlying servers (e.g., AWS Lambda). You only pay for the compute time consumed.

### Specialized Systems
- **IoT (Internet of Things):** Smart devices. Often lack robust security and cannot be easily patched.
- **SCADA / ICS:** Supervisory Control and Data Acquisition / Industrial Control Systems. Used in manufacturing and critical infrastructure. Usually requires strict isolation (air-gapping).

---

## 2. Securing Enterprise Infrastructure

### Network Appliances
- **Firewalls:**
  - *Stateless:* Filters based purely on IP and port.
  - *Stateful:* Remembers the state of active connections.
  - *Next-Generation Firewall (NGFW):* Includes deep packet inspection, application-level awareness, and IPS capabilities.
  - *WAF (Web Application Firewall):* Specifically designed to protect web apps from Layer 7 attacks like XSS and SQLi.
- **IDS / IPS:**
  - *Intrusion Detection System (IDS):* Passive monitoring. Alerts when malicious traffic is detected.
  - *Intrusion Prevention System (IPS):* Active monitoring. Blocks malicious traffic in real-time.
- **Load Balancers:** Distributes network or application traffic across a number of servers to increase capacity and reliability.

### Network Segmentation and Access
- **Zero Trust:** "Never trust, always verify." No implicit trust granted based on network location. Every request must be authenticated and authorized.
- **VLANs (Virtual LANs):** Logically segmenting a network on the same physical switch.
- **802.1X:** Port-based Network Access Control (PNAC). Requires authentication before a device is allowed to communicate on the network.

---

## 3. Data Security

### The Data Lifecycle
1. **Creation/Collection:** Data is generated.
2. **Storage:** Data is stored securely.
3. **Use:** Data is actively processed.
4. **Share/Transmit:** Data moves across networks.
5. **Archive:** Data is stored long-term for compliance.
6. **Destruction:** Data is securely destroyed (e.g., crypto-shredding, physical destruction).

### Data States and Encryption
- **Data at Rest:** Data stored on a hard drive or database. Protected by Full Disk Encryption (FDE) or File/Database Encryption (e.g., AES).
- **Data in Transit (Motion):** Data moving over a network. Protected by TLS/SSL or IPsec.
- **Data in Use (Processing):** Data currently in RAM or CPU caches. The hardest to protect, often requiring Confidential Computing (e.g., secure enclaves).

---

## 4. Resilience and Recovery

### High Availability and Redundancy
- **High Availability (HA):** Ensuring a system remains operational with minimal downtime. Measured in "nines" (e.g., 99.999% uptime).
- **Redundancy:** Having secondary components to take over if a primary component fails (e.g., RAID for hard drives, dual power supplies).

### Continuity of Operations (COOP)
- **RTO (Recovery Time Objective):** The maximum tolerable amount of time a system can be down after a disaster.
- **RPO (Recovery Point Objective):** The maximum tolerable amount of data loss, measured in time (e.g., "we can afford to lose the last 4 hours of data").
- **Recovery Sites:**
  - *Hot Site:* Fully operational, ready to go in minutes/hours. Very expensive.
  - *Warm Site:* Has the hardware, but needs current data restored. Takes days.
  - *Cold Site:* Empty building with power/cooling. You must bring hardware and data. Takes weeks. Very cheap.

### Backup Strategies
- **Full:** Backs up everything. Slowest to back up, fastest to restore.
- **Differential:** Backs up everything changed since the last *Full* backup.
- **Incremental:** Backs up everything changed since the *last* backup of any kind. Fastest to back up, slowest to restore.
