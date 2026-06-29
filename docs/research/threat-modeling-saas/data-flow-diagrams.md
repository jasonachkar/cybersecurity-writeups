# Data Flow Diagrams (DFDs) for SaaS Applications

Data Flow Diagrams (DFDs) are a visual representation of how data moves through a system. In threat modeling, they are used to map out the system architecture, identify trust boundaries, and pinpoint where threats from the STRIDE model could materialize.

---

## 1. DFD Components

Standard threat modeling DFDs use specific symbols to represent different entities in the system:

* **External Entities (Rectangles):** People, devices, or other systems that interact with the application but are outside of your control (e.g., a User's Browser, a 3rd-party Payment Gateway).
* **Processes (Circles):** Code or services that transform or route data (e.g., API Gateway, Authentication Service, Billing Microservice).
* **Data Stores (Parallel Lines):** Databases, file systems, S3 buckets, or caches where data rests.
* **Data Flows (Arrows):** The movement of data between entities (e.g., HTTP requests, database queries).
* **Trust Boundaries (Dotted Lines):** The perimeter separating entities with different levels of trust or privilege (e.g., the boundary between the public internet and your private VPC).

---

## 2. Example: Multi-Tenant SaaS Authentication Flow

This diagram illustrates a typical authentication flow and where trust boundaries exist.

```mermaid
flowchart TD
    subgraph Public Internet
        USER["👤 User Browser<br/>(External Entity)"]
    end

    subgraph AWS VPC (Trust Boundary 1)
        WAF["🛡️ Cloud WAF<br/>(Process)"]
        ALB["⚖️ Application Load Balancer<br/>(Process)"]
        
        subgraph Private Subnets (Trust Boundary 2)
            AUTH["🔑 Auth Microservice<br/>(Process)"]
            APP["⚙️ Core SaaS App<br/>(Process)"]
            DB[("💾 Multi-Tenant DB<br/>(Data Store)")]
        end
    end

    USER -- "1. Login Credentials (HTTPS)" --> WAF
    WAF -- "2. Filtered Request" --> ALB
    ALB -- "3. Route /auth" --> AUTH
    AUTH -- "4. Query Credentials" --> DB
    AUTH -- "5. Return JWT (incl. tenant_id)" --> ALB
    ALB -- "6. Send JWT to Client" --> USER
    
    USER -- "7. API Request + JWT" --> WAF
    WAF -- "8. Filtered Request" --> ALB
    ALB -- "9. Route /api" --> APP
    APP -- "10. Validate JWT & Query tenant data" --> DB

    style USER fill:#f87171,color:#000,stroke:#dc2626
    style WAF fill:#38bdf8,color:#000,stroke:#0284c7
    style ALB fill:#38bdf8,color:#000,stroke:#0284c7
    style AUTH fill:#4ade80,color:#000,stroke:#16a34a
    style APP fill:#4ade80,color:#000,stroke:#16a34a
    style DB fill:#c084fc,color:#000,stroke:#9333ea
```

### Analyzing the DFD for Threats (Mapping STRIDE)

Looking at the diagram above, we can identify potential threats at the trust boundaries:

1. **Between User and WAF (Internet $\rightarrow$ VPC):**
    * *Spoofing:* Attacker steals the JWT in transit if TLS is misconfigured.
    * *DoS:* Attacker floods the WAF/ALB with volumetric traffic.
2. **Between Core SaaS App and Database (Process $\rightarrow$ Data Store):**
    * *Information Disclosure:* The App process fails to append `WHERE tenant_id = ?` to a database query, leaking data across the trust boundary.
    * *Elevation of Privilege:* SQL Injection originating from the user allows arbitrary command execution on the database engine.
3. **Inside the Auth Microservice (Process):**
    * *Tampering:* The microservice uses a weak secret key for signing JWTs, allowing an attacker to forge tokens.
    * *Repudiation:* The Auth service fails to log failed login attempts, masking a brute-force attack.
