# <img src="../../assets/images/azure-logo.svg" width="36" height="36" style="vertical-align: middle; margin-right: 10px;"> SC-500 Domain 2: Secure Storage, Databases, and Networking

This domain outlines database access hardening, private networking configurations, and firewall routing controls.

---

## 1. Storage & Database Cryptographic Controls

### 1.1 Azure Storage Account Hardening
*   **Access Keys Disable:** Enforce Entra ID token-based authentication by disabling storage account access keys globally.
*   **Microsoft Defender for Storage:** Auto-scans uploads for malware and alerts on anomalous data access patterns.

### 1.2 Database Controls: Always Encrypted & Dynamic Masking
*   **Always Encrypted:** Client-side column-level encryption where database administrators cannot read decrypted table values because the decryption keys are stored separately in Azure Key Vault.
*   **Dynamic Data Masking (DDM):** Limits sensitive data exposure. Example SQL command masking card numbers:
    ```sql
    ALTER TABLE Customers
    ALTER COLUMN CreditCard ADD MASKED WITH (FUNCTION = 'partial(0,"XXXX-XXXX-XXXX-",4)');
    ```

---

## 2. Secure Network Design

### 2.1 Private Endpoints vs. Service Endpoints
Azure offers two primary options to restrict PaaS resource exposure:

*   **Service Endpoints:** Keep resources (e.g., Azure SQL) on public IP ranges, but write firewall rules to accept traffic strictly from designated VNet subnets.
*   **Private Endpoints:** Route PaaS resources directly through internal private IPs inside your subnets. The public endpoint of the PaaS service is disabled.

```
+-----------------------------------+--------------------+--------------------+
| Feature                           | Service Endpoint   | Private Endpoint   |
+-----------------------------------+--------------------+--------------------+
| Traffic Routing                   | Public IP space    | Private VNet IP    |
| Public Endpoint Accessibility     | Restricted/Active  | Disabled           |
| Data Exfiltration Protection      | Basic              | Advanced           |
| Cross-Premises Access (VPN)       | Not Supported      | Supported          |
+-----------------------------------+--------------------+--------------------+
```

### 2.2 Ingress/Egress Firewalling & Custom Routing
*   **User-Defined Routes (UDRs):** Custom routing tables applied at subnets to override default Azure routing, forcing all egress network traffic to pass directly through a central **Azure Firewall** for stateful packet inspection.
*   **Web Application Firewall (WAF):** Deployed on Application Gateway or Front Door to filter Layer 7 traffic against OWASP Top 10 vulnerabilities (SQLi, XSS).
