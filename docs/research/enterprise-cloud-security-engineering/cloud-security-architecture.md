# 3. Cloud Security Architecture & Enterprise Infrastructure

> A secure landing zone gets you a baseline; modern threats require **defense in depth inside the network** and **cryptographic control over data**. This section covers **immutable infrastructure and micro-segmentation** (constraining where workloads can talk and reducing exfiltration paths) and **cloud data protection** (envelope encryption, customer-managed keys, secret management, and classification).

**Contents**
- [3.1 Immutable infrastructure & micro-segmentation](#31-immutable-infrastructure--micro-segmentation)
- [3.2 Cloud data protection](#32-cloud-data-protection)
- [Reference topology](#reference-topology)
- [Best practices summary](#best-practices-summary)
- [Further reading](#further-reading)

---

## 3.1 Immutable infrastructure & micro-segmentation

The Azure **hub-and-spoke landing zone** centralizes shared services (firewall, DNS, identity, monitoring) in a hub and isolates workloads in spokes. It's necessary but **not sufficient**: by itself it does little to stop **east-west (lateral) movement** between or within spokes, and it doesn't address data exfiltration over public PaaS endpoints. Two patterns close those gaps: **immutable infrastructure** and **micro-segmentation**.

### Immutable infrastructure

**Principle:** servers are never patched or modified in place. To change anything, you **build a new image and redeploy**, then destroy the old. This eliminates configuration drift, shrinks the window for persistence, and makes rollback trivial.

- Build golden images with **Packer** (or **Azure VM Image Builder**); bake in hardening (CIS baseline), the agent stack, and patches.
- Deploy via **VM Scale Sets** / immutable container images; roll forward by swapping the image reference, not by SSH-ing in.
- **Disable interactive access** to production hosts (no standing SSH/RDP); use just-in-time access (Azure Bastion + JIT) for break-glass only.
- Treat the image pipeline like any other artifact pipeline: scan it, sign it, and record provenance (see [Section 2](./devsecops-pipeline-hardening.md)).

> **Why it matters for detection:** in an immutable model, *any* in-place change to a production host is anomalous by definition — a high-signal detection (see [Section 4](./detection-engineering.md)).

### Private Link & Private DNS — keep PaaS traffic off the public internet

By default, Azure PaaS services (Storage, SQL, Key Vault, Cosmos DB, and many SaaS offerings) expose **public endpoints**. Even with firewall allow-lists, this leaves an internet-reachable control surface and an **exfiltration path**.

**Azure Private Link** projects a PaaS service into your VNet as a **private endpoint** with a private IP. Traffic stays on the Microsoft backbone and never touches the public internet.

| | Service Endpoints | **Private Link / Private Endpoint** |
|---|---|---|
| IP exposure | Service keeps public IP; VNet identity added | Service reachable via **private IP** in your VNet |
| Traffic path | Optimized route, still to public endpoint | Microsoft backbone, private |
| Exfiltration control | Weaker (public endpoint remains) | Strong — can disable public access entirely |
| DNS | No change | **Requires Private DNS** to resolve FQDN → private IP |
| Granularity | Per service/subnet | Per **resource instance** |

**The DNS gotcha (most common failure mode):** the service FQDN (e.g., `myacct.blob.core.windows.net`) must resolve to the **private IP**. You must link a **Private DNS zone** (e.g., `privatelink.blob.core.windows.net`) to the VNet (typically centralized in the hub) so clients resolve correctly. Get this wrong and clients silently fall back to the public endpoint — or fail. Enforce private endpoints and disable public network access with **Azure Policy** at the management-group level.

```
   Spoke VNet                         Hub VNet
  ┌───────────────┐                 ┌──────────────────────┐
  │  App subnet   │                 │  Private DNS zones    │
  │  ┌─────────┐  │   private IP    │  privatelink.blob...  │
  │  │ Workload│──┼───────────────► │  privatelink.vaultcore│
  │  └─────────┘  │  (10.x.x.x)     └──────────┬────────────┘
  │  ┌──────────┐ │                            │ VNet link (resolves FQDN)
  │  │ Private  │ │                            ▼
  │  │ Endpoint │─┼──────────────► Azure Storage / Key Vault (public access DISABLED)
  │  └──────────┘ │                 on the Microsoft backbone, no internet path
  └───────────────┘
```

### Micro-segmentation — assume breach inside the network

Flat networks let one compromised workload reach everything. Micro-segmentation enforces **least-path** so workloads can only reach exactly what they need.

- **NSGs + Application Security Groups (ASGs):** write rules against *application roles* (e.g., `asg-web` → `asg-api` on 443 only) instead of brittle IP ranges. **Default-deny** intra-subnet where possible.
- **Azure Firewall Premium** in the hub for **TLS inspection**, **IDPS**, and **FQDN filtering** of egress; force spoke traffic through it via **User-Defined Routes** (UDRs).
- **Control egress aggressively** — most exfiltration and C2 leaves over outbound 443. Default-deny egress; allow only required FQDNs; use DNS with threat-intel filtering.
- **Connect regions** with **Virtual WAN** or global VNet peering, but **force inter-spoke and cross-region traffic through inspection hubs** (a secured-hub / routing-intent pattern). Use **Azure Route Server** to integrate NVAs with dynamic routing.
- **Kubernetes:** apply **NetworkPolicy** (Azure CNI / Calico / Cilium) to isolate pods namespace-to-namespace; default-deny and explicitly allow. This is micro-segmentation *inside* the cluster.

### Common failure modes

| Failure mode | Consequence | Mitigation |
|--------------|-------------|------------|
| Private endpoint without Private DNS | Clients hit public endpoint or break | Link Private DNS zone to VNet; verify resolution; enforce via Policy. |
| Public network access left enabled | Exfiltration/attack path remains | `public_network_access_enabled=false`; deny via Azure Policy (see [§2.1 Rego](./devsecops-pipeline-hardening.md#writing-a-rego-policy-to-block-insecure-terraform)). |
| Allow-all egress | Easy data exfiltration / C2 | Default-deny egress; FQDN allow-list via Azure Firewall. |
| Flat spoke, no intra-segmentation | One pod/VM compromise = lateral sweep | NSGs/ASGs default-deny; K8s NetworkPolicy. |
| In-place patching | Drift + persistence foothold | Immutable images; redeploy to change. |

---

## 3.2 Cloud data protection

Encryption is table stakes; the differentiator is **who controls the keys** and **how secrets are eliminated from code**.

### Envelope encryption (and why two keys)

Encrypting a large dataset directly with a master key is slow and risky (the master key is exposed in many operations). **Envelope encryption** uses two layers:

- A **Data Encryption Key (DEK)** encrypts the data (fast symmetric crypto).
- A **Key Encryption Key (KEK)** — held in Key Vault / HSM and **never exported** — *wraps* (encrypts) the DEK.

```
        ┌──────────────┐ wraps  ┌──────────────┐ encrypts ┌──────────────┐
        │  KEK (in HSM │───────►│  DEK (data    │─────────►│   Your data   │
        │  / Key Vault)│        │  enc. key)    │          │  (at rest)    │
        └──────────────┘        └──────────────┘          └──────────────┘
         customer-controlled      stored wrapped            ciphertext only
         rotate -> re-wrap DEK     next to the data
```

**Why it matters:** to rotate, you only **re-wrap the DEK** with a new KEK — no need to re-encrypt terabytes. To revoke access instantly, **disable the KEK** and all wrapped data becomes unreadable (a powerful kill-switch). With **Customer-Managed Keys (CMK)**, *you* hold the KEK, so the cloud provider cannot read your data without your key, and you control rotation/revocation.

Azure Storage, SQL Database, Cosmos DB, Disk Encryption, and more support **CMK in Azure Key Vault or Managed HSM**. For the highest sensitivity, layer **double encryption** (platform key + customer key) and consider **SQL Always Encrypted with secure enclaves** to protect sensitive columns even from DBAs.

### Key management discipline

- **Separate Key Vaults** per environment (prod/dev) and per application/blast-radius — don't co-mingle keys.
- **Enable soft-delete and purge protection** — without purge protection, a malicious or accidental purge permanently destroys keys (and renders CMK-encrypted data unrecoverable). This is a top, irreversible failure mode.
- **Rotate keys** on a policy (Key Vault auto-rotation); test that consumers pick up rotation.
- **RBAC data-plane model** (not legacy access policies) for least privilege; grant `get`/`wrapKey`/`unwrapKey` narrowly.
- **Private Link the Key Vault** and **disable public network access**.
- **Log every key operation** (Key Vault diagnostic logs → Sentinel) and alert on anomalies (see [§4.2](./detection-engineering.md#correlating-key-vault-with-data-access-cross-resource-exfiltration)).
- **Test backup/restore** of keys and the recovery runbook before you need it.

### Secrets management & secretless patterns

The best secret is **no secret**:

1. **Prefer managed identities / workload identity federation** (Section 1) so apps and pipelines get tokens, not stored secrets.
2. Where secrets are unavoidable, **store them in Key Vault** with least-privilege access and reference them at runtime (e.g., Key Vault references in App Service/Container Apps) rather than baking them into images or config.
3. For databases and short-lived credentials, use **dynamic secrets** (e.g., **HashiCorp Vault**) that are generated on demand and auto-expire — eliminating standing DB passwords.
4. **Never** commit secrets; run secret scanning in CI (trufflehog/Gitleaks) and pre-commit hooks; rotate anything that leaks.

### Data classification & labelling

You can't protect what you haven't classified. Use **Microsoft Purview Information Protection** (formerly AIP) to discover, classify, and **label** data (Public / Internal / Confidential / Highly Confidential), then **drive enforcement** from labels:

- Auto-apply labels via sensitive-information types (PII, PCI, secrets) and trainable classifiers.
- **DLP policies** block or encrypt sharing of labeled data; labels can apply encryption that travels with the file.
- Feed Purview/DLP events into the SIEM to detect exfiltration of sensitive data.

### Common failure modes

| Failure mode | Consequence | Mitigation |
|--------------|-------------|------------|
| Purge protection disabled | Irreversible key (and data) loss | Enable soft-delete **and** purge protection everywhere. |
| One shared Key Vault for everything | Single compromise = total blast radius | Per-env, per-app vaults; narrow RBAC. |
| Secrets in images / repos / state | Leaked, long-lived, broadly trusted | Managed identity/WIF; Key Vault refs; secret scanning. |
| Provider-managed keys for regulated data | No customer control/revocation | CMK in Key Vault/Managed HSM; double encryption for crown jewels. |
| No classification | Can't apply or prove data controls | Purview labels + DLP; map to handling rules. |

---

## Reference topology

```
                         ┌───────────────────────────────────────────┐
                         │            Management Group root           │
                         │  Azure Policy: deny public PaaS, require    │
                         │  diag settings, allowed regions/SKUs        │
                         └───────────────────────────────────────────┘
                                            │
            ┌───────────────────────────────┴───────────────────────────────┐
            ▼                                                                 ▼
   ┌──────────────────┐   peering + UDR (force-tunnel)        ┌────────────────────────┐
   │      HUB VNet     │◄────────────────────────────────────►│      SPOKE VNet(s)       │
   │  Azure Firewall   │                                       │  default-deny NSGs/ASGs  │
   │  Premium (IDPS,   │   all egress + inter-spoke traffic    │  Private Endpoints ──────┼──► Storage/SQL/KeyVault
   │  TLS inspect)     │   inspected here                      │  immutable VMSS / AKS    │   (public access OFF)
   │  Private DNS      │                                       │  K8s NetworkPolicy       │
   │  Bastion (JIT)    │                                       └────────────────────────┘
   └──────────────────┘
            │  diagnostic settings (all resources)
            ▼
   Log Analytics / Sentinel  ── see Section 4 (Detection Engineering)
```

---

## Best practices summary

- **Immutable everything:** golden images (Packer), redeploy-to-change, no standing interactive prod access.
- **Private-Link PaaS** and **disable public access**; get **Private DNS** right; enforce with Azure Policy.
- **Micro-segment:** default-deny NSGs/ASGs, Firewall Premium egress inspection, force inter-spoke traffic through the hub, K8s NetworkPolicy.
- **Envelope encryption + CMK:** customer-held KEK, rotation, soft-delete **and** purge protection, per-env/app vaults, Key Vault logging.
- **Go secretless:** managed identity/WIF first; Key Vault refs or dynamic secrets otherwise; scan for leaks.
- **Classify and enforce:** Purview labels + DLP; feed events to the SIEM.

---

## Further reading

- NIST SP 800-57, *Recommendation for Key Management* — <https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final>
- Microsoft — *Azure Private Link* — <https://learn.microsoft.com/azure/private-link/private-link-overview>
- Microsoft — *Private Link & DNS integration* — <https://learn.microsoft.com/azure/private-link/private-endpoint-dns>
- Microsoft — *Azure landing zones (CAF)* — <https://learn.microsoft.com/azure/cloud-adoption-framework/ready/landing-zone/>
- Microsoft — *Customer-managed keys overview* — <https://learn.microsoft.com/azure/security/fundamentals/encryption-models>
- Microsoft — *Key Vault security & soft-delete/purge protection* — <https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview>
- Microsoft Purview Information Protection — <https://learn.microsoft.com/purview/information-protection>
- HashiCorp Vault dynamic secrets — <https://developer.hashicorp.com/vault/docs/secrets>
- CSA Cloud Controls Matrix — <https://cloudsecurityalliance.org/research/cloud-controls-matrix>

---

[← Previous: DevSecOps](./devsecops-pipeline-hardening.md) · [Back to overview](./README.md) · [Next: Detection Engineering →](./detection-engineering.md)
