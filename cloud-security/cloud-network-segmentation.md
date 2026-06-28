---
title: "Cloud Network Segmentation: VPC Architecture, Transit Gateway Routing, and PrivateLink Integration"
type: cloud-security
tags: [VPC, Transit Gateway, PrivateLink, Network Security, Segmentation]
date: 2026-06
readingTime: 18
---

# Cloud Network Segmentation: VPC Architecture, Transit Gateway Routing, and PrivateLink Integration

## Executive Summary

As organizations transition to the cloud, they often bring traditional on-premises networking assumptions with them. This legacy mindset leads to broad IP allocations and flat network architectures. Many engineering teams mistakenly believe that placing resources in different subnets or using basic Security Groups provides adequate security. In reality, a compromised workload in a flat VPC can easily perform lateral scanning, access unsegmented development databases, and exfiltrate data via public endpoints.

At scale, relying solely on Security Groups for access control is hard to manage and error-prone. Organizations must implement a defense-in-depth networking strategy. This requires physical isolation using dedicated VPCs, centralized egress traffic filtering, and private service connectivity via AWS PrivateLink or Azure Private Link. This whitepaper explains how to design secure cloud network architectures, configure Transit Gateway routing tables, implement PrivateLink, and establish DNS security controls to prevent data exfiltration.

---

## Threat Model and Attack Surface

The network-layer threat model assumes the adversary has established a foothold inside a workload and is seeking to identify sensitive adjacent services or establish outbound command-and-control (C2) connections.

```
       [ Compromised Host in Web VPC ]
                      │
        ( DNS Tunneling / Scanning )
                      │
                      ▼
        [ Attempts Egress Connection ]
                      │
       ┌──────────────┴──────────────┐
       ▼                             ▼
[ Direct Internet Route ]     [ Central Firewall / Inspection VPC ]
       │                             │
       ▼                             ▼
[ Bypass security gates ]     [ Deep Packet Inspection (DPI) ]
       │                             │
  ( Exfil Successful )        [ Blocked: Untrusted Domain / IP ]
```

### Threat Vectors and Kill-Chains

1. **Lateral Movement across VPC Peering Connections**:
   - *Adversary Goal*: Compromise a production database from a development environment.
   - *Attack Vector*: An enterprise connects a dev VPC and a prod VPC using VPC Peering to simplify administrative tasks. An attacker compromises an application server in the dev VPC. Because VPC Peering does not support transitive routing limits at the VPC link level, the attacker scans and connects directly to the prod database subnet, exploiting weak database credentials to access production data.
2. **Data Exfiltration via Public Endpoints**:
   - *Adversary Goal*: Exfiltrate sensitive data without triggering data loss prevention (DLP) alerts.
   - *Attack Vector*: An attacker gains access to an internal application server. To exfiltrate data, they call public APIs of cloud services (e.g. public S3 buckets or external databases) over the default internet gateway route. Because the network lacks egress filtering, the outbound traffic flows directly to the internet, bypassing security monitoring.
3. **DNS Tunneling**:
   - *Adversary Goal*: Establish a command-and-control tunnel that bypasses firewall rules.
   - *Attack Vector*: An attacker uses DNS query messages to encode data payloads. By querying a custom subdomain (e.g. `exfil-data.attacker.com`) through the default VPC resolver (`169.254.169.253`), the request is forwarded to the attacker's external nameserver. This allows data to be exfiltrated and commands to be received over standard DNS protocol channels, bypassing traditional IP-based egress filters.

---

## Deep Technical Body

### Transit Gateway (TGW) Routing Architecture and Traffic Isolation

AWS Transit Gateway (TGW) acts as a centralized cloud router. It allows organizations to connect thousands of VPCs and on-premises networks. However, to maintain security boundaries, you must configure TGW route tables carefully. 

#### The Shared Routing Table Trap
If all VPC attachments are associated with a single default TGW route table, every VPC can communicate with every other VPC. This creates a flat network across the entire organization.

#### The Isolated Hub-and-Spoke Pattern
To prevent unauthorized lateral movement, assign VPC attachments to separate, dedicated TGW route tables. 

```
[ Web VPC ] <--> [ Web TGW Route Table ] ────┐
                                             ▼
[ Core DB VPC ] <--> [ DB TGW Route Table ] ─┼─> [ Inspection VPC (Firewall Appliance) ]
                                             ▲
[ Shared SVCS ] <--> [ SVCS TGW Route Table ]┘
```

By decoupling propagation (which networks the TGW learns about) and association (which route table the TGW uses to route traffic), you can force all inter-VPC traffic through a central firewall appliance in an **Inspection VPC**.

### AWS PrivateLink: Eliminating Public Egress Paths
AWS PrivateLink allows you to access services hosted in other VPCs or AWS services privately, without exposing traffic to the public internet.

#### How PrivateLink Works
PrivateLink creates **Interface VPC Endpoints** inside your subnets. These endpoints appear as local elastic network interfaces (ENIs) with private IP addresses. Traffic destined for the target service is routed over the AWS internal network fabric, avoiding the internet gateway entirely.

#### Policy Constraints on Endpoints
To prevent data exfiltration, you must attach an Endpoint Policy to your VPC endpoints. This restricts the specific accounts and resources that can use the endpoint. For example, the policy below allows access only to a specific, authorized S3 bucket:

```json
{
  "Statement": [
    {
      "Sid": "AllowAccessToAuthorizedBucketOnly",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::my-authorized-enterprise-bucket",
        "arn:aws:s3:::my-authorized-enterprise-bucket/*"
      ]
    }
  ]
}
```

If an attacker tries to use this endpoint to exfiltrate data to a personal S3 bucket, the request is blocked by the endpoint policy, even if the application's IAM policy allows broad S3 access.

---

## Defensive Architecture

A secure cloud network architecture requires segmenting network tiers and routing all outbound traffic through central inspection points.

### Architecture Topology: Hub-and-Spoke Inspection Flow

```
[ Spoke VPC A: Frontend ]      [ Spoke VPC B: Backend ]
           │                              │
           └──────────────┬───────────────┘
                          ▼ (TGW Attachment)
             [ AWS Transit Gateway ]
                          │
                          ▼ (Route table forces traffic to Inspection VPC)
            [ Inspection VPC Subnets ]
                          │
                          ▼
            [ AWS Network Firewall / NGFW ]
                          │
                          ▼ (Inspected & Approved Traffic)
                 [ Transit Gateway ]
                          │
                          ▼
                  [ Egress VPC ] ──> [ Internet Gateway ]
```

### Route 53 Resolver DNS Firewall Implementation
To prevent DNS-based data exfiltration and restrict access to malicious domains, implement Route 53 Resolver DNS Firewall rules. Block known malicious domains and unauthorized external DNS resolvers.

#### Terraform Configuration Snippet
```hcl
resource "aws_route53_resolver_firewall_domain_list" "blocked_domains" {
  name    = "enterprise-blocked-domains"
  domains = ["*.malicious-domain.com", "*.attacker.net"]
}

resource "aws_route53_resolver_firewall_rule_group" "dns_rule_group" {
  name = "dns-security-policy"
}

resource "aws_route53_resolver_firewall_rule" "block_malicious" {
  name                    = "block-malicious-traffic"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.dns_rule_group.id
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.blocked_domains.id
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
  priority                = 100
}
```

---

## Tooling and Implementation

Maintain continuous visibility and enforcement across the network plane:

1. **AWS Network Firewall / Palo Alto VM-Series**: Deploy firewalls within your central inspection VPC to perform deep packet inspection (DPI), stateful packet filtering, and SSL decryption for all traffic entering or leaving the organization.
2. **VPC Flow Logs & Athena**: Enable VPC Flow Logs for all VPCs and aggregate them in a central S3 bucket. Use Amazon Athena to query flow records and identify anomalous traffic patterns, such as internal port scanning or connections to unexpected IP ranges.
3. **Route 53 Resolver Query Logging**: Enable query logging to record all DNS queries initiated by resources within your VPCs. This provides the visibility needed to detect DNS tunneling and command-and-control activity.

---

## Network Security Audit Checklist

| Item | Focus Area | Verification Step / Command | Target State |
| :--- | :--- | :--- | :--- |
| 1 | Internet Route Verification | Check Spoke VPC route tables to verify if direct Internet Gateway (IGW) routes exist. | Private workloads must route all egress traffic through the Transit Gateway, not directly to an IGW. |
| 2 | Endpoint Policies | Review all Interface VPC Endpoints (`s3`, `secretsmanager`, `ssm`). | Endpoints have custom policies restricting access to authorized resources. |
| 3 | TGW Segmentation | Inspect TGW route table configurations. | Separate route tables exist for different environments (Prod, Dev, Shared Services) to prevent direct routing. |
| 4 | Flow Log Status | Verify VPC Flow Log settings. | Flow logs are active for all VPCs and capture both accepted and rejected traffic. |
| 5 | DNS Query Logging | Check Route 53 Resolver configuration. | Query logging is enabled and logs are sent to a secure, centralized storage location. |
| 6 | Security Group Scope | Audit Security Groups for overly permissive rules. | No security groups allow broad inbound access (e.g. `0.0.0.0/0` on port 22 or 3389). |

---

## References

* *AWS Transit Gateway Routing Architecture*: [AWS Documentation](https://docs.aws.amazon.com/vpc/latest/tgw/tgw-route-tables.html)
* *AWS PrivateLink and Interface Endpoints*: [AWS Documentation](https://docs.aws.amazon.com/vpc/latest/userguide/endpoint-service.html)
* *Route 53 Resolver DNS Firewall*: [AWS Security Blog](https://aws.amazon.com/blogs/security/how-to-use-amazon-route-53-resolver-dns-firewall-to-block-dns-exfiltration/)
* *NIST Special Publication 800-207 (Zero Trust Architecture)*: [NIST SP 800-207](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf)
