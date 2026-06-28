---
title: "Cloud Breach Case Studies: Technical Autopsy of Capital One, Uber, and CircleCI Compromises"
type: threat-intel
tags: [Threat Intelligence, Case Studies, Cloud Breaches, Incident Response, Incident Analysis]
date: 2026-06
readingTime: 20
---

# Cloud Breach Case Studies: Technical Autopsy of Capital One, Uber, and CircleCI Compromises

## Executive Summary

Analyzing real-world security breaches is essential for platform security engineers. Case studies provide valuable insights into how actual adversaries exploit complex system configurations. Often, breaches are not the result of a single, highly advanced exploit. Instead, they occur when attackers chain together minor misconfigurations, legacy features, and loose access boundaries.

This whitepaper performs a detailed technical autopsy of three major cloud breaches: Capital One, Uber, and CircleCI. It analyzes the root causes, architectural failures, and specific attack techniques used in each incident. By dissecting these compromises, we extract precise engineering lessons and defensive mitigations to protect modern cloud landing zones.

---

## Technical Autopsy 1: Capital One (SSRF & IMDSv1 Abuse)

In 2019, Capital One suffered a massive data breach exposing over 100 million customer records stored in Amazon S3 buckets. The incident is a classic example of how Server-Side Request Forgery (SSRF) can be used to compromise cloud metadata services.

```
       [ External Attacker ] ── (Exploits SSRF on web application proxy) ──> [ WAF EC2 Instance ]
                                                                                   │
                                                          (Queries IMDSv1 endpoint)
                                                                                   ▼
                                                                        [ Plaintext Temp Role Keys ]
                                                                                   │
                                                                                   ▼
                                                                     [ Exfiltrates S3 Bucket Data ]
```

### Attack Path and Root Cause
1. **Initial Vulnerability (SSRF)**: The attacker identified a misconfigured open-source web application proxy running on an EC2 instance. The proxy was vulnerable to Server-Side Request Forgery (SSRF), allowing the attacker to craft requests that forced the EC2 instance to query local network resources on the attacker's behalf.
2. **Metadata Exploitation (IMDSv1)**: The attacker forced the proxy to query the EC2 Instance Metadata Service (IMDSv1) at `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. Because IMDSv1 does not require session token authentication, the service immediately returned temporary IAM security credentials assigned to the EC2 instance role.
3. **Overly Permissive IAM Privileges**: The EC2 instance role was configured with excessive read permissions, including wildcard access to list and download files from S3 buckets across the AWS account.
4. **Data Exfiltration**: The attacker configured the stolen temporary credentials on their local machine and called S3 APIs to list buckets and download data directly, bypassing the corporate firewall.

### Architectural Failures
* **Failure to Enforce IMDSv2**: IMDSv1 does not validate incoming requests. In contrast, IMDSv2 requires a session token generated via a PUT request. This token cannot easily be forwarded by web proxies, blocking SSRF-based metadata harvesting.
* **Violating Least Privilege**: The web application proxy did not require access to S3 buckets, yet its IAM execution role possessed broad read access, amplifying the blast radius of the compromise.

---

## Technical Autopsy 2: Uber (Hardcoded Credentials & PAM Compromise)

In 2022, an attacker gained full control of Uber's internal IT systems, AWS environments, and Google Cloud workspaces. The breach demonstrated the danger of storing administrative credentials in plaintext shares and having flat access paths.

```
       [ Compromised Contractor Session ] ── (Scans internal network files) ──> [ Network Share Backup ]
                                                                                      │
                                                                         (Finds script with credentials)
                                                                                      ▼
                                                                           [ Thycotic PAM Password ]
                                                                                      │
                                                                                      ▼
                                                                     [ Full Cloud Infrastructure Control ]
```

### Attack Path and Root Cause
1. **Initial Access**: The attacker compromised a contractor's personal device and captured their credentials. They used MFA fatigue tactics, sending repeated push notifications until the contractor approved the authentication request.
2. **Internal Network Scanning**: Once connected to Uber's internal network via VPN, the attacker scanned network drives and backup shares.
3. **Plaintext Secrets Exposure**: The attacker discovered a PowerShell script containing hardcoded administrative credentials for Uber's Privileged Access Management (PAM) platform (Thycotic).
4. **Platform Takeover**: The attacker logged into the PAM tool using the hardcoded credentials, extracting master keys for Azure AD, AWS, Google Cloud, and Slack, leading to complete infrastructure compromise.

### Architectural Failures
* **Secrets Stored in Version Control / Backup Shares**: Storing passwords in configuration files or deployment scripts bypasses access controls.
* **Lack of Multi-Factor Authentication for Admin Platforms**: The PAM platform trusted login credentials without requiring additional authentication steps (MFA) or network source validation.

---

## Technical Autopsy 3: CircleCI (Workstation Compromise & Build System Session Hijacking)

In 2022, CircleCI suffered a breach that exposed customer environment variables, repository secrets, and deployment keys. The compromise illustrated the vulnerability of build platform execution environments.

```
       [ Malware on Developer Laptop ] ── (Extracts active session cookies) ──> [ Attacker Machine ]
                                                                                      │
                                                                         (Hijacks 2FA Session)
                                                                                      ▼
                                                                           [ CircleCI Control Plane ]
                                                                                      │
                                                                                      ▼
                                                                     [ Extracts Customer Environment Keys ]
```

### Attack Path and Root Cause
1. **Developer Workstation Compromise**: An attacker compromised a developer's local laptop using malware. The malware bypassed endpoint protections and extracted active session cookies from the developer's web browser.
2. **Session Hijacking**: The attacker used the stolen session cookies to bypass multi-factor authentication (MFA) checks, hijacking the developer's administrative session on the CircleCI control plane.
3. **Database and Vault Access**: The developer had authorized access to core database backups and decryption keys. Using the hijacked session, the attacker downloaded customer environment variables and decryption keys stored in the platform's Vault database, compromising customer deployment environments.

### Architectural Failures
* **Broad Session Token Lifetimes**: Long-lived session cookies allow attackers to use hijacked sessions without re-authenticating.
* **Over-privileged Developer Accounts**: The developer possessed broad administrative access to production database decryption keys, violating least privilege.

---

## Architectural Lessons and Defenses

Applying technical lessons from these breaches requires implementing concrete security controls:

### 1. Hardening EC2 Instance Metadata Options (Mitigation for Capital One)
Enforce IMDSv2 and disable IMDSv1 on all EC2 instances to protect credentials from SSRF exploits.

```bash
# Force IMDSv2 on an existing instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-0123456789abcdef0 \
  --http-tokens required \
  --http-endpoint enabled
```

### 2. Implementing IAM Session Conditions (Mitigation for Stolen Credentials)
Add source IP and execution conditions to IAM policies to ensure stolen credentials cannot be used outside the enterprise network or authorized CI/CD platforms.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "NotIpAddress": {
          "aws:SourceIp": [
            "198.51.100.0/24",
            "203.0.113.0/24"
          ]
        },
        "Bool": {
          "aws:ViaAWSService": "false"
        }
      }
    }
  ]
}
```

---

## Tooling and Implementation

Deploy automated scanners to detect and mitigate breach vulnerabilities:

1. **Checkov / Gitleaks**: Integrate Gitleaks into your build pipelines to scan code repositories for hardcoded credentials, preventing secrets from being committed to source control (Mitigation for Uber).
2. **AWS Config / Azure Policy**: Enforce compliance policies across your cloud infrastructure. Configure rules to flag or terminate EC2 instances running with IMDSv1 enabled automatically (Mitigation for Capital One).
3. **Endpoint Detection and Response (EDR)**: Deploy EDR tools (like CrowdStrike or Microsoft Defender) on all developer endpoints to detect and block credential-dumping malware, protecting active session tokens (Mitigation for CircleCI).

---

## Incident Prevention Audit Checklist

| Item | Incident Context | Verification Step / Command | Target State |
| :--- | :--- | :--- | :--- |
| 1 | IMDS Enforcement | Query instances for IMDS configuration settings. | IMDSv1 is disabled; IMDSv2 is enforced on all workloads. |
| 2 | Code Secret Scanning | Run Gitleaks scans on all active source repositories. | Zero hardcoded passwords, keys, or API tokens are found in code. |
| 3 | Access Policy Limits | Audit IAM policies for wildcard permissions (`*` on `*`). | Actions and resources are explicitly defined; wildcards are restricted. |
| 4 | MFA Validation | Check MFA status on administrative endpoints and PAM platforms. | Access requires multi-factor authentication; session timeouts are set to short limits. |
| 5 | Session IP Locks | Review access conditions for high-privilege administrative roles. | Access is restricted using source IP or virtual private endpoint constraints. |
| 6 | Endpoint Security | Check EDR agent installation status on developer workstations. | Active security agents monitor endpoints and block unauthorized process executions. |

---

## References

* *Capital One Breach Information and Technical Analysis*: [AWS Security Blog](https://aws.amazon.com/blogs/security/defense-in-depth-introducing-instance-metadata-service-v2/)
* *Uber Security Incident Update (2022)*: [Uber Newsroom Statement](https://www.uber.com/newsroom/security-update/)
* *CircleCI Incident Security Report (2022)*: [CircleCI Security Advisory](https://circleci.com/blog/january-4-2023-security-alert/)
* *OWASP API Security Top 10 (SSRF and Broken Object Level Authorization)*: [OWASP Project](https://owasp.org/www-project-api-security/)
