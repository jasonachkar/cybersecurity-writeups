---
title: "Cloud Incident Case Studies: Evidence, Chronology, and Control Lessons"
id: "cloud-breach-case-studies"
navTitle: "Incident case studies"
order: 20
type: "threat-intel"
tags:
  - threat-intel
  - cloud
  - breach
  - case
  - studies
date: "2026-07-25"
lastReviewed: "2026-07-25"
reviewStatus: "partially-verified"
validatedAgainst:
  - "Capital One 2019 incident facts — https://www.capitalone.com/digital/facts2019/"
  - "US Department of Justice: United States v. Paige Thompson — https://www.justice.gov/usao-wdwa/united-states-v-paige-thompson"
  - "DOJ arrest announcement describing the WAF access path — https://www.justice.gov/usao-wdwa/pr/seattle-tech-worker-arrested-data-theft-involving-large-financial-services-company"
  - "AWS launch of IMDSv2 on November 19, 2019 — https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/"
  - "Uber September 2022 security update — https://www.uber.com/newsroom/security-update/"
  - "CircleCI January 2023 incident report — https://circleci.com/blog/jan-4-2023-incident-report/"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "illustrative"
reviewIntervalDays: 90
---

# Cloud Incident Case Studies: Evidence, Chronology, and Control Lessons

Incident lessons are useful only when chronology and evidence are honest. This review uses affected-organization disclosures and competent-authority records, separates confirmed facts from engineering inference, and avoids judging an organization for a control that did not exist at incident time.

## Evidence method

For each case:

- **Confirmed** means directly stated by the organization or a government/court source cited below.
- **Engineering inference** connects confirmed facts to a control design but is not a claim about the victim's undocumented environment.
- **Retrospective control** was released or became available later and is useful for current defense, not a contemporaneous missed requirement.

Public reports do not expose every root cause, architecture detail, detection signal, or corrective action. Absence from a disclosure is not proof a control was absent.

## Capital One, 2019

### Confirmed chronology and scope

Capital One says unauthorized access occurred on March 22 and 23, 2019. The company determined unauthorized access had occurred on July 19 and announced the incident on July 29, 2019. It reported approximately 100 million people in the United States and 6 million in Canada were affected. The disclosed categories and counts vary by data type; the company's facts page is the authoritative scope reference rather than the shorthand "100 million records."

The US Department of Justice described a misconfigured web application firewall that enabled commands to reach and obtain credentials for data access. The prosecution and later court materials provide case-specific evidence; they should not be expanded into an unsupported claim that every S3 bucket or the entire AWS environment was exposed.

### Control analysis

Engineering lessons for current systems:

- constrain the application/WAF instance role to exact required actions/resources;
- prevent server-side request forgery through URL allowlists, parser-safe validation, egress controls, and removal of generic fetch/proxy behavior;
- segment sensitive data and use data-access/audit detections independent of the web tier;
- monitor unusual metadata/credential access, role sessions, object enumeration, and bulk reads;
- treat application-layer compromise plus reachable workload credentials as a compound threat and test it.

AWS launched IMDSv2 on November 19, 2019 - months after the March incident. Requiring IMDSv2 and limiting metadata hop behavior are strong **retrospective defense-in-depth** recommendations for current EC2 designs. They must not be described as a control Capital One failed to enable at incident time.

### Residual caution

IMDSv2 reduces important SSRF/metadata attack paths but does not repair an overly privileged role, arbitrary command execution, compromised host, exposed credentials, or sensitive-data access that the role is authorized to perform.

## Uber, September 2022

### Confirmed chronology and access path

Uber's September 19 security update said an external contractor's account was compromised. Uber reported it was likely the attacker purchased the contractor's corporate password after the contractor's personal device was infected with malware. The attacker repeatedly attempted to log in, generating two-factor approval requests, and the contractor accepted one. Uber said the attacker then accessed other employee accounts and tools and posted a message to a company-wide Slack channel. The company identified the activity on September 15 and responded by restricting affected systems and access.

Use Uber's update for the organization's stated impact. Avoid summaries such as "the attacker controlled all infrastructure" unless a primary source establishes that scope. Password possession plus an approved MFA prompt explains an authenticated session; it does not by itself prove every subsequent privilege path or dataset.

### Control analysis

Engineering inference for present-day programs:

- use phishing-resistant authentication (for example device-bound/passkey/security- key mechanisms appropriate to the workforce platform) for privileged access;
- reduce MFA push fatigue with number matching, context, rate limits, risk signals, help-desk controls, and user reporting;
- prevent an ordinary contractor session from becoming an administrative platform session through tiered identities, just-in-time privilege, device health, network/ application access policy, and separate privileged workstations;
- restrict and monitor credential stores, scripts, shared drives, PAM tools, service credentials, and administrative remote-management systems;
- correlate identity, endpoint, SaaS, source-control, secrets, and cloud audit events.

### Failure mode lesson

MFA success is an authentication signal, not proof of legitimate intent. Repeated denials followed by approval, new device/location, contractor privilege use, and rapid movement across administrative tools should create high-confidence containment and human-verification paths.

## CircleCI, December 2022 to January 2023

### Confirmed chronology and mechanism

CircleCI's incident report states that malware on an employee laptop enabled a threat actor to steal a valid, two-factor-authenticated session cookie. CircleCI reported the initial laptop compromise on December 16, 2022, reconnaissance on December 19, and data exfiltration on December 22. The employee had privileges that enabled generation of production access tokens, and the attacker extracted encryption keys from a running process, enabling access to encrypted customer credentials. CircleCI alerted customers in early January 2023 and instructed rotation.

The event is best described as a December 2022 compromise discovered/disclosed in January 2023, not simply a "2023 breach." The primary report should govern detailed scope, token rotation, and remediation claims.

### Control analysis

Engineering lessons:

- session cookies for privileged SaaS/control-plane access are bearer credentials; protect endpoints, bind sessions/device context where supported, shorten privileged lifetimes, and reauthenticate for critical actions;
- separate ordinary engineering sessions from production token-generation authority;
- reduce standing privileges and require just-in-time, approved, attributable access;
- design encryption so a single long-running process and its identity cannot expose every customer's credential without additional scoped authorization/audit;
- make customer-secret rotation fast, automatable, and inventory-driven;
- provide customers with exact affected secret categories, time windows, audit evidence, and verification steps.

Encryption at rest did not make the decrypted data inaccessible to an authorized running process. This is a general envelope/key-access design lesson, not a reason to discard encryption at rest.

## Cross-case engineering patterns

| Pattern | Capital One | Uber | CircleCI | Current design response |
|----|----|----|----|----|
| Trusted workload/user session abused | workload credentials reached from web tier | contractor session accepted after MFA prompts | stolen authenticated session cookie | constrain session privilege and continuously evaluate context |
| Privilege compounded impact | data-access role capabilities | movement into other internal tools/accounts | ability to mint production tokens/read keys | eliminate standing privilege; separate trust tiers and duties |
| One control was insufficient | perimeter/WAF did not contain data role | MFA approval did not establish legitimate intent | encryption did not protect from authorized process/key access | layer preventive, detective, and recovery controls |
| Credential lifecycle mattered | workload credential scope/session | password/session/admin secrets | customer secrets required rotation | inventory, scope, short lifetime, revocation and rehearsed rotation |
| Detection/reconstruction required multiple planes | web, STS/cloud, data access | IdP, endpoint, SaaS/internal tools | endpoint, identity, production, customer credential access | normalize/correlate control-plane and data-plane telemetry |

## Validation questions for architectures

1. Can a server-side request or code-execution flaw reach a credential endpoint or data plane, and what exact authorization would that credential have?
2. Does a successful MFA/session event permit privilege escalation without independent device, role, approval, and risk controls?
3. Which identities can mint production/customer credentials or read encryption keys from memory/control planes?
4. Can the organization identify every credential/artifact/data object touched by one compromised session and revoke/rotate it quickly?
5. Are controls evaluated as of incident date, and are later mitigations labeled retrospective?

## Operational checklist

Incident timelines use occurrence, detection, containment, and disclosure dates.

Record counts and access scope retain the source's precision and caveats.

Confirmed fact, inference, and retrospective control are visibly separated.

Identity/session privilege is correlated with endpoint, SaaS, cloud, and data access telemetry.

Workload/user credentials are narrow, short-lived, and revocable.

Break-glass, bulk-secret rotation, and customer notification evidence are tested.

New vendor/court disclosures trigger review rather than silent narrative drift.

## Limitations

These are public-source case studies, not forensic reports. They do not assign legal liability, evaluate controls unavailable in private evidence, or claim that listed recommendations would certainly have prevented the incidents.

## References

- [Capital One 2019 incident facts](https://www.capitalone.com/digital/facts2019/)
- [US Department of Justice: United States v. Paige Thompson](https://www.justice.gov/usao-wdwa/united-states-v-paige-thompson)
- [DOJ arrest announcement describing the WAF access path](https://www.justice.gov/usao-wdwa/pr/seattle-tech-worker-arrested-data-theft-involving-large-financial-services-company)
- [AWS launch of IMDSv2 on November 19, 2019](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/)
- [Uber September 2022 security update](https://www.uber.com/newsroom/security-update/)
- [CircleCI January 2023 incident report](https://circleci.com/blog/jan-4-2023-incident-report/)
- [CircleCI January 4, 2023 security alert](https://circleci.com/blog/january-4-2023-security-alert/)
