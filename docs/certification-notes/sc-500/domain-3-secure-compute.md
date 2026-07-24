# Study Notes: Secure compute

This skills group includes AI and agent workloads, servers and virtual machines, and
application platform services. Product behavior and licensing should be checked in
current Microsoft documentation.

## AI and agent workload objectives

Current outline topics include Microsoft Purview DSPM for AI, Copilot Studio
real-time protection, Microsoft Entra Agent ID access and Conditional Access,
Defender XDR blast-radius analysis, Azure API Management AI Gateway for Microsoft
Foundry, Defender for AI Services, Foundry agent guardrails, and Microsoft 365 agent
management.

Content filters, prompt instructions, and agent guardrails can reduce some unsafe
outputs. They are not authorization boundaries. Tool, data, and tenant authorization
must be enforced by deterministic services outside the model using an authenticated
principal and capability-scoped identity.

For engineering detail and tests, use the repository's
[AI agent security investigation](../../../appsec/ai-agent-security.md), not this
exam summary.

## Servers and virtual machines

Study:

- disk encryption and key ownership;
- Azure Bastion and just-in-time access;
- Azure Arc for hybrid and multicloud servers;
- Defender for Servers plans, vulnerability assessment, EDR, and agentless scanning;
- secure boot, vTPM, integrity monitoring, and VM security types; and
- Azure Machine Configuration enforcement.

Distinguish a posture recommendation from an enforced deny and from a runtime
detection. Document exception and remediation ownership.

## Application platform services

Study the security control planes for:

- AKS and Defender for Containers;
- Azure Container Registry, Container Instances, and Container Apps;
- Functions, Logic Apps, and App Service identity/network controls;
- Web Application Firewall; and
- API Management policy for back-end API protection.

Private connectivity reduces exposure under the selected routing and DNS design; it
does not replace workload authorization, input validation, or runtime monitoring.

## Review questions

1. Which service enforces the decision and which service only reports posture?
2. What identity performs remediation?
3. Which traffic path remains when a private endpoint is enabled?
4. How does an agent obtain a tool credential, and who authorizes the action?
5. What evidence shows a recommendation moved from audit to enforcement?

## References

- [Official SC-500 study guide](https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/sc-500)
- [Azure compute security documentation](https://learn.microsoft.com/en-us/azure/security/fundamentals/virtual-machines-overview)
- [Microsoft Foundry security](https://learn.microsoft.com/en-us/azure/ai-foundry/concepts/security)
