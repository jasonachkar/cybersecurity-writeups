---
title: "Cloud Network Segmentation and Egress Control: Routing, Private Endpoints and Failure Domains"
id: "cloud-network-segmentation"
navTitle: "Network segmentation"
order: 20
type: "cloud-security"
tags:
  - cloud-security
  - cloud
  - network
  - segmentation
date: "2026-07-25"
lastReviewed: "2026-11-02"
reviewStatus: "requires-review"
validatedAgainst:
  - "2026-11-02 research-protocol and local-test audit; retained product claims require independent renewed source review"
  - "AWS Transit Gateway route tables, associations and propagation — https://docs.aws.amazon.com/vpc/latest/tgw/tgw-route-tables.html"
  - "How AWS Transit Gateway routing and appliance mode work — https://docs.aws.amazon.com/vpc/latest/tgw/how-transit-gateways-work.html"
  - "AWS Transit Gateway asymmetric routing and appliance mode — https://docs.aws.amazon.com/prescriptive-guidance/latest/inline-traffic-inspection-third-party-appliances/transit-gateway-asymmetric-routing.html"
  - "AWS gateway endpoints for Amazon S3 — https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html"
  - "AWS VPC endpoint policies and interaction with identity/resource policies — https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html"
  - "Route 53 Resolver DNS Firewall behavior — https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-overview.html"
sourceQuality: "requires-review"
implementationStatus: "illustrative"
reviewIntervalDays: 90
---

# Cloud Network Segmentation and Egress Control: Routing, Private Endpoints and Failure Domains

Segmentation is an enforced reachability decision, not a diagram of subnets. Separate administrative ownership, routing, stateful filtering, identity policy, and resource policy; then test the allowed and denied paths in both directions, including IPv6 and failure behavior.

## The core decision

Define communication intents first: source principal/workload, destination, protocol, port, direction, data classification, and owner. Implement the minimum routes, security-group rules, endpoint policies, identity policies, and resource policies needed for those intents. Use centralized, distributed, or hybrid inspection according to failure-domain, latency, scale, cost, ownership, and regulatory needs rather than assuming one central firewall is mandatory.

A dedicated VPC provides administrative and network-isolation primitives; it is not physical isolation. Separate subnets do not isolate traffic unless route and enforcement controls deny the path.

## Scope and assets

The reference model covers AWS VPCs connected directly or through Transit Gateway, private access to AWS services, north-south and east-west traffic, DNS resolution, IPv4/IPv6 egress, and optional inspection appliances. Protect:

- workload and management-plane reachability;
- tenant or environment separation;
- approved internet and SaaS destinations;
- endpoint, bucket, identity and firewall policy;
- routing, DNS and TLS key custody; and
- flow, query, firewall, proxy and configuration evidence.

## Enforcement planes

| Plane | What it enforces | What it does not prove |
|----|----|----|
| VPC/subnet route table | Selected next hop for a destination prefix | That the destination authorizes the caller or an appliance permits traffic |
| Transit Gateway route table | Attachment-to-attachment forwarding and blackholes | Application identity or stateful inspection |
| Security group | Stateful ENI/resource traffic rules | Business authorization or an intended route through inspection |
| Network ACL | Stateless subnet boundary rules | Connection state, identity, or application semantics |
| Firewall/proxy | Supported flow, protocol, domain and content policy | Complete data-loss prevention or application authorization |
| VPC endpoint policy | Which principals/actions/resources may use that endpoint | Authorization without matching identity and resource policies |
| Identity/resource policy | Service API authorization under policy evaluation | That traffic used the expected endpoint unless conditions enforce it |

Security groups are valuable stateful enforcement controls, not merely “basic” filters. Use references and narrowly scoped CIDRs where appropriate, account for return traffic and ephemeral ports, and test rule changes. Network identity remains separate from user/tenant authorization.

## Transit Gateway routing

Transit Gateway is a router; it does not automatically create segmentation or inspection. For each attachment, distinguish:

- **Association:** the single Transit Gateway route table consulted for traffic entering from that attachment.
- **Propagation:** installation of an attachment's routes into one or more Transit Gateway route tables. A propagated VPC attachment contributes its CIDR routes; static and blackhole routes can be added separately.

Segmentation depends on the resulting route tables. A shared default association/propagation design can create broad reachability. Conversely, an absent TGW route is not sufficient when VPC peering, direct internet gateways, NAT, endpoints, VPN, Direct Connect, or another route exists.

### Stateful appliances and asymmetry

Trace both request and response through VPC subnet route tables, Transit Gateway tables, appliance endpoints, NAT and internet gateway routes. A stateful device may drop a flow if directions traverse different appliance instances or Availability Zones. AWS Transit Gateway appliance mode keeps the same Availability Zone for the lifetime of a flow on the appliance VPC attachment; it is not a substitute for correct bidirectional routes or health/failover design.

## Centralized, distributed and hybrid egress

| Topology | Advantages | Costs and failure modes |
|----|----|----|
| Centralized inspection/egress VPC | Consistent policy, consolidated tooling and evidence, fewer public egress points | Shared blast radius, routing complexity, inter-AZ/data processing cost, latency, scale and asymmetric-path risk |
| Distributed per-VPC egress | Smaller failure domains, local ownership, direct path and potentially simpler routing | Duplicated controls, policy drift, more NAT/firewall cost and fragmented telemetry |
| Hybrid | Central controls for high-risk/shared paths with local endpoints or egress for selected workloads | More policy classes and a higher risk of unintended bypass if ownership is unclear |

PrivateLink or another private endpoint creates a private path for selected services; it does not remove internet gateways, NAT, proxies, public endpoints, peering paths, or IPv6 egress. Explicitly remove or deny paths that should not exist. Audit IPv4 and IPv6 separately, including egress-only internet gateways, NAT64/DNS64 where used, dual-stack service endpoints, and security rules.

## Private endpoints and S3

Amazon S3 supports both **gateway** and **interface** VPC endpoints:

| Endpoint | Routing/connectivity | Cost and use considerations |
|----|----|----|
| S3 gateway endpoint | Adds an S3 prefix-list route to associated VPC route tables; it cannot be used from on-premises, peered VPCs, another Region, or through Transit Gateway | No additional endpoint charge; local VPC route-table scope |
| S3 interface endpoint | PrivateLink ENIs and DNS; supports connectivity patterns that require interface endpoints, including appropriate on-premises/private network access | Hourly/data processing charges, subnet/AZ design and security groups |

An endpoint policy controls use of that endpoint. AWS explicitly states that it does not override or replace identity-based or resource-based policies. A request succeeds only when all applicable policy layers allow it and no explicit deny applies. Bucket policies can require a specific endpoint or VPC where appropriate, but test AWS-service access, console behavior, backup/replication, and break-glass paths before enforcing such conditions.

Endpoint policies are preventive controls for that path, not proof that all service traffic uses the path. Monitor endpoint configuration, DNS resolution, route changes, public service access, and rejected API calls.

## DNS and exfiltration

Route 53 Resolver DNS Firewall filters domain names for queries that traverse the VPC Resolver, and query logging provides useful but cache-aware visibility. It is not complete data-loss prevention. Model:

- direct IP connections and hard-coded endpoints;
- DNS over HTTPS/TLS and application-embedded resolvers;
- alternate or on-premises resolvers and forwarding rules;
- permitted SaaS destinations used for exfiltration;
- compromised allowed domains and redirection chains;
- domain-fronting-like behavior where protocol/provider behavior permits it;
- DNS caching, which means not every client lookup appears as a resolver query log; and
- IPv6 and private/public answer differences.

Combine resolver controls with route policy, egress proxy/firewall, workload identity, destination allow rules, service control/resource policies, application controls, and telemetry. Decide fail-open or fail-closed behavior for DNS/filter outages and test it.

## TLS interception

Use interception only after a risk and privacy review. It introduces a trusted man-in-the-middle, private-key custody, certificate issuance, endpoint trust-store changes, sensitive plaintext handling, and a new availability dependency. Certificate pinning, mutual TLS, QUIC, unsupported protocols, regulated data, client certificates, and vendor terms can make interception unsafe or ineffective.

Define bypass categories explicitly, protect interception keys in an appropriate cryptographic boundary, minimize logged content, restrict operator access, monitor certificate errors, test failover, and provide a rollback that does not silently route around all inspection.

## Failure modes and what should get blocked

**This is the test plan I'd run against a real VPC/TGW setup — I haven't executed it for this write-up.**

| Failure or test | Expected outcome |
|----|----|
| Source attached to wrong TGW route table | Drift alert; prohibited destination remains unreachable |
| Unexpected route propagation | Reachability analysis/test detects new path before promotion |
| Return path bypasses stateful appliance | Topology test fails; change is blocked or rolled back |
| Inspection endpoint/AZ failure | Documented failover or bounded fail-closed behavior without route leak |
| Public S3 endpoint used despite private endpoint | Identity/bucket conditions deny where required; telemetry identifies path |
| Endpoint policy allows but bucket policy denies | Request denied; test proves endpoint policy is not standalone authorization |
| Direct IP and encrypted-DNS attempt | Route/proxy policy handles it independently of DNS Firewall |
| IPv6 destination bypasses IPv4 egress policy | Denied or routed through an equivalently controlled IPv6 path |
| Allowed SaaS tenant used for exfiltration | Tenant-aware proxy/application or CASB control detects/denies where supported |
| Pinned TLS application traverses interception | Approved bypass or known failure; no emergency global disable |

## Rollout, rollback and observability

1. Export current VPC and TGW routes, associations, propagations, security groups, NACLs, endpoints, DNS rules and IPv6 paths.
2. Model intended reachability and ownership; compare configuration and runtime observations.
3. Deploy logging and alert-only DNS/firewall rules; baseline destinations and false positives.
4. Canary route and endpoint changes in one non-critical segment/AZ, testing both what should work and what should be blocked.
5. Promote with change guardrails, health-based rollback and a maximum affected VPC/account count.

Observe accepted/rejected flow logs, TGW flow logs where enabled, firewall/proxy actions, resolver queries, endpoint connections, route/configuration changes, NAT/IPv6 egress, TLS errors, and service API authorization denials. Flow logs are metadata, not packet or business-intent proof.

Rollback should restore the last reviewed route and policy set. Do not “fix” an outage by adding a broad default route or wildcard allow. Keep a tested management path that does not depend on the failed inspection component but remains strongly authenticated and logged.

## What's still not solved

A compromised destination that's on your allowlist, traffic hidden inside an allowed protocol, missing workload/application identity, drift between regions or accounts, hitting route-scale limits, provider service paths outside your telemetry, bugs in the inspection appliance itself, DNS cache effects, IPv6 gaps, privileged admins, and outages caused by the centralized chokepoints you just built — all still real. Segmentation limits what can reach what; it doesn't replace identity, resource, tenant, or application authorization.

## Research question and hypothesis

**Question:** Does a separate gateway prevent a fetch tool from using a direct internal path after URL controls are bypassed?

**Falsifiable hypothesis (bounded experiment):** The secure tool cannot directly connect to the mock metadata service and rejects redirect-based access while permitting the intended origin; any successful direct connection refutes this local topology.

## Research threat model

| Element | Declared scope |
| --- | --- |
| Actor | Caller controlling a tool URL; separately, compromised tool process |
| Assets | Internal destination, gateway policy and reachability evidence |
| Entry points | URL, redirect response and direct socket connection |
| Trust boundaries | Tool network → gateway network → target network |
| Impact under investigation | Internal service retrieval or routing around inspection |
| Trusted assumptions | Owned test host, reviewed fixture/code and independently established identity context; deployment administrators remain outside the local attacker model |

## Method and evidence requirements

Follow the [evidence standards](../research-methodology/evidence-standards.md).
The [related lab](../labs/mcp-tool-ssrf/README.md) owns setup, prerequisites, expected
output, safety, evidence collection and teardown. From repository root:

```sh
python3 vulnerability-research/mcp-tool-ssrf/lab/test_fetcher.py
```

This command is a **tested local check**, with the scope below. Review test inputs
and failure assertions before interpreting a pass. For a deployment study, capture
exact versions/configuration, one allowed control, every intended denial, state
before/after and independent audit evidence. A policy file or syntax check is T1,
not enforcement proof. Do not deploy cloud resources from repository validation.

## Findings and interpretation

| Claim class | Evidence tier and boundary |
| --- | --- |
| Observed local result | T2/T3 within the linked harness: The linked study additionally runs real Docker TCP and paired HTTP tests. Unit resolver results alone are not network enforcement. |
| Architecture guidance below | T0: sourced explanation or engineering judgment under its stated assumptions |
| Configuration/schema examples | At most T1 unless a linked runtime test explicitly covers that example |
| Production effectiveness | Not established by this repository's local result |

## Practical guidance and failure containment

Treat DNS, routes and application authorization as separate controls. Keep gateway ownership separate and fail closed on dependency errors; an allowed destination remains a disclosure path.

Count exercised allow/deny cases against the declared corpus, keeping structural,
native-policy and runtime results separate. Preserve failure, unknown and missing
telemetry states. Roll back the exact reviewed control change while retaining
evidence; broad privilege or global bypass is not an automatic recovery path.

## Limitations and what was not tested

The local experiment does not validate the complete reference architecture, live
cloud enforcement, hosted CI, production data, independent audit storage or
representative adversarial coverage. Retained implementation and historical
source-inspection descriptions are not newly reproduced results. Review status
remains `requires-review` until a reviewer rechecks the retained product claims
against `validatedAgainst` and the linked evidence.

Time to detect, time to contain, population false-positive/negative rates, pipeline
impact and monthly operational cost are **not measured in this article**. Use the
[measurement contract](../research-methodology/evidence-standards.md#measurement-contract)
to define clocks, denominators, repeated workloads and residual capabilities before
claiming those outcomes. Report local fixture counts separately from live coverage.

## Open questions

Do IPv6, alternate proxies or failover routes bypass the equivalent production egress decision?

## References

- [AWS Transit Gateway route tables, associations and propagation](https://docs.aws.amazon.com/vpc/latest/tgw/tgw-route-tables.html)
- [How AWS Transit Gateway routing and appliance mode work](https://docs.aws.amazon.com/vpc/latest/tgw/how-transit-gateways-work.html)
- [AWS Transit Gateway asymmetric routing and appliance mode](https://docs.aws.amazon.com/prescriptive-guidance/latest/inline-traffic-inspection-third-party-appliances/transit-gateway-asymmetric-routing.html)
- [AWS gateway endpoints for Amazon S3](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html)
- [AWS VPC endpoint policies and interaction with identity/resource policies](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html)
- [Route 53 Resolver DNS Firewall behavior](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-overview.html)
- [Route 53 Resolver query logging and cache behavior](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html)
- [AWS centralized egress architecture and operational guidance](https://docs.aws.amazon.com/prescriptive-guidance/latest/transitioning-to-multiple-aws-accounts/centralized-egress.html)
