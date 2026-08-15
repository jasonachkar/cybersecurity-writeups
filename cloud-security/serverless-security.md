---
title: "Serverless Security Engineering: Event Trust, Function Identity and Runtime Reuse"
id: "serverless-security"
navTitle: "Serverless security"
order: 60
type: "cloud-security"
tags:
  - cloud-security
  - serverless
  - security
date: "2026-07-25"
lastReviewed: "2026-07-25"
reviewStatus: "partially-verified"
validatedAgainst:
  - "API Gateway Lambda proxy integration — https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-set-up-simple-proxy.html"
  - "API Gateway private HTTP integrations and VPC links — https://docs.aws.amazon.com/apigateway/latest/developerguide/private-integration.html"
  - "API Gateway API keys and usage plans — https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-usage-plans.html"
  - "AWS Lambda execution roles and role sharing — https://docs.aws.amazon.com/lambda/latest/dg/concepts-basics.html"
  - "AWS Lambda execution-environment lifecycle and `/tmp` reuse — https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html"
  - "AWS Lambda security and execution-environment best practices — https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "illustrative"
reviewIntervalDays: 90
---

# Serverless Security Engineering: Event Trust, Function Identity and Runtime Reuse

Serverless removes server administration from the application team; it does not remove trust boundaries. Authenticate the event source, authorize invocation, validate event content and replay behavior, give the function only the downstream permissions it needs, and assume an execution environment can be reused.

## The core decision

For each function, document the accepted event producers, invocation policy, event schema, replay/idempotency contract, execution role, downstream resources, secret-delivery path, network path, failure destination, and data retained in memory or `/tmp`. Separate roles when functions cross materially different ownership, data classification, or permission boundaries. Shared roles are acceptable only for functions with genuinely identical trust and required permissions and with a controlled change process.

## Scope, assets and actors

The reference architecture includes synchronous API Gateway invocation and asynchronous AWS event sources. Assets include customer data, event payloads, function code and layers, environment configuration, execution roles, resource policies, authorizer context, secrets, downstream data stores, queues, logs, and deployment artifacts.

| Actor | Credential or capability | Decision |
|----|----|----|
| API client or event producer | User token, IAM signature, service principal, resource ownership | May this producer invoke this route/function? |
| API Gateway / event service | AWS service identity plus configured integration/source | Is the service constrained to the expected API, queue, bucket, topic or rule? |
| Function | Execution role and runtime code | Which downstream actions/resources/conditions are allowed? |
| Deployment principal | Code/config/role update authority and `iam:PassRole` | May it change both code and the function's authority? |

## Event trust boundaries

Receiving an AWS-shaped JSON object does not prove its source. Establish trust at the integration:

- Constrain the function resource policy to the expected service principal and source ARN/account where supported.
- For queues, topics, buckets and event buses, constrain who may write to the source as well as who may invoke the function.
- Validate event type/version, required fields, size, identifiers and resource ownership. Treat free-form metadata as untrusted input.
- Design for duplicate and out-of-order delivery. Use an operation-specific idempotency key and durable state when side effects must occur once.
- Bound recursion, fan-out, batch size, retries, event age and concurrency. Configure a dead-letter queue or failure destination with ownership and replay controls.

Authentication of the producer does not authorize the requested business action. A valid user, bucket, topic or partner can still submit an object identifier belonging to another tenant.

## API Gateway to Lambda integration

    Client
      → API Gateway
      → IAM / JWT, Lambda authorizer, or Cognito authorizer as appropriate
      → Lambda proxy integration
      → narrowly authorized downstream services

A direct Lambda integration uses an AWS/Lambda integration; the common proxy form is `AWS_PROXY`. A VPC link is for a private HTTP integration to VPC resources such as a load balancer and ECS-backed service. It is not the hop between API Gateway and a directly integrated Lambda function.

    Separate private HTTP example:
    Client → API Gateway → VPC link → ALB/NLB → ECS or private HTTP service

Validate authorization at the gateway and again at the function/resource layer where business context is available. The function must not trust authorizer context merely because a test event contains similarly named fields; it should rely on the configured integration and validate the expected claim contract.

### API keys are not authentication

AWS explicitly says not to use API Gateway API keys for authentication or authorization. They identify usage-plan clients for metering and best-effort throttling; values can appear in headers and logs, and usage-plan quotas are not hard limits. Use IAM, a Lambda authorizer, or a Cognito user pool as appropriate for access control, then use API keys only when their metering purpose is required.

## Function identity and permission boundaries

Every Lambda function has an execution role, and AWS permits one role to be used by more than one function. The engineering rule is:

> Use separate roles for materially different trust and permission boundaries. Functions with identical ownership, data classification and required permissions may share a carefully scoped role, but broad catch-all roles create unnecessary blast radius.

Scope actions, resources and conditions; constrain KMS encryption context or service-specific attributes where useful; and separately constrain who can update function code/configuration, attach layers, add event sources, edit resource policies, and pass the role. A least-privilege execution role does not help if an attacker can replace the function or pass it a stronger role.

Use IAM Access Analyzer and CloudTrail activity as inputs to refinement, not proof that unused permissions are safe. Negative-test explicit denies, cross-account resource policies, and the exact function alias/version used by production.

## Runtime reuse and data lifetime

A Lambda execution environment may be frozen and reused for later invocations of the same function environment, but reuse is not guaranteed. Global objects and connections can persist when reuse occurs. AWS documents `/tmp` as storage unique to an execution environment whose contents remain across warm reuse and even some reset paths.

- Use reuse for immutable clients, connections and non-sensitive caches with freshness/error checks.
- Do not retain user data, events, authorization results, bearer tokens, or other security-sensitive state across invocations.
- Namespace and delete temporary files defensively, apply restrictive permissions, bound size, and handle cleanup failure.
- Clear per-request variables and asynchronous callbacks before returning. Do not assume a new invocation means a new process.

Do not claim predictable “memory scavenging” of a prior invocation. A compromised process can read data and credentials available in its current process and execution environment; arbitrary cross-function or future-invocation memory reads are not established by the reuse model.

## Secrets retrieval, caching and rotation

AWS recommends Secrets Manager instead of environment variables for database credentials and similar sensitive values. Dynamic retrieval changes the risk rather than eliminating it:

- Grant the exact secret ARN and `secretsmanager:GetSecretValue`; include only the required KMS decrypt permission.
- Choose a cache TTL that balances availability/cost/latency against rotation freshness. AWS's extension and Powertools support local caches; stale cache behavior must be tested.
- Define behavior for throttling, timeout, regional outage, access denial, malformed secret, and rotation overlap. Fail closed for privileged actions; do not fall back to a hard-coded secret.
- Never place secret values in request parameters, logs, exceptions, traces, metrics dimensions, dead-letter events, or returned errors.
- Secrets remain plaintext in process memory while used. Rotation does not remove already copied values or necessarily terminate existing database sessions.
- Protect the rotation function as a privileged deputy and verify it changes the intended target.

## Network attachment and egress

A Lambda function does not need attachment to a customer VPC merely to be “secure.” By default, Lambda runs functions in a service VPC with connectivity to AWS services and the internet. Attach a function to the customer's VPC when it needs private VPC resources or the design requires customer-controlled network paths.

When attached, the function follows the selected subnet route tables and security groups. Placing it in a subnet called “private” does not create internet access; intended outbound internet connectivity needs a route through a NAT gateway (or another designed egress path), while supported AWS services may use appropriate VPC endpoints. Test DNS, IPv4/IPv6, endpoint policies, NAT failure, security groups, IP/ENI capacity and downstream timeouts.

Network controls do not replace execution-role or resource authorization. Conversely, IAM allow does not create a network route.

## Threat-based WAF decision

Do not require a WAF for every serverless API. Consider AWS WAF for exposed HTTP APIs that benefit from managed exploit rules, IP/geo/rate controls, bot controls or emergency virtual patches. Assess parser alignment, inspection limits, cost, latency, false positives, alternate routes and operational ownership.

APIs with private access, non-HTTP events, tightly controlled machine clients, or a low-value/simple request surface may prioritize other controls. Even when WAF is present, preserve application authorization, input validation, quotas/concurrency, abuse detection and patching.

## Failure cases and what should get denied

**This is the test plan I'd run against a real deployment — I haven't executed it for this write-up.**

| Case | Expected result |
|----|----|
| Direct function invoke by an unapproved principal/source ARN | Resource-policy denial |
| Valid API key without valid authentication | Authentication denial; API key alone grants no access |
| Valid user requests another tenant's object | Business authorization denial |
| Duplicate asynchronous event | Idempotent side effect and recorded duplicate decision |
| Poison event exhausts retries | Bounded retry then controlled failure destination; no infinite recursion |
| Warm invocation after sensitive request | No prior user/event state in globals or `/tmp` |
| Secret rotates while cache is warm | Documented overlap/retry; cache refreshes within policy |
| Secrets Manager or KMS unavailable | Bounded timeout and fail-closed behavior without secret leakage |
| Function assumes shared role after another function gains permission | Change review detects shared blast-radius increase |
| VPC-attached function needs internet without NAT | Fast bounded failure; network alarm identifies route dependency |
| WAF rule false positive | Canary/count evidence and scoped rollback, not global bypass |

## Observability, rollout and rollback

Correlate API request ID or event ID, authenticated principal, source ARN/account, function ARN/version/alias, cold/warm indicator where available, execution-role session, authorization result, downstream resource, idempotency decision, retry/age, secret version label (never value), network error class, duration, concurrency and failure destination.

1. Inventory producers, invocation/resource policies, roles, role-sharing, downstream resources, secrets, routes and failure paths.
2. Add contract tests for event schema, producer binding, tenant/object authorization and duplicate delivery.
3. Canary role and networking changes using aliases or staged traffic; monitor denies, timeouts, concurrency and downstream saturation.
4. Load-test timeouts, retries and reserved concurrency against dependency capacity.
5. Rehearse rollback of code/configuration, role policy, event-source mapping, secret version and WAF rule independently.

Rollback to a previously reviewed version and permission set. Do not restore availability by attaching a broad managed policy, disabling authorizers, exposing a private backend, or logging secret values.

## What's still not solved

Compromised deployment principals, a dependency or layer supply-chain issue, confused-deputy resource policies, a producer that's valid but malicious, cross-tenant bugs in the app itself, replay inside the idempotency window, stale secret caches, warm-state leakage, a service or region outage, downstream saturation, event loss past the retention window, and telemetry gaps — all still possible. Managed isolation and short-lived execution environments cut down some exposure, but they don't prove tenant isolation or that the application logic is correct.

## References

- [API Gateway Lambda proxy integration](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-set-up-simple-proxy.html)
- [API Gateway private HTTP integrations and VPC links](https://docs.aws.amazon.com/apigateway/latest/developerguide/private-integration.html)
- [API Gateway API keys and usage plans](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-usage-plans.html)
- [AWS Lambda execution roles and role sharing](https://docs.aws.amazon.com/lambda/latest/dg/concepts-basics.html)
- [AWS Lambda execution-environment lifecycle and `/tmp` reuse](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html)
- [AWS Lambda security and execution-environment best practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [Using Secrets Manager with Lambda, caching and rotation freshness](https://docs.aws.amazon.com/lambda/latest/dg/with-secrets-manager.html)
- [AWS Secrets Manager `GetSecretValue` permissions and caching guidance](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html)
- [AWS Lambda VPC and internet connectivity](https://docs.aws.amazon.com/lambda/latest/dg/troubleshooting-networking.html)
- [AWS WAF web ACL controls](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl.html)
