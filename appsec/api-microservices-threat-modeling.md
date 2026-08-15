---
title: "API and Microservice Trust Boundaries: Workload Identity, User Context and Downstream Authorization"
id: "api-microservices-threat-modeling"
navTitle: "API threat modeling"
order: 40
type: "appsec"
tags:
  - appsec
  - api
  - microservices
  - threat
  - modeling
date: "2026-07-25"
lastReviewed: "2026-07-25"
reviewStatus: "partially-verified"
validatedAgainst:
  - "NIST SP 800-204 - Security Strategies for Microservices-based Application Systems — https://csrc.nist.gov/pubs/sp/800/204/final"
  - "NIST SP 800-204A - Building Secure Microservices-based Applications Using Service-Mesh Architecture — https://csrc.nist.gov/pubs/sp/800/204/a/final"
  - "RFC 9700 - Best Current Practice for OAuth 2.0 Security — https://www.rfc-editor.org/rfc/rfc9700.html"
  - "RFC 8693 - OAuth 2.0 Token Exchange — https://www.rfc-editor.org/rfc/rfc8693.html"
  - "OpenID Connect Core 1.0 incorporating errata set 2 — https://openid.net/specs/openid-connect-core-1_0.html"
  - "Kubernetes Network Policies — https://kubernetes.io/docs/concepts/services-networking/network-policies/"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "illustrative"
reviewIntervalDays: 90
---

# API and Microservice Trust Boundaries: Workload Identity, User Context and Downstream Authorization

This is a design and review guide based on how I'd threat-model this myself — not a claim that I've got a specific platform running somewhere with these exact controls. Authentication only answers who presented a credential. Authorization still has to decide whether that principal can do this particular thing, to this tenant-bound object, right now.

## The core decision

Use two independent identity planes. Authenticate each calling workload at the service boundary, and carry the end-user's delegation in an audience-constrained token that the receiving resource server validates itself. Reject unsigned identity headers outright. The resource-owning service should enforce tenant, object, state-transition, and business-policy authorization even when a gateway or mesh has already let the call through.

Pick one user-context pattern on purpose, rather than drifting into a mix: either validate the original audience-appropriate access token at each resource server, or use a trusted token service to exchange or mint a short-lived internal token for the exact downstream audience. Neither pattern turns mTLS, a NetworkPolicy, or a gateway into an application authorization boundary by itself.

## Scope and non-goals

The scope is an HTTP API behind an ingress or gateway, with downstream services that may run on Kubernetes. The protected assets are tenant data, high-impact operations, access tokens, signing keys, workload credentials, authorization policy, and audit evidence.

Where an external OAuth flow creates the user grant, RFC 9700 is the current OAuth Security Best Current Practice: use exact redirect-URI matching and do not revive deprecated insecure modes. Those client/authorization-server controls complement, but do not replace, the resource-server checks modeled here.

- **In scope:** direct reachability, caller authentication, delegated user context, replay, token confusion, and downstream authorization.
- **Out of scope:** selecting a service-mesh product, implementing JWT cryptography, or asserting that one topology fits every trust model.

## Actors and assets

| Actor | Credential or capability | Security question |
|----|----|----|
| End user | Access token and session context | Was the user authenticated, and what delegation was granted? |
| OAuth client | Client identity, redirect flow, proof key or sender constraint | Is this the client for which the grant was issued? |
| Gateway or token service | Workload identity and, if authorized, token-minting key | May it transform user context for this audience? |
| Calling workload | mTLS certificate, SPIFFE identity, cloud identity, or bound service-account token | Which deployed workload made this hop? |
| Resource service | Audience identity plus data-plane permissions | Does it own and enforce the final authorization decision? |

## Trust boundaries

    user / OAuth client
      → public authorization and API boundary
      → gateway or token service
      → workload-authenticated service boundary
      → resource-owning service
      → tenant-aware data boundary

Record actual listeners, routes, identities, and alternate paths for every arrow. A Kubernetes Service, pod IP, debug port, job, sidecar, batch worker, or peered network can create a path that does not traverse the public gateway. A compromised pod and a deliberate service-mesh bypass are different scenarios: test network reachability and accepted identity for each.

## Threat model

| Threat | Required precondition | What stops it |
|----|----|----|
| Direct backend invocation | Backend listener is reachable and accepts the caller | Network policy plus workload authentication and resource-server authentication |
| Identity-header spoofing | Service treats a mutable header as authoritative | Remove untrusted headers and derive identity only from validated credentials |
| Token substitution | Issuer or audience validation is missing or ambiguous | Maintained token-validation library with fixed issuer and exact intended audience |
| Cross-tenant access | Tenant claim is accepted without binding it to subject and object | Tenant-aware object query and business authorization |
| Replay | Bearer token or high-impact request can be reused within its validity window | Short lifetime, sender constraint where appropriate, idempotency, nonce or replay store for the operation |

## Direct-service bypass

A gateway is not a choke point merely because the intended client path uses it. Inventory every route to each backend and test from untrusted namespaces, compromised workload identities, administration networks, and asynchronous workers. Kubernetes NetworkPolicy is an L3/L4 reachability control implemented by the network plugin; it does not validate the requested object or business action, and a policy object has no effect when the selected plugin does not enforce it.

The backend must fail closed when the expected workload identity or user token is absent. NetworkPolicy and mesh authorization reduce reachable callers, but the service still validates its application credential and authorizes the operation.

## Header spoofing

Never authorize from `X-User-Id`, `X-User-Roles`, `X-Tenant-ID`, or equivalent headers merely because they arrived from an internal address. Stripping client-supplied copies at the gateway prevents one path of confusion, but it is insufficient when a backend is directly reachable or another workload can mint the same headers.

If a proxy adds convenience headers, treat them as derived, non-authoritative context. Bind the request to the validated token and authenticated proxy workload, prevent bypass paths, and ensure the receiving service rejects conflicting or duplicated identity representations.

## Workload identity versus user identity

| Identity | What it can establish | What it does not establish |
|----|----|----|
| mTLS or workload credential | The peer controlling the private key or credential accepted for this channel | End-user identity, tenant membership, resource ownership, or permission for a business action |
| End-user access token | Delegation represented by validated claims for the intended resource server | That the calling workload is trusted, or that the requested object belongs to the subject |
| Application authorization result | A decision over principal, tenant, object, action, and current state | Future requests or a different resource |

Kubernetes service accounts are non-human workload identities. Bound service-account tokens can include an audience, expiry, and not-before time. Their successful authentication must still be followed by authorization.

## Token propagation versus token exchange

### Pattern 1: resource-server validation

Each resource server receives an access token intended for it, validates the token with a maintained library, and performs its own authorization. This preserves end-user delegation but can expose the original bearer token to more workloads and fails when one broad token is accepted by unrelated services.

### Pattern 2: constrained internal token

A trusted gateway or token service uses a defined exchange such as RFC 8693, or an equivalent reviewed minting flow, to issue a short-lived internal token. The token contains only required context and has an exact downstream audience. The minting service must authenticate the caller, verify the incoming grant, constrain delegation, protect its signing key, and log the exchange without logging tokens.

Do not prescribe nested JWTs as a generic solution. Token format does not fix an over-broad audience, confused deputy, missing tenant binding, or absent object authorization.

### Validation contract for either pattern

- Verify the signature with an allowed algorithm and trusted, bounded key set.
- Require the configured issuer and the exact intended audience.
- Validate expiry and not-before with a documented clock-skew allowance.
- Validate the expected subject and client or authorized-party semantics.
- Bind tenant context to the authenticated subject and requested object.
- Validate purpose, scope, authorization details, or another operation context where required.
- Perform downstream object and business authorization after token validation.

## Downstream authorization

The service that owns the resource should authorize using server-derived object attributes. A safe decision resembles:

    allow when
      token is valid for this service
      AND authenticated workload may call this operation
      AND token tenant equals route tenant and object tenant
      AND subject has the required relationship or permission
      AND object state permits the transition
      AND request satisfies replay and risk controls

Query by both object identifier and tenant boundary where possible. Do not fetch an object globally and compare only a user-supplied tenant header afterward. Administrative and support paths need explicit, separately audited policy rather than a magic role string.

## Failure modes

- **Identity provider or JWKS unavailable:** use bounded key caching and fail closed for unknown keys; do not disable validation.
- **Clock drift:** alert before time validation begins rejecting legitimate traffic; keep skew small and explicit.
- **Token service unavailable:** define which operations fail, queue, or use an already valid token; never mint unsigned fallback context.
- **Mesh or policy outage:** the application continues to reject missing or invalid credentials.
- **Authorization dependency unavailable:** deny high-impact operations; narrowly scope any documented read-only degradation.
- **Key compromise:** stop minting, rotate, revoke or shorten acceptance, and search by issuer, key ID, audience, and token identifier.

## Cases that should fail

**This is the test plan I'd run against a real implementation — I haven't executed it for this write-up.**

| Case | Expected result | Evidence to retain |
|----|----|----|
| Spoofed user or tenant header | Ignored or rejected; never changes the authorization principal | Gateway and service decision with redacted headers |
| Missing workload identity | Connection or request denied | mTLS or workload-authentication denial |
| Wrong issuer | 401 before handler execution | Reason code, not token contents |
| Wrong audience | 401 at the receiving service | Expected and observed audience classification |
| Expired token | 401 outside documented skew | Time-validation reason |
| Not-before violation | 401 until valid time | Time-validation reason |
| Wrong client or authorized party | 401 or policy denial | Client-validation reason |
| Wrong tenant | 403 or non-enumerating 404 | Tenant-policy decision |
| Valid identity without resource authorization | 403 or non-enumerating 404 | Object-policy decision |
| Direct backend call bypassing gateway | Network or application authentication denial | Reachability test and backend denial |
| Gateway token used at the wrong service | 401 for audience mismatch | Wrong-service test result |
| Replayed high-impact request | Duplicate suppressed or denied according to operation design | Idempotency or replay-store decision |

## Observability

Correlate a generated request ID with authenticated workload identity, token issuer, subject pseudonym, client ID, audience, tenant identifier, authorization policy/version, resource class, decision, reason code, and latency. Do not log raw access tokens, signing keys, or unrestricted personal data. Alert on direct backend attempts, repeated audience failures, cross-tenant denials, unexpected minting clients, signing-key changes, and replay decisions.

## Rollout and rollback

1. Inventory listeners, routes, credentials, audiences, and current header dependencies.
2. Add decision telemetry and shadow validation without treating shadow success as authorization.
3. Issue service-specific audiences and migrate one receiving service at a time.
4. Enforce workload identity, then remove direct routes and legacy header trust.
5. Run the negative matrix in each environment and rehearse signing-key and issuer outage response.

Rollback should restore the previous validated token path, not plaintext identity headers or a shared all-services audience. Keep old signing keys only for the minimum overlap needed for already-issued tokens, and retain an emergency deny capability.

## What's still not solved

Even with this in place: a compromised gateway or token service, a stolen bearer token used within its validity window, plain old authorization bugs in the app, stale relationship data, a compromised signing key or identity provider, policy exceptions people forgot to clean up, side channels, and asynchronous paths I haven't modeled here all remain open problems. Sender-constrained tokens cut down on replay by a different client, but they don't prove business authorization on their own.

## References

- [NIST SP 800-204 - Security Strategies for Microservices-based Application Systems](https://csrc.nist.gov/pubs/sp/800/204/final)
- [NIST SP 800-204A - Building Secure Microservices-based Applications Using Service-Mesh Architecture](https://csrc.nist.gov/pubs/sp/800/204/a/final)
- [RFC 9700 - Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html)
- [RFC 8693 - OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)
- [OpenID Connect Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html)
- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Kubernetes Service Accounts](https://kubernetes.io/docs/concepts/security/service-accounts/)
