---
title: "OAuth 2.0 and OpenID Connect Security Engineering"
type: "appsec"
tags:
  - appsec
  - oauth2
  - oidc
  - deep
  - dive
date: "2026-07-25"
lastReviewed: "2026-07-25"
readingTime: 9
reviewStatus: "partially-verified"
validatedAgainst:
  - "RFC 9700: OAuth 2.0 Security Best Current Practice — https://www.rfc-editor.org/rfc/rfc9700.html"
  - "OpenID Connect Core 1.0 — https://openid.net/specs/openid-connect-core-1_0-18.html"
  - "RFC 9449: Demonstrating Proof of Possession — https://www.rfc-editor.org/info/rfc9449/"
  - "RFC 8705: OAuth mutual TLS — https://www.rfc-editor.org/info/rfc8705/"
  - "RFC 9126: Pushed Authorization Requests — https://www.rfc-editor.org/rfc/rfc9126.html"
  - "RFC 9207: OAuth authorization server issuer identification — https://www.rfc-editor.org/rfc/rfc9207.html"
sourceQuality: "primary-sources-reviewed"
implementationStatus: "partially-tested"
reviewIntervalDays: 90
---

# OAuth 2.0 and OpenID Connect Security Engineering

OAuth delegates access; OpenID Connect (OIDC) adds authentication and identity claims. A secure implementation validates the right token for the right consumer, binds authorization responses to the initiating session, uses exact redirect URIs, protects authorization codes with PKCE, limits bearer-token replay, and treats the authorization server's metadata and keys as trusted configuration - not arbitrary input.

RFC 9700 is the current OAuth Security Best Current Practice. It replaces many older recommendations and makes the authorization code flow with PKCE the general browser/ native baseline. The implicit grant should not be used for new designs.

## Roles, artifacts, and audiences

| Artifact | Intended consumer | Essential interpretation |
|----|----|----|
| Authorization code | Client's registered redirect endpoint | Short-lived intermediate value; redeem once with redirect/client binding and PKCE verifier |
| ID token | OIDC client | Authentication statement about the end-user session; audience normally includes the client's `client_id` |
| Access token | Resource server/API | Authorization credential; audience/resource indicator must identify the API that accepts it |
| Refresh token | Authorization server token endpoint | Long-lived delegation handle; protect from replay and bind/rotate as required |

Do not send an ID token to an API as an access token. Do not validate every access token by comparing `aud` to a UI client's ID: the resource server validates that the token is intended for that resource/API. Exact access-token format and validation may be JWT-profile based, opaque/introspection based, or provider-specific; configure one supported contract rather than guessing from token shape.

## Threat model

```
sequenceDiagram
  participant U as User agent
  participant C as OIDC client
  participant AS as Authorization server
  participant API as Resource server
  C->>C: Create state, nonce, PKCE verifier/challenge
  C->>AS: Authorization request with exact redirect and challenge
  AS->>U: Authenticate and authorize
  AS->>C: Code plus state (and issuer where applicable)
  C->>C: Validate state and expected issuer
  C->>AS: Redeem code with verifier and client authentication if confidential
  AS->>C: ID token, access token, optional refresh token
  C->>C: Validate ID token issuer, audience/client, signature, time, nonce
  C->>API: Access token
  API->>API: Validate issuer, API audience, signature/introspection, time, authorization
```

Material threats are redirect interception, authorization-code injection, CSRF, authorization-server mix-up, open redirectors, token substitution, bearer replay, refresh-token theft, algorithm/key confusion, discovery/JWKS SSRF, excessive scopes, and incorrect subject/account linking.

## Authorization request and callback

### Exact redirect registration

Authorization servers must compare redirect URIs using exact string matching as specified by RFC 9700, with the native-app loopback exception defined by the native application BCP. Avoid wildcard hosts/paths and open redirectors in clients and authorization servers. Validate post-login application return locations separately against a narrow allowlist; never copy an arbitrary `returnUrl` into an OAuth redirect.

### PKCE

Public clients must use PKCE, and RFC 9700 recommends it for confidential clients as well. Generate a high-entropy verifier per authorization request, store it bound to the initiating browser/session, send the `S256` challenge, and delete it after one redemption attempt. Reject downgrade/missing verifier. PKCE protects authorization code interception/injection; it does not replace client authentication for a confidential client or validate the user session by itself.

### `state`, nonce, and issuer

- Bind `state` to the initiating user-agent session and request details; compare once using a safe equality operation and expire it. It is a correlation/CSRF mechanism, not a place for unsigned trusted application state.
- For OIDC, generate and validate `nonce` in the ID token to bind authentication to the request and resist replay.
- Defend mix-up by binding the expected authorization server/issuer to the transaction and validating the authorization response issuer mechanism (RFC 9207) or the applicable OIDC response semantics.

Avoid putting sensitive business data in front-channel parameters. Signed/encrypted request objects and pushed authorization requests (PAR, RFC 9126) reduce front-channel tampering/disclosure and are required by stronger profiles such as FAPI 2.0 in their specified combinations.

## Token validation

Use a maintained library and configured issuer metadata. Pseudocode for an ID token:

<div class="language-text highlight">

<span id="__span-0-1">`# Pseudocode: library calls and provider requirements vary. `</span><span id="__span-0-2">`metadata = cached_metadata_for(configured_issuer) `</span><span id="__span-0-3">`key = select_allowed_key(metadata.jwks, token.header.kid) `</span><span id="__span-0-4">`reject unless header.algorithm is in the configured asymmetric allowlist `</span><span id="__span-0-5">`claims = verify_signature_and_decode(token, key) `</span><span id="__span-0-6">`require claims.iss == configured_issuer `</span><span id="__span-0-7">`require client_id is an allowed member of claims.aud `</span><span id="__span-0-8">`validate azp according to OIDC Core when multiple audiences are present `</span><span id="__span-0-9">`validate exp, iat, and nbf with narrow documented clock skew `</span><span id="__span-0-10">`require claims.nonce == one_time_session_nonce `</span>

</div>

The resource server performs a separate access-token validation for itself:

<div class="language-text highlight">

<span id="__span-1-1">`# Pseudocode: JWT access token profile or introspection contract must be explicit. `</span><span id="__span-1-2">`claims = validate_access_token(token, configured_authorization_server) `</span><span id="__span-1-3">`require api_resource_identifier is in claims.aud `</span><span id="__span-1-4">`require token is active and within time bounds `</span><span id="__span-1-5">`require scopes/authorization_details and subject/client are allowed for this action `</span><span id="__span-1-6">`enforce tenant/object/business authorization using server-side data `</span>

</div>

Reject `alg: none`, algorithms outside a narrow allowlist, tokens signed by the wrong key type, missing required claims, unknown critical headers, and keys from an unconfigured issuer. `kid` selects among already trusted issuer keys; it is not a URL to fetch. Fetch discovery/JWKS only from a configured HTTPS issuer with controlled redirect, DNS, egress, size, timeout, cache, and key-rotation behavior.

Key cache logic must handle legitimate rotation without accepting an arbitrary new issuer or refreshing on every attacker-controlled `kid`. Keep last known-good keys for a bounded overlap according to provider behavior, refresh with rate limits, and fail closed when no trusted key validates.

## Sender-constrained access tokens

Bearer tokens can be replayed by whoever steals them. For higher-risk APIs, evaluate:

- OAuth mutual TLS (RFC 8705), which binds tokens to a client certificate and requires end-to-end certificate identity/proxy handling and lifecycle operations;
- DPoP (RFC 9449), which binds tokens to a proof key and requires request proof, method/URI binding, nonce/replay controls, clock handling, and secure client key storage.

Sender constraint narrows replay but does not repair excessive authorization, client compromise, or a resource server that fails to validate the binding.

## Refresh tokens and sessions

RFC 9700 requires public-client refresh tokens to be sender-constrained or use refresh token rotation so replay is detected. Confidential clients also need secure storage, client authentication, narrow scope/audience, inactivity/absolute expiry according to risk, revocation, and reuse detection. On reuse, revoke the affected token family or take provider-defined containment action and investigate the client session.

Browser applications should prefer a backend-for-frontend or another architecture that avoids exposing durable tokens to browser JavaScript when it fits the product. Cookies need `Secure`, `HttpOnly`, appropriate `SameSite`, CSRF controls, rotation at authentication/privilege change, bounded lifetime, and logout/revocation behavior.

## Client authentication and secrets

Public clients cannot keep a static secret. Do not ship one in a mobile, desktop, or single-page application. Confidential clients should prefer stronger asymmetric methods (private-key JWT or mTLS when profile/provider support fits) over a widely copied shared secret, and must manage keys as production credentials.

Workload federation can remove stored cloud credentials but is separate from end-user OAuth. Validate issuer, audience, subject, and resulting authorization in both cases.

## Authorization design

Scopes express delegated capability but rarely encode complete object/tenant/business authorization. The API must evaluate token subject/client, scopes or authorization details, current account/tenant membership, resource ownership, consent/policy, and request context. Avoid stable broad refresh/access grants when a narrower resource indicator, incremental consent, or transaction-specific authorization is available.

Use provider pairwise subjects/issuer+subject as account keys according to the protocol. Do not link accounts only by unverified email. Validate claims such as `email_verified` only within the provider's documented semantics and business policy.

## Failure modes and operations

- Discovery/JWKS unavailable: use bounded valid cache; do not skip signature validation or accept another issuer.
- Clock skew: monitor time synchronization and use a narrow documented leeway; do not grant long arbitrary grace periods.
- Authorization callback mismatch: terminate the transaction, clear one-time state, and log a safe correlation event.
- Refresh reuse: revoke/contain the family, require reauthentication as appropriate, and investigate device/client telemetry.
- Provider compromise/misconfiguration: disable trust, revoke sessions/tokens where possible, freeze account linking, and use preplanned alternate authentication or recovery - not local password fallback created during the incident.

Log issuer, client ID, API audience, subject pseudonym/internal principal, scopes, authorization outcome, token/session identifier hash, reason code, and trace ID without logging raw tokens/codes/verifiers. Alert on issuer/audience/algorithm mismatch, refresh reuse, callback errors, abnormal consent/scope, discovery/key churn, and token use inconsistent with sender constraint.

## What I actually ran

The linked [OAuth/OIDC token-boundary lab](../labs/oauth-oidc/README.md) was run locally on 2026-07-23:

| Runtime | What I actually ran | Result |
|----|----|----|
| Node.js 24.12.0 | RS256 signature, issuer, string/array audience, expiration, `nbf`, tenant, scope, bounded key rotation, unknown `kid`, and exact web redirect matching | 14 of 14 positive and negative cases passed |
| Go 1.26.1 | RFC 7636 S256 vector and generated round trip, with wrong verifier, `plain` downgrade, method case, verifier length/syntax, and malformed-challenge rejection | 8 of 8 cases passed |

The Node code is a dependency-free executable model with injected time and in-memory trusted keys. The Go code demonstrates the PKCE verifier boundary and does not log verifiers or challenges. These checks back up the specific invariants above; they don't prove that a real OAuth/OIDC library, provider, discovery flow, JWKS transport, session store, deployment, or full authorization design would hold up in production.

## Validation checklist

Authorization code with S256 PKCE is used; implicit is absent.

Redirect URIs are exact and application return URLs are separately allowlisted.

State, nonce, expected issuer, and one-time transaction data are validated.

ID token audience is the client; access-token audience is the accepting API.

Signature algorithm, issuer, keys, time, and required claims are allowlisted.

Discovery/JWKS retrieval cannot become arbitrary SSRF.

Public-client refresh tokens rotate or are sender-constrained.

Scopes do not replace tenant/object/business authorization.

Token values are never logged and failure paths are observable.

PAR/FAPI/sender constraint is evaluated for high-value APIs.

## Limitations

Providers add profile-specific claims, logout, token exchange, device authorization, dynamic registration, and key-rotation behavior. Validate the provider's conformance and current documentation. Pseudocode is intentionally not a drop-in token validator. The executable model does not perform discovery, network JWKS retrieval, provider integration, library interoperability, session persistence, or deployment validation.

## References

- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0-18.html)
- [RFC 9449: Demonstrating Proof of Possession](https://www.rfc-editor.org/info/rfc9449/)
- [RFC 8705: OAuth mutual TLS](https://www.rfc-editor.org/info/rfc8705/)
- [RFC 9126: Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126.html)
- [RFC 9207: OAuth authorization server issuer identification](https://www.rfc-editor.org/rfc/rfc9207.html)
- [FAPI Working Group specifications](https://openid.net/wg/fapi/specifications/)
