# OAuth/OIDC Misconfiguration Mitigations

This document outlines comprehensive mitigation strategies for each OAuth 2.0 / OpenID Connect misconfiguration scenario described in **attack-scenarios.md**. For each real-world case study, we provide targeted defenses — including secure configuration examples, code snippets, and monitoring guidance — to harden **Authorization Servers (AS)**, **Client applications**, and **Resource Servers (RS)** against similar vulnerabilities.

An Appendix of fictional demo scenarios is included to illustrate additional pitfalls and their mitigations.

All recommendations reflect current best practices as of **January 2026** (aligned with **RFC 6749**, **RFC 7636 (PKCE)**, **RFC 9700 (OAuth 2.0 Security BCP)**, and **OpenID Connect Core**).

---

## Mitigation for Example 1: Facebook OAuth Redirect URI Bypass (CVE-2020)

### Scenario Summary
Facebook’s OAuth implementation had a redirect URI validation bypass. Attackers chained an open redirect on a Facebook domain to the OAuth flow, causing the Authorization Server to send tokens to an attacker-controlled URL. This misconfiguration allowed account takeover by stealing OAuth access tokens.

### Mitigation Strategies

#### Authorization Server – Strict Redirect URI Allowlist
Use exact string matching for redirect URIs and prohibit wildcards or partial matches. Each OAuth client should register explicit redirect URI(s); the server must redirect **only** to these exact addresses.

Example: If `https://app.example.com/callback` is registered, the server should reject:
- `https://app.example.com/redirect?url=https://attacker.com` (open redirect abuse)
- Anything not **exactly** `https://app.example.com/callback`

Implement validation at both **authorization** and **token** endpoints to ensure the `redirect_uri` in the token request matches the one used in the authorization request.

**Secure configuration snippet (AS side):**
```json
{
  "client_id": "myapp",
  "redirect_uris": [
    "https://app.example.com/oauth/callback"
  ],
  "redirect_uri_wildcards": false,
  "pkce_required": true
}
````

**Secure redirect URI validation (exact match & normalization):**

```python
from urllib.parse import urlparse

# registered_uris = {"https://app.example.com/oauth/callback"}

parsed = urlparse(input_uri)
normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

if normalized not in registered_uris:
    raise OAuthError("Invalid redirect_uri")
```

**Rationale**
Exact matching + normalization prevents attackers from exploiting open redirects, path tricks, or parser quirks to sneak untrusted URLs past validation. The configuration disables wildcards (aligned with OAuth BCP expectations). Enforcing `"pkce_required": true` provides defense-in-depth against code interception if redirect checks ever fail.

> Per RFC 3986 & OAuth 2.1 direction, fragments (`#...`) in redirect URIs should be rejected and not considered in matching.

#### Client Application – Eliminate Open Redirects

The Facebook flaw relied on an open redirect on a trusted domain. Clients must audit and fix open redirects on any domain used for OAuth redirects.

If redirect-like behavior is needed:

* validate targets against an allowlist of internal paths
* do **not** blindly redirect to user-controlled `?url=` values

By removing open redirects, even if an OAuth server trusts the domain, attackers can’t bounce tokens out to an external site.

#### Defense-in-Depth – Require PKCE

Even for confidential clients, PKCE ensures an intercepted authorization code cannot be exchanged without the `code_verifier`. If PKCE is enforced by the AS and always used by the client, a stolen code redirected to an attacker is useless without the verifier.

> RFC 9700 recommends PKCE broadly, and modern profiles increasingly require it.

#### Monitoring & Detection

* Enable detailed logging for OAuth authorization requests.
* Log all failed or mismatched redirect URI attempts (include offending `redirect_uri`, client_id).
* Alert on repeated suspicious patterns (e.g., unknown domains or encoded redirects).
* Monitor for successful auth where redirect is allowlisted but no subsequent client activity occurs (possible bounce).
* On the client side, add telemetry to detect callback pages loaded outside expected app flows.

---

## Mitigation for Example 2: Microsoft & GitHub OAuth Path Traversal (2021)

### Scenario Summary

OAuth implementations at Microsoft and GitHub in 2021 had redirect URI manipulation via path traversal. Validation logic allowed attackers to append `../` segments or similar encodings to reach an attacker-controlled page, resulting in authorization code theft.

### Mitigation Strategies

#### Authorization Server – Normalize and Validate Redirects

The Authorization Server must properly normalize and strictly compare redirect URIs. Detect and reject path traversal (`..`) and encoding tricks.

Avoid naive substring/prefix matching (e.g., “startsWith trusted domain”) — it is insecure.

```python
from urllib.parse import urlparse

# Insecure approach (vulnerable to traversal)
def validate_redirect_insecure(uri, allowed_uris):
    return any(allowed in uri for allowed in allowed_uris)  # 🚫 insecure

# Secure approach (normalize then exact match)
def validate_redirect_secure(uri, allowed_uris):
    parsed = urlparse(uri)
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return normalized in allowed_uris  # ✅ exact only
```

In addition:

* reject redirect URIs containing URL-encoded characters often used for abuse (e.g., `%0d`, `%5c`, `%2e`)
* reject any occurrence of `..` **after decoding**
* reject multiple separators or oddities (`@`, double `//`, mixed slashes) that may confuse parsers

#### Disable Wildcards and Prefixes

Disallow wildcard domains or path prefixes in redirect URI registration.

Instead of:

* `https://*.example.com/*`

Require explicit entries like:

* `https://app.example.com/callback`
* `https://portal.example.com/callback`

This eliminates entire classes of redirect attacks (subdomain takeover chaining, open redirects, traversal ambiguity).

#### Token Endpoint Validation

The token exchange step should enforce that `redirect_uri` in the token request exactly matches the `redirect_uri` used in the authorization request (RFC 6749 §4.1.3). Log any mismatch as a likely attack attempt.

#### Monitoring & Response

* Detect changes in redirect usage: if a client normally uses one path and suddenly a variant appears, alert.
* Track failed exchanges due to redirect mismatches (`invalid_grant`) as potential interception attempts.
* Alert on authorization requests containing suspicious substrings like `%2e` or unusual separators.

---

## Mitigation for Example 3: ShinyHunters Device Code Phishing (2024–2025)

### Scenario Summary

The ShinyHunters campaign abused the OAuth Device Code flow (RFC 8628) via voice phishing. Attackers tricked users into entering a code at the legitimate Microsoft device login portal, linking the attacker’s device to the victim’s account and obtaining tokens (often bypassing MFA because the victim completed the flow).

### Mitigation Strategies

#### Authorization Server – Restrict or Harden Device Code Flow

If Device Authorization Grant is not required, disable it for tenants/clients that don’t need it.

If required (TV/IoT use cases), constrain it:

**Policy controls**

* Block device code flow for most users/apps, allow only for specific device clients
* Require higher assurance controls for device code sign-in (Conditional Access / Device Trust / BeyondCorp-like policy)

Example policy sketch:

```yaml
# Example: Conditional Access to restrict device code usage
Conditions:
  ClientApps: ["Device Code Flow"]
  Users: AllUsers
Controls:
  Grant: Block  # or require MFA/known device for device code logins
```

**Short expiry & rate limiting**

* Short device code lifetime (e.g., 5 minutes)
* Strict polling interval
* Rate limit attempts

**User warnings & notifications**

* Prominent warning: “Do not enter codes provided by unknown callers.”
* Email/push notifications when device code is activated (include location/device)
* If possible: explicit user confirmation (“You are about to grant access to device X”)

#### Client/User Side – Education and Verification

* Train users: “IT will never ask for a device code.”
* Helpdesk training: treat device codes like OTPs.
* Ensure consent UI clearly shows the requesting app/device so users can detect mismatches.

#### Resource Server – Anomaly Detection

Even though the token is “legitimate,” monitor for:

* impossible travel / unusual geo or ASN
* high-risk actions immediately following device grant
* spikes in device code grant usage
* repeated device code failures (testing attempts)

Correlate AS grant logs with RS access logs to detect attacker device usage.

#### Incident Response

* Provide rapid revocation for tokens issued via device grants (tie grant to refresh token/session).
* Allow revoking the device session without impacting all user sessions.

---

## Mitigation for Example 4: Badoo OAuth CSRF (Improper State Validation)

### Scenario Summary

A flaw in Badoo’s SAML/OAuth integration allowed account takeover via social login due to missing CSRF protection (`state` missing or not validated). Attackers could inject/reuse an authorization response to link their account to a victim session because the client didn’t verify `state` (or SAML `RelayState`) to bind response to request.

### Mitigation Strategies

#### Client Application – Enforce State Parameter Usage

All OAuth/OIDC clients **must** generate and validate `state` for every authorization request:

* cryptographically secure random value (e.g., 128-bit+)
* unique per request
* bound to user session (server-side store or session-bound cookie/storage)
* single-use: invalidate after verification

**Example implementation (browser-based flow):**

```js
// Generate a random state and store it (e.g., in sessionStorage)
function createState() {
  const array = new Uint8Array(16); // 128-bit
  crypto.getRandomValues(array);

  const state = [...array]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  sessionStorage.setItem("oauth_state", state);
  return state;
}

// Later, validate the returned state
const expectedState = sessionStorage.getItem("oauth_state");
sessionStorage.removeItem("oauth_state");

if (!expectedState || returnedState !== expectedState) {
  throw new Error("OAuth state mismatch - possible CSRF!");
}
```

For OpenID Connect authentication:

* also generate a `nonce`
* validate `nonce` in the ID token to prevent replay
* treat nonce like state (unique per login attempt)

#### Authorization Server – Enforce or Encourage State

AS can improve security by:

* rejecting or warning on requests lacking `state` (especially for browser-based clients)
* ensuring examples/docs always include `state`
* applying similar rigor to SAML `RelayState` if applicable

#### Session Binding for Account Linking

For account linking flows, bind the OAuth response to the initiating session:

* include a session identifier or linking intent token inside state
* encrypt or HMAC-sign it to prevent tampering

This prevents “attacker response attached to victim session.”

#### Monitoring & Alerts

* Log and alert on missing `state` or state mismatches.
* Capture metadata (IP, UA, client_id) and abort safely.
* Monitor for unusual account linking events and many-to-one social linking.
* Consider CSP / frame protections to reduce hidden iframe tactics.

#### Secure Implementation

Use well-tested OAuth/OIDC libraries that:

* handle `state` and `nonce`
* enforce issuer/audience/token validation
* reduce custom glue code

---

# Appendix: Fictional OAuth/OIDC Misconfiguration Scenarios (Demo)

> The following scenarios are fictional examples created to illustrate additional OAuth/OIDC misconfigurations and their mitigations. They are not real incidents, but they reflect common pitfalls.

---

## Scenario A (Fictional): Legacy Implicit Flow Leads to Token Leak

### The Scenario

A SPA uses implicit flow and receives an access token in `#access_token=...`. It stores tokens in `localStorage`. An XSS vulnerability allows an attacker to read localStorage and exfiltrate the token. In some cases, tokens leak into logs and referrers due to poor handling.

### Mitigations

#### Migrate Away from Implicit Flow

Implicit flow is deprecated for SPAs. Switch to Authorization Code + PKCE.

```text
# Implicit (old, insecure):
https://auth.example.com/authorize?
  response_type=token&
  client_id=SPACLIENT123&
  redirect_uri=https://app.example.com/callback&
  scope=read_profile

# Authorization Code + PKCE (modern, secure):
https://auth.example.com/authorize?
  response_type=code&
  client_id=SPACLIENT123&
  redirect_uri=https://app.example.com/callback&
  code_challenge=...&
  code_challenge_method=S256&
  scope=read_profile
```

#### Secure Token Storage in SPA

Avoid tokens in JS-accessible persistent storage:

* Prefer `HttpOnly` secure cookies (if same-origin backend)
* Otherwise store in memory only (non-persistent)
* Best: BFF pattern — SPA never sees tokens; server holds them

#### Prevent XSS + Monitor

* CSP, output encoding, audit third-party scripts
* Monitor for JWT-like patterns in URLs/logs and for anomalous API usage

#### Short Token Lifetimes & Refresh Rotation

* Access tokens: short-lived (e.g., 10 minutes)
* Refresh tokens: rotate; revoke on reuse signals

---

## Scenario B (Fictional): Insecure Mobile Token Storage and Reuse

### The Scenario

A mobile app logs tokens for debugging and stores refresh tokens in plaintext preferences. Malware or stolen backups reveal tokens. No refresh rotation → long-lived compromise.

### Mitigations

#### Secure Token Storage (Mobile)

* iOS: Keychain
* Android: Keystore / EncryptedSharedPreferences
* Never log tokens; scrub sensitive fields; disable debug logs in prod

#### Implement Refresh Token Rotation

Rotate refresh tokens on each use; detect reuse and revoke. Use provider features where available.

#### Expire and Scope Minimally

* 5–10 minute access tokens
* minimal scopes
* consider sender-constrained tokens (DPoP RFC 9449, mTLS RFC 8705) where feasible

#### Monitoring & Response

* Log refresh usage with device/app IDs
* Alert on location/device anomalies
* Provide device/session inventory and revocation UI
* Have playbooks for mass revocation if compromise patterns appear

---

## Scenario C (Fictional): Unverified JWT Signature Allows Forgery

### The Scenario

A Resource Server disables signature verification or accepts `alg: none`. Attacker forges JWTs and accesses protected endpoints without authenticating.

### Mitigations

#### Strict JWT Validation on Resource Server

* Verify signature (never accept `none`)
* Whitelist algorithms (e.g., only RS256/ES256)
* Prevent algorithm confusion (reject HS256 if expecting RS256)
* Validate claims: `exp`, `nbf`, `iss`, `aud`, `sub` (and `azp` where relevant)

```python
import jwt

def validate_jwt(token, pubkey):
    EXPECTED_ISS = "https://auth.example.com"
    EXPECTED_AUD = "my-api"

    try:
        payload = jwt.decode(
            token,
            pubkey,
            algorithms=["RS256"],
            issuer=EXPECTED_ISS,
            audience=EXPECTED_AUD,
            options={
                "require": ["exp", "iss", "aud", "sub"],
                "verify_exp": True,
                "verify_signature": True
            }
        )
    except Exception as e:
        raise Unauthorized(f"Invalid token: {e}")

    return payload
```

#### Authorization Server – Issue Tokens Securely

* Strong alg (RS256/ES256)
* publish JWKS + `kid`
* rotate keys
* server dictates allowed algorithms (client cannot choose)

#### Monitoring & Auditing

* log validation failures (without dumping tokens)
* alert on `alg:none` attempts, unexpected issuers/audiences
* detect simultaneous usage of the same `sub` from different regions

#### Defense-in-Depth

* token introspection (RFC 7662) for critical APIs
* sender-constrained tokens (mTLS / DPoP)

---

## Scenario D (Fictional): Confused Resource – Missing Audience Validation

### The Scenario

FilesAPI forgets to validate `aud`. Attacker uses a valid token for MessagesAPI to call FilesAPI, gaining unintended access.

### Mitigations

#### Resource Server – Verify Audience and Scope

Enforce:

```text
if token.aud != "files-api": reject
```

Also validate scopes/permissions for the resource.

#### Reduce Cross-Resource Confusion

* Use resource indicators (RFC 8707)
* Consider partitioning issuers/keys per resource group for stronger separation

#### Monitoring & Testing

* test “token for A used on B” in security testing
* alert when `aud` does not match service expectation

---

## Scenario E (Fictional): OAuth Consent Phishing via Malicious Application

### The Scenario

Attacker registers a lookalike OAuth app, requests powerful scopes, and phishes users into granting consent. No passwords stolen; attacker obtains tokens (often refresh tokens) via consent grant phishing.

### Mitigations

#### Authorization Server – Tighten Consent Policies

* Require admin consent for high-risk scopes
* Disable default user consent for untrusted apps
* Allow user consent only for low-impact scopes and verified publishers
* Implement app governance (approval workflows / whitelisting)

Example Azure AD-style approach (illustrative):

```powershell
# Disable user consent broadly
Set-AzureADMSAuthorizationPolicy -DefaultUserRolePermissions @{
  "PermissionGrantPoliciesAssigned" = @()
}

# Or allow only low-impact permissions from verified publishers
Set-AzureADMSAuthorizationPolicy -DefaultUserRolePermissions @{
  "PermissionGrantPoliciesAssigned" = @("managePermissionGrantsForSelf.microsoft-user-default-low-verified-publisher")
}
```

#### Organizational Policies & Education

* train users: unsolicited consent prompts are phishing
* run simulations including consent scenarios
* teach users to check publisher verification and requested scopes

#### Monitoring & Alerting

* alert on new app consents granting high-privilege scopes
* inventory service principals / OAuth apps and review deltas
* detect unusual third-party app access patterns (bulk reads, cross-user access)
* consider continuous access evaluation and time-bounded consent

---

# References

Key standards and guides influencing these mitigations include:

* RFC 6749 (OAuth 2.0) and extensions
* RFC 7636 (PKCE)
* RFC 8628 (Device Code Flow)
* RFC 9700 (OAuth 2.0 Security Best Current Practice)
* OpenID Connect Core 1.0
* OWASP OAuth Security guidance and incident post-mortems

By implementing the above measures, organizations can significantly reduce the risk of OAuth/OIDC misconfigurations being exploited and achieve a secure-by-default posture for authentication and authorization flows.
