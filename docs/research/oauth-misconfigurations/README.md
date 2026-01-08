# Common OAuth 2.0 Misconfigurations and Exploits

## Introduction

OAuth 2.0 is the dominant authorization framework for web and mobile applications, but its flexibility and complexity create significant attack surface. According to security research, OAuth misconfigurations remain one of the top web hacking techniques, with vulnerabilities repeatedly discovered in major platforms including Microsoft, GitHub, Facebook, and Google.

This tutorial documents common OAuth 2.0 vulnerabilities, attack techniques, and defensive measures. The focus is on practical understanding for security assessments and secure implementation.

**Important Distinction**: OAuth 2.0 is an *authorization* framework, not an authentication protocol. It grants limited access to resources ("Can this app post on my behalf?") rather than verifying identity ("Who are you?"). OpenID Connect (OIDC) adds authentication on top of OAuth 2.0. Confusing these concepts leads to security issues.

---

## OAuth 2.0 Fundamentals

### Key Actors

| Actor | Role | Example |
|-------|------|---------|
| Resource Owner | User who owns the data | End user |
| Client | Application requesting access | Third-party app |
| Authorization Server | Issues tokens after authentication | Google, Azure AD |
| Resource Server | Hosts protected resources | Google Drive API |

### Grant Types

| Grant Type | Use Case | Security Level |
|------------|----------|----------------|
| Authorization Code | Server-side apps | Highest (with PKCE) |
| Authorization Code + PKCE | SPAs, mobile apps | High |
| Client Credentials | Server-to-server | High (machine identity) |
| Implicit (Deprecated) | Legacy SPAs | Low (avoid) |
| Resource Owner Password | Legacy only | Low (avoid) |
| Device Code | Smart TVs, CLI tools | Medium |

### Authorization Code Flow

```
┌──────────┐                              ┌───────────────────┐
│          │  (1) Authorization Request   │                   │
│          │ ─────────────────────────────►                   │
│          │     + client_id              │                   │
│          │     + redirect_uri           │                   │
│  User    │     + scope                  │  Authorization    │
│  Agent   │     + state                  │  Server           │
│          │     + code_challenge (PKCE)  │                   │
│          │                              │                   │
│          │  (2) Authorization Code      │                   │
│          │ ◄─────────────────────────────                   │
│          │     via redirect_uri         │                   │
└────┬─────┘                              └───────────────────┘
     │                                              ▲
     │ (3) Code + code_verifier                     │
     ▼                                              │
┌──────────┐                                        │
│          │  (4) Token Request                     │
│  Client  │ ───────────────────────────────────────┘
│  App     │     + code
│          │     + client_secret (confidential)
│          │     + code_verifier (PKCE)
│          │
│          │  (5) Access Token + Refresh Token
│          │ ◄───────────────────────────────────────
└──────────┘
```

---

## Vulnerability Categories

### Category 1: Redirect URI Manipulation

**Risk Level**: Critical

The `redirect_uri` parameter controls where authorization codes and tokens are sent. Insufficient validation is the most common OAuth vulnerability.

#### Attack Scenarios

**1. Open Redirect Chain**
```
# Legitimate redirect_uri
redirect_uri=https://app.example.com/callback

# Attacker exploits open redirect on the same domain
redirect_uri=https://app.example.com/redirect?url=https://attacker.com
```

**2. Path Traversal**
```
# Registered: https://app.example.com/oauth/callback
# Attacker crafts:
redirect_uri=https://app.example.com/oauth/callback/../../../attacker-page
```

**3. Subdomain Takeover**
```
# If abandoned.example.com is unclaimed
redirect_uri=https://abandoned.example.com/callback
```

**4. Fragment/Query Confusion**
```
# Append attacker URL as fragment
redirect_uri=https://app.example.com/callback#https://attacker.com
```

**5. URL Parser Inconsistencies**
```
# Parser confusion attacks
redirect_uri=https://app.example.com@attacker.com
redirect_uri=https://app.example.com%40attacker.com
redirect_uri=https://attacker.com\@app.example.com
```

#### Mitigation

```python
# INSECURE: Partial matching
def validate_redirect_uri_insecure(uri, registered_uris):
    for registered in registered_uris:
        if registered in uri:  # Vulnerable!
            return True
    return False

# SECURE: Exact matching
def validate_redirect_uri_secure(uri, registered_uris):
    parsed = urlparse(uri)
    # Reconstruct to normalize
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return normalized in registered_uris
```

**Best Practices:**
- Require exact string matching for redirect URIs
- Prohibit wildcards in redirect URI registration
- Validate redirect_uri at both authorization and token endpoints
- Use allowlists, never blocklists
- Reject URIs with fragments, path traversal, or unusual encodings

---

### Category 2: Missing or Weak State Parameter

**Risk Level**: High

The `state` parameter prevents Cross-Site Request Forgery (CSRF) attacks against the OAuth flow.

#### Attack: OAuth CSRF / Authorization Code Injection

```
1. Attacker initiates OAuth flow, gets authorization code
2. Attacker drops the request before code is used
3. Attacker crafts malicious page with their authorization code
4. Victim visits malicious page
5. Victim's browser completes OAuth flow with attacker's code
6. Attacker's account is linked to victim's session
```

**Attack HTML:**
```html
<!-- Attacker hosts this page -->
<iframe src="https://target-app.com/oauth/callback?code=ATTACKER_CODE" 
        style="display:none"></iframe>
```

#### Mitigation

```javascript
// Generate cryptographically secure state
function generateState() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const state = btoa(String.fromCharCode.apply(null, array));
    
    // Store in session
    sessionStorage.setItem('oauth_state', state);
    return state;
}

// Validate state on callback
function validateState(returnedState) {
    const storedState = sessionStorage.getItem('oauth_state');
    sessionStorage.removeItem('oauth_state');
    
    if (!storedState || !returnedState) {
        throw new Error('Missing state parameter');
    }
    
    if (storedState !== returnedState) {
        throw new Error('State mismatch - possible CSRF attack');
    }
    
    return true;
}
```

**Best Practices:**
- Always use state parameter
- Generate cryptographically random values (min 128 bits)
- Bind state to user session
- Validate state before processing authorization code
- Use state for CSRF protection OR rely on PKCE (not neither)

---

### Category 3: Missing PKCE Implementation

**Risk Level**: High

PKCE (Proof Key for Code Exchange) prevents authorization code interception attacks.

#### Attack: Authorization Code Interception

```
Mobile App Flow Without PKCE:
1. Legitimate app requests authorization
2. User authenticates and approves
3. Authorization server sends code to custom URI scheme (myapp://)
4. Malicious app registered for same scheme intercepts code
5. Malicious app exchanges code for tokens
```

#### PKCE Flow

```
Client                          Authorization Server
  │                                      │
  │ (1) Generate code_verifier           │
  │     (random 43-128 chars)            │
  │                                      │
  │ (2) Compute code_challenge           │
  │     = BASE64URL(SHA256(verifier))    │
  │                                      │
  │ (3) Authorization Request            │
  │     + code_challenge                 │
  │     + code_challenge_method=S256     │
  │ ────────────────────────────────────►│
  │                                      │
  │ (4) Authorization Code               │
  │ ◄────────────────────────────────────│
  │                                      │
  │ (5) Token Request                    │
  │     + code                           │
  │     + code_verifier                  │
  │ ────────────────────────────────────►│
  │                                      │
  │     Server verifies:                 │
  │     SHA256(verifier) == challenge    │
  │                                      │
  │ (6) Access Token                     │
  │ ◄────────────────────────────────────│
```

#### Implementation

```javascript
// Generate PKCE challenge
async function generatePKCE() {
    // Generate random verifier (43-128 characters)
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const verifier = base64UrlEncode(array);
    
    // Generate challenge (SHA-256 hash of verifier)
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    const challenge = base64UrlEncode(new Uint8Array(hash));
    
    return { verifier, challenge };
}

function base64UrlEncode(buffer) {
    return btoa(String.fromCharCode.apply(null, buffer))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}
```

**Best Practices:**
- Use PKCE for ALL clients (public and confidential)
- Always use S256 method (never plain)
- Store code_verifier securely (memory only, not localStorage)
- Authorization servers should require PKCE for public clients

---

### Category 4: Implicit Flow Vulnerabilities

**Risk Level**: Critical (if still used)

The implicit flow sends tokens directly in URL fragments, exposing them to interception.

#### Problems with Implicit Flow

```
# Token exposed in URL fragment
https://app.example.com/callback#access_token=eyJ...&token_type=bearer

Vulnerabilities:
1. Token visible in browser history
2. Token exposed to JavaScript on page (XSS risk)
3. Token leaked via Referer header
4. No refresh tokens (forced re-authentication)
5. No token binding verification
```

#### Mitigation

**Recommendation**: Migrate to Authorization Code + PKCE

```javascript
// AVOID: Implicit flow
const implicitUrl = `${authServer}/authorize?
    response_type=token&
    client_id=${clientId}&
    redirect_uri=${redirectUri}`;

// USE: Authorization Code + PKCE
const pkceUrl = `${authServer}/authorize?
    response_type=code&
    client_id=${clientId}&
    redirect_uri=${redirectUri}&
    code_challenge=${challenge}&
    code_challenge_method=S256`;
```

---

### Category 5: Token Storage and Handling

**Risk Level**: High

Improper token storage exposes access tokens to theft.

#### Insecure Storage Patterns

```javascript
// INSECURE: localStorage (XSS vulnerable)
localStorage.setItem('access_token', token);

// INSECURE: sessionStorage (XSS vulnerable)  
sessionStorage.setItem('access_token', token);

// INSECURE: Global variable
window.accessToken = token;

// INSECURE: URL parameter
window.location = `/dashboard?token=${token}`;
```

#### Secure Storage Patterns

```javascript
// SECURE: HTTP-only cookies (for same-origin)
// Set by server:
// Set-Cookie: access_token=xxx; HttpOnly; Secure; SameSite=Strict

// SECURE: In-memory only (for SPAs)
class TokenManager {
    #accessToken = null;
    #refreshToken = null;
    
    setTokens(access, refresh) {
        this.#accessToken = access;
        this.#refreshToken = refresh;
    }
    
    getAccessToken() {
        return this.#accessToken;
    }
    
    clear() {
        this.#accessToken = null;
        this.#refreshToken = null;
    }
}

// SECURE: Backend-for-Frontend (BFF) pattern
// Tokens stored server-side, session cookie for client
```

**Best Practices:**
- Never store tokens in localStorage or sessionStorage
- Use HTTP-only, Secure, SameSite cookies
- Implement token rotation for refresh tokens
- Use short-lived access tokens (5-15 minutes)
- Consider BFF pattern for SPAs

---

### Category 6: Insufficient Scope Validation

**Risk Level**: Medium-High

Requesting excessive scopes or failing to validate scope changes.

#### Attack: Scope Manipulation

```
# Application requests minimal scope
scope=read_profile

# Attacker modifies request
scope=read_profile write_profile admin

# If server grants broader scope without user re-consent...
```

#### Attack: Scope Downgrade

```
# Attacker requests token with full scope
# Later uses token for operations beyond user's intended consent
```

#### Mitigation

```python
# Server-side scope validation
def validate_scopes(requested_scopes, client_allowed_scopes, user_consented_scopes):
    requested = set(requested_scopes.split())
    allowed = set(client_allowed_scopes)
    consented = set(user_consented_scopes)
    
    # Scope must be subset of what client is allowed
    if not requested.issubset(allowed):
        raise InvalidScopeError("Client not authorized for requested scopes")
    
    # Scope must be subset of what user consented to
    if not requested.issubset(consented):
        # Require new consent
        return require_consent(requested - consented)
    
    return requested

# Include granted scope in token response
{
    "access_token": "...",
    "token_type": "Bearer",
    "scope": "read_profile"  # Actual granted scope
}
```

**Best Practices:**
- Always return granted scope in token response
- Validate scope at resource server, not just at issuance
- Implement principle of least privilege
- Re-consent for scope upgrades
- Log scope changes for audit

---

### Category 7: Token Validation Failures

**Risk Level**: Critical

Improper JWT validation allows token forgery or misuse.

#### Common JWT Vulnerabilities

**1. Algorithm None Attack**
```json
// Attacker modifies header
{
    "alg": "none",
    "typ": "JWT"
}
// Signs with empty signature
// Vulnerable libraries accept as valid
```

**2. Algorithm Confusion (RS256 to HS256)**
```python
# Server expects RS256 (asymmetric)
# Attacker sends HS256 token signed with public key as secret
# Vulnerable library verifies signature using public key
```

**3. Missing Signature Verification**
```python
# INSECURE: Only decoding, not verifying
payload = jwt.decode(token, options={"verify_signature": False})
```

**4. Missing Claims Validation**
```python
# INSECURE: Not checking expiration, issuer, audience
payload = jwt.decode(token, secret, algorithms=["HS256"])
# Missing: exp, iss, aud validation
```

#### Secure JWT Validation

```python
import jwt
from datetime import datetime, timezone

def validate_token(token, expected_audience, expected_issuer, public_key):
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],  # Explicit algorithm whitelist
            audience=expected_audience,
            issuer=expected_issuer,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
                "require": ["exp", "iat", "iss", "aud", "sub"]
            }
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Token expired")
    except jwt.InvalidAudienceError:
        raise AuthError("Invalid audience")
    except jwt.InvalidIssuerError:
        raise AuthError("Invalid issuer")
    except jwt.InvalidTokenError as e:
        raise AuthError(f"Invalid token: {e}")
```

**Best Practices:**
- Always verify signatures
- Whitelist allowed algorithms (never accept from token)
- Validate all claims: exp, iat, nbf, iss, aud, sub
- Use asymmetric algorithms (RS256, ES256) for distributed systems
- Reject tokens with "none" algorithm
- Implement token revocation (jti claim + blacklist)

---

### Category 8: Device Code Flow Attacks

**Risk Level**: High (increasingly exploited)

The device code flow (RFC 8628) is increasingly targeted by attackers.

#### Attack: Social Engineering + Device Code

```
Attack Flow:
1. Attacker initiates device code flow, gets user_code
2. Attacker calls victim (voice phishing)
3. "This is IT support, please go to microsoft.com/devicelogin"
4. "Enter this code: ABCD-1234 to verify your identity"
5. Victim enters code, authorizes attacker's session
6. Attacker receives access token for victim's account
```

This attack bypasses MFA because the victim completes legitimate authentication.

#### Mitigation

```yaml
# Azure AD Conditional Access Policy
# Block or require additional controls for device code flow

Policy: "Restrict Device Code Flow"
Conditions:
  - Client apps: Other clients (device code flow)
  - Users: All users
Grant:
  - Block access
  # OR require additional verification:
  - Require approved client app
  - Require compliant device
```

**Best Practices:**
- Disable device code flow if not needed
- Apply Conditional Access policies to device code
- Train users about voice phishing targeting device codes
- Monitor for anomalous device code usage
- Consider allowlisting specific applications

---

### Category 9: Client Impersonation

**Risk Level**: High

Attackers create malicious OAuth applications that impersonate legitimate ones.

#### Attack: Malicious App Registration

```
1. Attacker registers app named "Microsoft Security Tool"
2. Attacker crafts phishing email with OAuth consent link
3. Victim clicks link, sees familiar-looking consent screen
4. Victim grants permissions to malicious app
5. Attacker has persistent access to victim's data
```

#### Mitigation

**For Authorization Servers:**
```yaml
# App registration controls
- Require admin consent for high-privilege scopes
- Display verified publisher information
- Show application permissions clearly
- Implement app governance policies
```

**For Organizations (Azure AD example):**
```powershell
# Disable user consent for apps
Set-AzureADMSAuthorizationPolicy -DefaultUserRolePermissions @{
    "PermissionGrantPoliciesAssigned" = @()
}

# Or restrict to verified publishers
Set-AzureADMSAuthorizationPolicy -DefaultUserRolePermissions @{
    "PermissionGrantPoliciesAssigned" = @(
        "managePermissionGrantsForSelf.microsoft-user-default-low-verified-publisher"
    )
}
```

**Best Practices:**
- Require admin approval for sensitive permissions
- Display publisher verification status
- Implement consent policies
- Regular review of granted permissions
- Alert on new OAuth grants

---

## Real-World Vulnerability Examples

### Example 1: Facebook OAuth Flaw (CVE-2020)

**Vulnerability**: Redirect URI validation bypass
**Impact**: Account takeover
**Details**: Attackers could chain an open redirect with OAuth to steal access tokens

### Example 2: Microsoft + GitHub OAuth Vulnerabilities (2021)

**Vulnerability**: Redirect URI manipulation via path traversal
**Impact**: Authorization code theft
**Details**: Insufficient validation allowed redirection to attacker-controlled pages

### Example 3: ShinyHunters Campaign (2024-2025)

**Vulnerability**: Device code flow abuse
**Impact**: Data breaches at major companies
**Details**: Voice phishing campaigns tricked users into authorizing malicious device codes

### Example 4: Badoo SAML/OAuth Hijack

**Vulnerability**: Improper state validation
**Impact**: Account takeover via social login
**Details**: Missing CSRF protection in OAuth flow allowed account linking attacks

---

## Security Testing Checklist

### Authorization Endpoint

- [ ] Test redirect_uri with various bypass techniques
- [ ] Verify state parameter is required and validated
- [ ] Check for PKCE enforcement
- [ ] Test response_type manipulation (code to token)
- [ ] Verify scope parameter handling
- [ ] Test for open redirect chains

### Token Endpoint

- [ ] Verify client authentication requirements
- [ ] Test code_verifier validation (PKCE)
- [ ] Check redirect_uri validation at token endpoint
- [ ] Test authorization code replay prevention
- [ ] Verify client_secret handling

### Token Validation

- [ ] Test JWT algorithm confusion attacks
- [ ] Verify signature validation
- [ ] Test claims validation (exp, iss, aud)
- [ ] Check token revocation
- [ ] Test for token leakage in logs

### Client Application

- [ ] Review token storage mechanisms
- [ ] Check for token exposure in URLs/logs
- [ ] Verify secure transmission (HTTPS only)
- [ ] Test for XSS that could steal tokens

---

## Implementation Recommendations

### For Authorization Servers

1. **Strict redirect_uri validation**
   - Exact string matching only
   - No wildcards or partial matches
   - Validate at both endpoints

2. **Require PKCE for all public clients**
   - Mandate S256 challenge method
   - Reject plain method

3. **Enforce state parameter**
   - Require for CSRF protection
   - Bind to session

4. **Short-lived tokens**
   - Access tokens: 5-15 minutes
   - Refresh tokens: sliding expiration with rotation

5. **Comprehensive logging**
   - Log all authorization events
   - Alert on anomalies

### For Client Applications

1. **Use Authorization Code + PKCE**
   - Never use implicit flow
   - Generate high-entropy verifiers

2. **Secure token storage**
   - HTTP-only cookies or in-memory
   - Never localStorage

3. **Validate all server responses**
   - Check state parameter
   - Verify token claims

4. **Minimal scope requests**
   - Request only needed permissions
   - Prefer incremental authorization

5. **Handle errors securely**
   - Don't expose tokens in errors
   - Log for debugging without sensitive data

---

## Tools for OAuth Security Testing

| Tool | Purpose |
|------|---------|
| Burp Suite | Intercept and modify OAuth flows |
| OWASP ZAP | Automated OAuth scanning |
| OAuch | OAuth compliance testing |
| KOAuth | Automated OAuth vulnerability testing |
| jwt.io | JWT debugging |
| jwt_tool | JWT attack automation |

---

## References

- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8628 - Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [PortSwigger OAuth Vulnerabilities](https://portswigger.net/web-security/oauth)
- [Auth0 State Parameter Guide](https://auth0.com/docs/secure/attack-protection/state-parameters)
