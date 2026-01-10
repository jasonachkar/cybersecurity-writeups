# OAuth & OpenID Connect Misconfigurations: Real-World Attack Scenarios

## 1) OAuth CSRF (Missing `state` Parameter)

### Description
The OAuth `state` parameter is a crucial CSRF token used to link client requests with provider responses. If an application omits `state` or fails to validate it, attackers can inject or replay OAuth responses. This often leads to **account linking CSRF** — where an attacker’s third-party account (e.g., a social login) gets bound to a victim’s account on the client application.

Essentially, the client can’t distinguish a malicious OAuth callback from a legitimate one without `state` acting as a nonce.

### Real-World Example
- **2012**: Researcher **Egor Homakov** demonstrated this flaw on multiple sites (e.g., SoundCloud, Pinterest). Many sites didn’t implement `state`, allowing an attacker to attach their OAuth login (e.g., Facebook account) to any victim’s account.
- This class of vulnerability continues to surface on modern web apps that support “Log in with X” without proper CSRF protection.

### Exploitation (Attack Steps)
An attacker:
1. Initiates an OAuth flow using their own third-party account, but does not complete the flow.
2. Obtains an authorization code (or token) issued for their social account and captures the redirect URL without letting it reach the client app.
3. Tricks a victim (already logged into the target application) into visiting a crafted URL (phishing link, image tag, etc.) that calls the client’s OAuth callback endpoint with the attacker’s code/token.
4. Because the client app isn’t checking `state`, it accepts the OAuth response and links the attacker’s OAuth identity to the victim’s session.

**Step summary:**
- Attacker obtains an OAuth authorization code tied to their own third-party account (e.g., Facebook/Google).
- Victim clicks malicious link that hits the vulnerable app’s OAuth callback URL with the attacker’s code.
- Client processes the code (since no valid `state` is required) and links the attacker’s OAuth provider account to the victim’s web account.
- Attacker can now log in as the victim via the social provider. The victim’s account is effectively compromised.

### Business/Security Impact
This misconfiguration enables **full account takeover** without needing the victim’s credentials. Attackers can access sensitive user data, perform actions as the victim, and potentially pivot to other linked services.

Because OAuth is often used for SSO, a successful exploit can be equivalent to stealing a password — but without a password change or 2FA prompt to tip off the user. In real cases, attackers could read private messages, initiate transactions, or change account settings.

Worse, these attacks often leave no obvious trace: to the application, the login via OAuth looks legitimate, and logs may just show an OAuth provider login by the account owner.

### Detection Opportunities
Look for anomalies in OAuth login flows, such as:
- Missing or static `state` values (empty, repeated, or absent).
- Unsolicited OAuth callbacks (callback received without a corresponding initiated login request).
- Multiple accounts linked to one OAuth ID (or unexpected many-to-one / one-to-many linking).
- Unusual timing or IP patterns: a victim session triggers an OAuth flow they didn’t initiate.

Security monitoring tools can flag OAuth responses that lack a matching request `state`. Implement server-side logs for OAuth initiation and callback and correlate them to detect callbacks processed without proper initiation.

### Mitigations
- **Always use and strictly validate `state`.**
- **Implement CSRF tokens:** Generate a cryptographically random `state` for each OAuth authorization request, store it (server-side or in an `HttpOnly` cookie tied to the user’s session), and verify it upon callback. If `state` is missing or doesn’t match, abort the flow.
- **Bind `state` to session:** Tie `state` to the user’s session or a specific login attempt, so an attacker’s valid code won’t be accepted without the correct `state`.
- **SameSite cookies:** Mark authentication session cookies as `SameSite=Lax` or `Strict`.
- **User confirmation (optional):** For sensitive apps, require re-confirmation when linking a new OAuth provider.
- **Library updates:** Use modern OAuth/OIDC client libraries that handle `state` correctly; beware of frameworks where `state` is optional or historically buggy.

---

## 2) Insecure Redirect URI Handling (Open Redirects & Validation Flaws)

### Description
OAuth relies on redirect URIs to send the user (and authorization code or token) back to the client application. Misconfigurations in redirect URI handling are common. Two major issues are:
1. **Insufficient validation of redirect URIs** by the IdP or client.
2. **Open redirect vulnerabilities** on the client’s domain.

If the IdP only checks part of the redirect URI (e.g., just the domain) or allows wildcards, an attacker can craft a rogue redirect URI that passes validation but ultimately points to a hostile destination. If the client has an open redirect, an attacker can chain this to bounce the OAuth response to themselves.

### Real-World Example
- **Booking.com (2023):** Researchers at Salt Security found Booking’s Facebook OAuth integration only whitelisted the subdomain for redirects (`https://account.booking.com`), not the full path. Attackers could specify any path under that domain, including one that triggered an open redirect.
- In Booking’s case, an OAuth endpoint on `account.booking.com` accepted a base64-encoded path parameter and redirected to it after login. By manipulating this, researchers could bounce an OAuth code through Booking.com to their own server, stealing the victim’s authorization code.

### Exploitation (Attack Steps)
Attackers combine lax redirect checks with open redirects:
1. **Craft OAuth URL:** Use a legitimate OAuth provider, but set `redirect_uri` to an attacker-controlled path on the client domain that eventually redirects to the attacker’s site.
2. **Lure victim:** Victim clicks link and authenticates at the provider as usual.
3. **Validation bypass:** Provider accepts redirect because it matches the trusted domain prefix.
4. **Open redirect trigger:** Provider redirects back with the code/token; the client path immediately redirects off-domain to the attacker, forwarding the code.
5. **Code/token theft:** Attacker’s server receives the OAuth secret (code or token).
6. **Session hijack:** Attacker uses the stolen code/token to impersonate the victim (especially effective for public clients or flows where code exchange is feasible).

### Business/Security Impact
Improper redirect URI handling can lead to **complete account compromise**. A stolen authorization code/token can grant full access to the victim’s account and data.

In Booking.com’s case, attackers could log into a victim’s Booking account, view personal details and trips, and access linked services. More broadly:
- OAuth trust is broken: tokens meant for `client.app` end up with the attacker.
- Potential “SSO supply chain” blast radius: a single open redirect on a trusted domain can be leveraged across many services.
- If the stolen token has broad scopes, damage may extend into the IdP’s APIs (e.g., Drive access if granted).

### Detection Opportunities
- Monitor suspicious `redirect_uri` patterns (encoded URLs, weird path segments, double-encoding).
- Watch for off-domain redirects immediately after OAuth completion.
- Investigate redirect chains (provider → your domain → another domain).
- Track frequent “redirect_uri mismatch” errors (probing signals).
- User reports of unexpected login prompts/consent screens.

### Mitigations
- **Strict redirect URI whitelisting:** Enforce *exact* redirect URI matching (including path). Avoid wildcards.
- **Eliminate open redirects:** Audit and fix open redirects on any path that could be used as an OAuth redirect handler; use allow-lists or signed redirect targets.
- **Prefer server-side flows:** Reduce exposure of secrets in front-channel navigation.
- **PKCE:** Use PKCE for public clients; it won’t stop leakage but blocks exchanging a stolen code without the verifier.
- **Logging:** Keep detailed logs of full redirect URIs used (for incident response).

---

## 3) Implicit Grant & Lack of PKCE (Token Exposure Vulnerabilities)

### Description
The OAuth **Implicit Grant** (now largely deprecated) returns an access token immediately in the redirect URI (typically in the URL fragment). Tokens in browser contexts are exposed to risks like browser history, referers (in some buggy cases), and malicious scripts.

Even with Authorization Code flow, **not using PKCE** in public clients can enable code interception: if an attacker intercepts the authorization code, they can exchange it for a token.

### Real-World Example (Pattern)
Older “Login with X” implementations often used implicit flow for SPAs/mobile apps. Over time, numerous incidents and testing labs have shown token leakage via:
- bad URL handling,
- third-party scripts,
- open redirects,
- XSS or malicious extensions reading `window.location.hash`.

Modern OAuth guidance (OAuth 2.1 direction) removes implicit flow due to these risks.

### Exploitation (Attack Steps)

#### Variant A: Token in URL Leakage
1. User completes implicit flow; redirected to `https://client-app.com/#access_token=XYZ...`.
2. If the app mishandles the token (e.g., puts it in query string, logs it, or exposes it through a bug), it can leak via referers/logs or be read by XSS/extensions.
3. Attacker uses token to call APIs and impersonate the user until token expiry.

#### Variant B: Code Interception (No PKCE)
1. User initiates code flow on mobile/SPA; provider returns `?code=ABC123`.
2. Attacker intercepts the code (malicious app hijacking URI scheme, malware, etc.).
3. Attacker exchanges the code for tokens (no PKCE means no code verifier required).
4. Attacker wins the race; user login may fail while attacker gains access.

#### Variant C: Weak Binding / Token Replay
If a client/server fails to ensure tokens map to the correct subject/user, an attacker can swap identifiers or abuse trust in token contents (rare, but seen in poor integrations).

### Business/Security Impact
Token/code exposure leads to immediate compromise—similar to theft of session cookies or passwords. Impact depends on scopes:
- profile/email access,
- cloud data access,
- API actions on behalf of the user,
- long-term access if refresh tokens are stolen.

Users often don’t notice until token expiration (and refresh token theft can persist longer).

### Detection Opportunities
- Flag implicit grant usage (`response_type=token` / `id_token`) where code flow is expected.
- Detect codes redeemed multiple times or redeemed from different sources quickly.
- Identify token requests missing `code_verifier` for public clients.
- Scan logs/referrers for `access_token` or unexpected `code=` propagation.
- Investigate user-reported login failures or unknown authorized sessions/devices.

### Mitigations
- **Deprecate implicit flow:** Use Authorization Code + PKCE for all clients.
- **Mandate PKCE:** Require `code_challenge`/`code_verifier` especially for public clients.
- **Use HTTPS and safe redirect schemes:** Prefer HTTPS; for mobile use Universal Links/App Links.
- **Short token lifetimes:** Keep access tokens short-lived; rotate refresh tokens.
- **Secure storage:** Prefer `HttpOnly` cookies or secure OS storage; avoid `localStorage`.
- **Referrer-Policy:** Use `strict-origin-when-cross-origin` (or stricter) and clear tokens from URL with `history.replaceState()`.
- **Advanced sender constraints:** Consider DPoP / PoP tokens to reduce usability of stolen tokens.

---

## 4) Pre-Account Takeover via OAuth Linking

### Description
Apps that support both password accounts and social logins can be vulnerable when they fail to handle **email collisions** safely.

An attacker can pre-create an account using the victim’s email (often possible when email verification is missing). Later, when the victim logs in via Google/Facebook and the app auto-links by email, the victim is logged into an account the attacker controls (because the attacker set the password first).

### Real-World Example
- Public reports (e.g., 2021 HackerOne report referenced for a dating app) describe this pattern: signup allowed without email verification; attacker registers victim email; later victim uses OAuth with that email; app links by email and the attacker still has password access.

### Exploitation (Attack Steps)
1. Attacker registers a local account with victim’s email and a password.
2. Email verification is absent/weak → attacker doesn’t need inbox access.
3. Victim later logs in via OAuth using the same email.
4. App sees “email exists” and logs victim into attacker-created account (or auto-links).
5. Victim uses the service and stores data/payment info.
6. Attacker logs in with email/password they set and accesses everything.

### Business/Security Impact
- Silent account hijack at creation time.
- Personal data exposure, fraud, impersonation, persistent compromise.
- Undermines trust in “Login with Google” experience.

### Detection Opportunities
- Password login occurring before first OAuth login for same email.
- Accounts created but never email-verified that later succeed via OAuth.
- Reports of “I logged in and saw someone else’s profile/data”.
- Duplicate emails across accounts (if your system allows it).
- Password logins on accounts expected to be OAuth-only.
- Geolocation/IP mismatch patterns between password vs OAuth logins.

### Mitigations
- **Require email verification** for all signups (local and OAuth).
- **Do not auto-merge by email** across auth methods. Force explicit linking flows.
- **Use provider immutable identifiers** (`sub`) rather than email strings as the primary key for OAuth identities.
- **Account linking confirmation:** Only allow linking as an explicit, authenticated user action.
- **Cleanup unverified accounts** and prevent unverified accounts from blocking OAuth signups indefinitely.
- **User notifications:** Alert when new login methods are linked or when password login occurs on an OAuth account.

---

## 5) Domain Trust Vulnerability in OIDC (Google “Dangling Domain” Flaw)

### Description
Some relying parties trust email domains too much. If a company domain expires and is re-registered by an attacker, the attacker can create Google accounts with emails matching former employees and use “Sign in with Google” to access third-party services where those employees had accounts.

This becomes severe when the relying party identifies users by email only and does not use immutable identifiers like `sub`.

### Real-World Example (Pattern Discussed Publicly)
Researchers demonstrated that re-registering expired Google Workspace domains could allow access to third-party apps where users had previously used Google SSO. Sensitive systems referenced in discussions included HR systems, payroll/tax documents, and interview platforms.

### Exploitation (Attack Steps)
1. Attacker acquires an expired company domain.
2. Sets up Google Workspace/accounts for that domain.
3. Creates accounts matching prior employees (e.g., `alice@coolstartup.com`).
4. Uses Google Sign-In on third-party apps where `alice@coolstartup.com` previously had access.
5. If relying party keys identity off email and doesn’t validate `sub` continuity, attacker is treated as the same “Alice”.
6. Access granted to historical data and privileges.

### Business/Security Impact
- Identity recycling attack across SaaS ecosystem.
- Exposure of personal HR/tax data, IP, source code, administrative access.
- Hard to detect because logins appear “legitimate” via SSO.

### Detection Opportunities
- Dormant accounts suddenly logging in again after long inactivity.
- **`sub` mismatch for the same email** across logins (strong signal).
- Domain lifecycle awareness: logins from domains known to be deprecated/retired.
- Compare IdP account creation time vs your account age (heuristic).
- Manual offboarding audits and monitoring.

### Mitigations
- **Use immutable identifiers:** Store and enforce `sub` as the stable identifier.
- **Block/flag identity changes:** If email is same but `sub` differs, require manual review or re-verification.
- **Enterprise offboarding:** Convert accounts away from the retiring domain before shutdown.
- **Provider features:** Adopt IdP protections if/when available (org-bound identifiers, warnings).
- **Dormant account checkpoints:** Require re-validation for accounts that return after long inactivity.

---

# Demo Scenarios (Fictional but Realistic)

> These scenarios are hypothetical examples inspired by common OAuth/OIDC mistakes. They are fictional and not based on any specific public incident, but they mirror weaknesses that could exist in a real application.

## Demo Scenario: OAuth Token in URL Query (Leak via Referer)

### Offensive perspective
Acme Corp’s web app uses “Login with AcmeID”. Due to developer oversight, the OAuth callback appends the access token in the **URL query string** instead of the fragment:

`https://app.acme.com/oauth/callback?access_token=XYZ123`

After login, the app redirects to the homepage which loads a third-party analytics script from `analytics.example.com`. Because the access token is in the query string, the browser includes it in the `Referer` header when fetching the analytics script, leaking the token externally. An attacker monitoring analytics logs can harvest valid tokens and call Acme’s APIs.

### Defensive perspective
- **Detection:** Look for tokens appearing in outbound referrers, or unusual API calls from unknown IPs using valid tokens.
- **Mitigation:** Never place tokens in query strings; prefer code flow. Set `Referrer-Policy: no-referrer` (or strict policies) on auth pages, and strip tokens from URL immediately.

---

## Demo Scenario: Misconfigured OIDC Audience

### Offensive perspective
BetaCorp uses OIDC for SSO but does not validate the `aud` claim—only signature. An attacker registers their own app with the same IdP and gets an ID token for a victim where `aud` is the attacker’s client ID. BetaCorp accepts it anyway, logging the attacker in as the victim.

### Defensive perspective
- **Detection:** Any ID token accepted with an unexpected `aud` is anomalous.
- **Mitigation:** Always validate issuer + audience. Use `nonce` and validate it to prevent replay from other flows. Use standard OIDC libraries that enforce these checks.

---

## Demo Scenario: Refresh Token Persisted in Mobile App Storage

### Offensive perspective
A mobile banking app stores refresh tokens in plaintext local storage. Malware steals the refresh token and continuously mints access tokens to perform fraudulent API actions.

### Defensive perspective
- **Detection:** Unusual refresh frequency, odd-hour activity, new IPs, multiple concurrent sessions.
- **Mitigation:** Store tokens in Keychain/Keystore. Use rotating refresh tokens and device binding. Add step-up auth for sensitive actions.

---

## Demo Scenario: Unchecked Logout Redirect Hijack

### Offensive perspective
Logout endpoint:

`https://app.example.com/logout?returnUrl=https://app.example.com`

`returnUrl` isn’t validated. Attacker crafts:

`https://app.example.com/logout?returnUrl=https://evil.com/stealtoken`

User clicks it → gets logged out → redirected to attacker. The attacker uses this as a chain into phishing or post-logout token theft (if any tokens leak).

### Defensive perspective
- **Detection:** Monitor external `returnUrl` usage and off-domain redirects.
- **Mitigation:** Allow-list redirect destinations (prefer internal paths only). Avoid arbitrary URL redirects in login/logout. Regularly test for open redirects.

---

# Best Practice Recap
A secure OAuth/OIDC implementation should include:
- `state` for CSRF protection
- exact redirect URI whitelisting (no wildcards)
- no implicit flow; use Authorization Code + PKCE
- OIDC `nonce`, `aud`, and `iss` validation
- short-lived tokens and secure storage
- identity binding via immutable identifiers like `sub` (not email alone)
- strong logging, monitoring, and library hygiene

---

# Sources (as provided)
- Egor Homakov — *The Most Common OAuth2 Vulnerability* (2012)  
  http://homakov.blogspot.com/2012/07/saferweb-most-common-oauth2.html
- Salt Security — *Booking.com OAuth Flaw* (2023)
- Vishal Sharma — *OAuth Vulnerabilities* (2025, Medium)  
  https://medium.com/@vishalsharma445500/hacking-apis-series-12-36-oauth-vulnerabilities-common-exploits-and-how-to-prevent-them-84061265f0ba
- Outpost24 — *7 common OAuth vulnerabilities (plus mitigations)*  
  https://outpost24.com/blog/common-oauth-vulnerabilities-mitigations/
- CSO Online — *Booking.com account takeover flaw shows pitfalls in OAuth implementations*  
  https://www.csoonline.com/article/574669/booking-com-account-takeover-flaw-shows-possible-pitfalls-in-oauth-implementations.html
- Fitbit Community — *Authentication iOS*  
  https://community.fitbit.com/t5/Web-API-Development/Authentication-ios/td-p/2612265?nobounce
- Coupa — *How to Identify OAuth2 Vulnerabilities and Mitigate Risks*  
  https://careers.coupa.com/how-to-identify-oauth2-vulnerabilities-and-mitigate-risks
- InfoSec Write-ups — *OAuth Misconfiguration Leads To Pre-Account Takeover*  
  https://infosecwriteups.com/oauth-misconfiguration-leads-to-pre-account-takeover-8f94c1ef50be?gi=62e03c7f013e
- GitHub — `auth0-misconfigurations.md`  
  https://github.com/h0tak88r/Sec-88/blob/720ae22260f3cb71b5d2e5955456b3ab282040e3/web-appsec/auth0-misconfigurations.md#L9-L16
- Medium — *OAuth Gone Wrong: When “Sign in with Google” Opens a Pandora’s Box*  
  https://medium.com/@instatunnel/oauth-gone-wrong-when-sign-in-with-google-opens-a-pandoras-box-e7cfa048f908
- Wu et al. — *OAuth 2.0 Case Study on Dropbox* (2013 PDF)  
  https://www.cpp.edu/polysec/project/dropbox/dropbox-paper.pdf
