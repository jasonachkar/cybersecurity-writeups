# Application Security scripts

The application security scripts and packages I've written, with their source shown directly below — no need to open GitHub to read them.

<div id="oauth-pkce-verifier" class="section" aria-labelledby="oauth-pkce-verifier-heading">

## OAuth PKCE (S256) verifier and generator

<span class="docs-badge">Go</span><span class="docs-badge">Read-only</span><span class="docs-badge">Go test suite</span>

### What it does

A small, dependency-free implementation of RFC 7636's S256 PKCE flow: generating a valid random verifier, deriving its challenge, and validating a verifier against a stored challenge using a constant-time comparison.

### Why I wrote it

The OAuth/OIDC write-up needed a real PKCE implementation behind its test cases instead of a description of one, so I wrote the minimal correct version and used it as that reference implementation.

### How it works

GenerateRandomVerifier draws from crypto/rand and formats the result to RFC 7636's unreserved-character alphabet. ComputeChallengeS256 does the SHA-256 + base64url-no-padding derivation. ValidatePKCES256 recomputes the expected challenge from the supplied verifier and compares it to the stored one with crypto/subtle.ConstantTimeCompare, and only accepts the S256 method (deliberately, plain is never accepted).

### Requirements

- Go 1.22+

### Permissions and safety

None — no filesystem, network, or credential access. It deliberately never logs the verifier or challenge values it handles.

### Usage

    go test ./appsec/scripts/oauth-pkce/...

### Inputs

A verifier length (for generation) or a verifier/challenge/method triple (for validation).

### Outputs

A verifier string, a challenge string, or a boolean validation result.

### What I tested

pkce_test.go exercises the correct round trip plus the negative cases: a wrong verifier, a plain-method downgrade attempt, wrong verifier length, invalid characters, and a malformed stored challenge.

### Limitations

- This checks the PKCE mechanics only — it says nothing about redirect-URI matching, state/nonce handling, or token validation, which live in the OAuth/OIDC lab instead.
- No CLI entry point; it is meant to be imported or exercised via its tests.

### Related research

- Related research: [OAuth 2.0 and OIDC](/appsec/oauth2-oidc-deep-dive/)
- Related lab: [OAuth/OIDC lab](/labs/oauth-oidc/)

</div>
