# OAuth 2.0 security code examples (superseded)

**Lifecycle:** Historical examples retired on 2026-07-23.

This page previously contained a large collection of illustrative TypeScript and
Python fragments. They were not connected to dependency locks or automated tests,
and one redirect validator normalized registered and requested URIs before comparison.
That behavior could treat distinct strings as equivalent and did not demonstrate the
exact redirect matching required by the current OAuth Security Best Current Practice.

The unsafe fragments have been removed from the current guidance. Git history retains
them for review; they are not implementation recommendations.

## Current replacements

| Security boundary | Evidence | Status |
| --- | --- | --- |
| Authorization flow, token consumers, state, nonce, issuer, keys, refresh, sender constraint | [OAuth 2.0 and OpenID Connect Security Engineering](../../../appsec/oauth2-oidc-deep-dive.md) | Primary-source-reviewed guidance with explicitly labeled pseudocode |
| Access-token issuer, audience, signature, time, tenant, scope, and key rotation | [OAuth/OIDC token-boundary lab](../../../labs/oauth-oidc/README.md) | Dependency-free automated positive and negative checks |
| Redirect URI exact string matching | [OAuth/OIDC token-boundary lab](../../../labs/oauth-oidc/README.md) | Tested web-client matcher; native loopback exception is out of scope |
| PKCE verifier/challenge validation | [S256-only Go verifier](../../../appsec/scripts/oauth-pkce-verifier.go) | Executable RFC 7636 vector and negative checks; no secret-value logging |

Use a maintained OAuth/OIDC and JOSE library in production. Configure the expected
issuer, resource-server audience, asymmetric algorithm, provider token profile, and
trusted metadata/JWKS origin. A valid token does not replace tenant, object, or
business authorization.

## References

- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [RFC 7636: Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636.html)
- [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0-18.html)
- [RFC 8725: JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html)
