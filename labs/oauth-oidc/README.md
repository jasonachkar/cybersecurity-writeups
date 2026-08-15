---
id: oauth-oidc
title: OAuth/OIDC token-boundary lab
navTitle: OAuth and OIDC
domain: appsec
order: 30
summary: Exercises issuer, audience, time, nonce, state, redirects, PKCE, and key rotation against local boundary fixtures.
implementationStatus: tested
related:
  research: [oauth2-oidc-deep-dive]
sourceFiles:
  - { path: labs/oauth-oidc/oauth-security.js, label: Boundary adapter, language: javascript, primary: true }
  - { path: labs/oauth-oidc/tests/oauth-security.test.js, label: Tests, language: javascript }
runCommands: [node --test labs/oauth-oidc/tests/oauth-security.test.js]
---

# OAuth/OIDC token-boundary lab

**Implementation status:** Tested locally on 2026-07-23 with Node.js 24.12.0 and Go 1.26.1. The JavaScript suite supports Node.js 22 or newer.

This dependency-free lab turns the most important OAuth/OIDC resource-server boundaries into executable acceptance and rejection checks. It is deliberately a small verifier model, not a replacement for a maintained JOSE/OIDC library.

## What the lab proves

`tests/oauth-security.test.js` generates trusted, rotated, and attacker RSA keys and checks that the resource-server validator:

- accepts a correctly signed RS256 access token for the configured issuer, API audience, tenant, and required scope;
- rejects a bad signature, issuer, audience, expiration, not-before time, tenant, or scope;
- accepts the configured audience in either the string or array form;
- accepts old and new trusted keys during a bounded rotation overlap, then rejects the retired key;
- rejects an unknown `kid` without turning it into a network location; and
- compares web redirect URI requests to registered strings exactly, including case, port, path, query, and fragment differences.

The `tid` and `scope`/`scp` names are an explicit example contract. Real providers can use different claims, token profiles, and authorization semantics. Configure those from trusted provider documentation. The API must still enforce current object, tenant, and business authorization after token validation.

## Run

From the repository root:

```text
node labs/oauth-oidc/tests/oauth-security.test.js
go test ./appsec/scripts/oauth-pkce
```

Expected results are 14 passing Node.js checks and 8 passing Go checks. The Go program covers the RFC 7636 Appendix B vector, generated-verifier round trip, wrong verifier, `plain` downgrade, method case, length, syntax, and malformed challenge. It never prints verifier or challenge values.

## Security boundaries and limitations

- The lab trusts only keys supplied in the configured `Map`; it performs no discovery or network fetch. Production metadata/JWKS retrieval needs a configured HTTPS issuer, bounded caching, rate limits, controlled redirects and egress, and a last-known-good rotation strategy.
- Only RS256 with `typ=JWT` is modeled. A maintained library should be configured for the provider's exact asymmetric algorithm and token profile.
- The clock is injected so time tests are deterministic. Deployed code needs a narrow documented skew and synchronized clocks.
- Exact matching is shown for a confidential web client's HTTPS redirects. Native loopback redirects have the port exception defined by RFC 8252 and are intentionally outside this matcher.
- The lab does not implement authorization-code redemption, nonce/state persistence, DPoP, mTLS, introspection, revocation, or refresh-token rotation.
- Neither raw tokens nor PKCE verifiers should be written to logs.

## Related guidance

- [OAuth 2.0 and OpenID Connect Security Engineering](../../appsec/oauth2-oidc-deep-dive.md)
- [S256-only PKCE verifier](../../appsec/scripts/oauth-pkce/pkce.go)
- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [RFC 7636: Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 8725: JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html)
