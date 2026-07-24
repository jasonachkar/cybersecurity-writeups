---
title: "API authorization example: bounded design checklist"
type: tutorial
status: superseded
lastReviewed: 2026-07-23
implementationStatus: illustrative
---

# API authorization example: bounded design checklist

This page previously presented a short Flask snippet as a complete secure API. It
has been retired because disabling debug mode, using a parameterized query, and
checking one identifier do not establish a complete API security boundary.

The former snippet also used a fallback JWT secret, omitted issuer and audience
validation, did not show database-connection cleanup, and coupled object
authorization directly to a route parameter. Those omissions make it unsuitable
as runnable hardened guidance.

## Control checklist

A maintained implementation should test all of these controls:

1. Fail startup when signing or verification key configuration is absent.
2. Validate the JWT algorithm allowlist, signature, issuer, audience, expiry, and
   not-before time before using claims.
3. Resolve the authenticated subject to an application principal; do not assume a
   route identifier is the subject identifier.
4. Authorize the requested action against the specific object and tenant after the
   object is loaded.
5. Use parameterized SQL and a database identity with only the required
   permissions.
6. Return an explicit response schema that omits secret and internal fields.
7. Apply request-size, rate, and resource-consumption limits at enforceable layers.
8. Record authorization denials without logging tokens, payment data, or other
   secrets.
9. Test horizontal and vertical authorization failures, malformed and expired
   tokens, wrong issuer and audience, and cross-tenant identifiers.
10. Deploy through a maintained WSGI server and reverse proxy with transport,
    timeout, and error-handling controls appropriate to the environment.

## Validation evidence

This page is a design checklist, not a runnable Flask application. No production
deployment is claimed. Protocol validation cases are exercised separately in the
[OAuth/OIDC security lab](../../../../labs/oauth-oidc/README.md); object and tenant
authorization require application-specific integration tests.

## Primary sources

- [RFC 8725: JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [OWASP API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [Flask: deploying to production](https://flask.palletsprojects.com/en/stable/deploying/)
