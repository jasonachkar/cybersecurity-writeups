# Application Security Automation Scripts

This section contains utility scripts written in Go that demonstrate core application security concepts: token validation, PKCE cryptography, and vulnerability scanning.

---

## 1. Cryptographic JWT Validator (`jwt-validator.go`)

### Purpose
Implements manual parsing and cryptographic validation of JSON Web Tokens (JWT) using standard library RSA signature verification, checking expiration, issuer, and audience claims.

### Code Implementation
```go
--8<-- "appsec/scripts/jwt-validator.go"
```

---

## 2. OAuth 2.0 PKCE Verifier (`oauth-pkce-verifier.go`)

### Purpose
Cryptographically demonstrates and verifies the OAuth 2.0 PKCE (Proof Key for Code Exchange) flow (RFC 7636), showing how authorization servers check verifiers against challenges to mitigate token interception attacks.

### Code Implementation
```go
--8<-- "appsec/scripts/oauth-pkce-verifier.go"
```

---

## 3. IDOR API Endpoint Scanner (`idor-scanner.go`)

### Purpose
Simulates an IDOR (Insecure Direct Object Reference) audit scan on REST endpoints, demonstrating how automated scanners query resources using different authorization headers to discover access isolation breaches.

### Code Implementation
```go
--8<-- "appsec/scripts/idor-scanner.go"
```
