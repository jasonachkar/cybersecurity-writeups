# DevSecOps Automation Scripts

This section outlines security automation scripts designed to build compliance checks, diff dependency SBOMs, and catch secrets during CI/CD execution.

---

## 1. CI/CD Security Gate Parser (`pipeline-gate.go`)

### Purpose
Implements a CI/CD pipeline deployment security gate. Parses vulnerability reports and fails the build (exit code 1) if security thresholds (e.g. any Criticals, > 2 Highs, or hardcoded secrets) are violated.

### Code Implementation
```go
--8<-- "devsecops/scripts/pipeline-gate.go"
```

---

## 2. CycloneDX SBOM Digger (`sbom-diff.go`)

### Purpose
Parses and diffs two CycloneDX Software Bill of Materials (SBOM) files in JSON format to identify new dependencies, version upgrades/downgrades, and license compliance updates.

### Code Implementation
```go
--8<-- "devsecops/scripts/sbom-diff.go"
```

---

## 3. High-Entropy Secret Scanner (`secret-scanner.go`)

### Purpose
Scans code files or git diff inputs using regular expressions and Shannon entropy calculations to identify hardcoded API keys, passwords, and private keys.

### Code Implementation
```go
--8<-- "devsecops/scripts/secret-scanner.go"
```
