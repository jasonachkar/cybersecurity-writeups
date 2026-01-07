# Security Tools Reference

This document provides detailed configuration and usage guidance for security scanning tools used in CI/CD pipelines.

## Tool Categories Overview

| Category | Tools Covered | Purpose |
|----------|---------------|---------|
| SAST | CodeQL, SonarQube, Semgrep | Source code analysis |
| SCA | Dependabot, Snyk, OWASP Dependency-Check | Dependency scanning |
| Secrets | Gitleaks, TruffleHog, detect-secrets | Credential detection |
| Container | Trivy, Docker Scout, Anchore | Image vulnerability scanning |
| IaC | Trivy, Checkov, tfsec | Infrastructure configuration |
| DAST | OWASP ZAP, Nuclei | Runtime testing |

---

## Trivy (Multi-Purpose Scanner)

Trivy is a comprehensive, open-source security scanner that handles multiple scan types in a single tool.

### Installation

```bash
# macOS
brew install trivy

# Linux (Debian/Ubuntu)
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Docker
docker pull aquasec/trivy:latest
```

### Scan Types

#### Container Image Scanning

```bash
# Basic scan
trivy image nginx:latest

# With severity filter
trivy image --severity HIGH,CRITICAL nginx:latest

# Ignore unfixed vulnerabilities
trivy image --ignore-unfixed nginx:latest

# Output to SARIF
trivy image --format sarif --output results.sarif nginx:latest

# Exit with error on findings
trivy image --exit-code 1 --severity CRITICAL nginx:latest
```

#### Filesystem Scanning

```bash
# Scan current directory
trivy fs .

# Scan specific path
trivy fs /path/to/project

# Include secrets and config scanning
trivy fs --scanners vuln,secret,config .
```

#### IaC Scanning

```bash
# Scan Terraform files
trivy config ./terraform

# Scan Kubernetes manifests
trivy config ./k8s

# Scan Dockerfile
trivy config --file-patterns "dockerfile:Dockerfile" .
```

#### SBOM Generation

```bash
# Generate CycloneDX SBOM
trivy image --format cyclonedx --output sbom.json nginx:latest

# Generate SPDX SBOM
trivy image --format spdx-json --output sbom.spdx.json nginx:latest

# Scan from SBOM
trivy sbom sbom.json
```

### Configuration File

Create `trivy.yaml`:

```yaml
# Scanning options
severity:
  - CRITICAL
  - HIGH

# Vulnerability options
vulnerability:
  ignore-unfixed: true
  
# Secret scanning
secret:
  config: trivy-secret.yaml

# Misconfiguration scanning  
misconfiguration:
  trace: false
  
# Cache settings
cache:
  dir: .trivy-cache
  
# Output
format: table
output: trivy-report.txt

# Exit code
exit-code: 1
```

### Ignore File

Create `.trivyignore`:

```
# Ignore specific CVEs
# Format: CVE-XXXX-XXXXX

# CVE with no fix available, accepted risk
CVE-2023-12345

# False positive in test dependencies
CVE-2023-67890

# Expires after review period
# exp:2025-06-01
CVE-2024-11111
```

### Secret Scanning Configuration

Create `trivy-secret.yaml`:

```yaml
rules:
  - id: custom-api-key
    category: general
    title: Custom API Key
    severity: HIGH
    regex: 'MYAPP_API_KEY_[A-Za-z0-9]{32}'
    
allow-rules:
  - id: allow-example-keys
    description: Allow example/test keys
    regex: '(example|test|dummy)[-_]?(api)?[-_]?key'
```

---

## CodeQL (SAST)

CodeQL is GitHub's semantic code analysis engine for identifying security vulnerabilities.

### Supported Languages

| Language | Identifier | Build Required |
|----------|------------|----------------|
| C/C++ | cpp | Yes |
| C# | csharp | Yes (or none) |
| Go | go | Yes (or none) |
| Java/Kotlin | java-kotlin | Yes (or none) |
| JavaScript/TypeScript | javascript-typescript | No |
| Python | python | No |
| Ruby | ruby | No |
| Swift | swift | Yes |

### Query Suites

| Suite | Description |
|-------|-------------|
| `default` | Standard security queries |
| `security-extended` | Additional security queries |
| `security-and-quality` | Security + code quality |
| `security-experimental` | Experimental security queries |

### Custom Queries

Create `.github/codeql/custom-queries.ql`:

```ql
/**
 * @name Hardcoded database credentials
 * @description Finds hardcoded database connection strings
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id custom/hardcoded-db-credentials
 * @tags security
 */

import csharp

from StringLiteral s
where s.getValue().regexpMatch("(?i)(password|pwd)\\s*=\\s*[^;]+")
select s, "Potential hardcoded database credential"
```

### CLI Usage

```bash
# Create database
codeql database create mydb --language=javascript --source-root=./src

# Run analysis
codeql database analyze mydb codeql/javascript-queries:Security --format=sarif-latest --output=results.sarif

# Upgrade database
codeql database upgrade mydb
```

---

## Gitleaks (Secret Detection)

Gitleaks is a fast, lightweight secret scanner for git repositories.

### Installation

```bash
# macOS
brew install gitleaks

# Go install
go install github.com/gitleaks/gitleaks/v8@latest

# Docker
docker pull ghcr.io/gitleaks/gitleaks:latest
```

### Usage

```bash
# Scan current directory
gitleaks detect --source .

# Scan with verbose output
gitleaks detect --source . --verbose

# Scan specific commit range
gitleaks detect --source . --log-opts="HEAD~10..HEAD"

# Output formats
gitleaks detect --source . --report-format json --report-path report.json
gitleaks detect --source . --report-format sarif --report-path report.sarif

# Protect mode (for pre-commit)
gitleaks protect --source . --staged
```

### Configuration

Create `.gitleaks.toml`:

```toml
title = "Gitleaks Configuration"

[extend]
useDefault = true

# Custom rules
[[rules]]
id = "internal-api-token"
description = "Internal API Token"
regex = '''INTERNAL_TOKEN_[A-Za-z0-9]{24,}'''
tags = ["token", "internal"]
entropy = 3.5

[[rules]]
id = "custom-secret-pattern"
description = "Custom Secret Pattern"
regex = '''(?i)my_secret\s*[:=]\s*['"]?([a-zA-Z0-9+/]{32,})['"]?'''
secretGroup = 1

# Path allowlist
[allowlist]
description = "Global Allowlist"
paths = [
    '''\.gitleaks\.toml$''',
    '''(^|/)test(s)?/''',
    '''(^|/)__test(s)?__/''',
    '''\.test\.(js|ts|py)$''',
    '''_test\.go$''',
    '''\.md$'''
]

# Regex allowlist (for test values)
regexes = [
    '''EXAMPLE_[A-Z_]+''',
    '''test[-_]?(api[-_]?)?key''',
    '''dummy[-_]?secret'''
]

# Specific commit allowlist
commits = [
    "abc123def456"  # Commit with false positive
]

# Stopwords (common false positives)
stopwords = [
    "example",
    "sample",
    "placeholder"
]
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

---

## TruffleHog (Secret Detection)

TruffleHog specializes in finding credentials with high accuracy using pattern matching and entropy analysis.

### Installation

```bash
# pip
pip install trufflehog

# Docker
docker pull trufflesecurity/trufflehog:latest

# Go
go install github.com/trufflesecurity/trufflehog/v3@latest
```

### Usage

```bash
# Scan git repository
trufflehog git file://./repo --json

# Scan GitHub repository
trufflehog github --repo https://github.com/org/repo --json

# Scan filesystem
trufflehog filesystem /path/to/dir --json

# Only verified secrets
trufflehog git file://. --only-verified

# Exclude paths
trufflehog git file://. --exclude-paths exclude.txt
```

### Exclude File

Create `exclude.txt`:

```
**/test/**
**/tests/**
**/*.test.js
**/node_modules/**
**/vendor/**
*.md
```

---

## Snyk (SCA + SAST)

Snyk provides comprehensive security scanning for dependencies, code, containers, and IaC.

### Installation

```bash
# npm
npm install -g snyk

# Homebrew
brew tap snyk/tap
brew install snyk
```

### Authentication

```bash
snyk auth
# Or use token
export SNYK_TOKEN=your-token
```

### Usage

```bash
# Test dependencies
snyk test

# Monitor project
snyk monitor

# Test container
snyk container test nginx:latest

# Test IaC
snyk iac test ./terraform

# Code analysis
snyk code test

# With severity threshold
snyk test --severity-threshold=high

# Output formats
snyk test --json > results.json
snyk test --sarif > results.sarif
```

### Configuration

Create `.snyk`:

```yaml
version: v1.5.0

# Ignore specific vulnerabilities
ignore:
  SNYK-JS-LODASH-567746:
    - '*':
        reason: No fix available, low risk
        expires: 2025-06-01
        
  SNYK-PYTHON-REQUESTS-1234567:
    - requirements.txt > requests:
        reason: Used only in development
        
# Patch vulnerabilities
patch:
  SNYK-JS-LODASH-567746:
    - lodash:
        patched: '2024-01-15T00:00:00.000Z'
```

---

## OWASP Dependency-Check (SCA)

Open-source dependency scanner that identifies known vulnerabilities.

### Installation

```bash
# Download release
wget https://github.com/jeremylong/DependencyCheck/releases/download/v9.0.0/dependency-check-9.0.0-release.zip
unzip dependency-check-9.0.0-release.zip

# Docker
docker pull owasp/dependency-check:latest
```

### Usage

```bash
# Scan project
./dependency-check.sh --project "MyProject" --scan ./src --format HTML --out ./reports

# Multiple formats
./dependency-check.sh --project "MyProject" --scan . --format "HTML,JSON,SARIF" --out ./reports

# With NVD API key (faster updates)
./dependency-check.sh --nvdApiKey YOUR_API_KEY --scan .

# Fail on CVSS score
./dependency-check.sh --scan . --failOnCVSS 7
```

### Suppression File

Create `dependency-check-suppression.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">
   <suppress>
      <notes>False positive - not applicable to our usage</notes>
      <cve>CVE-2023-12345</cve>
   </suppress>
   
   <suppress>
      <notes>Accepted risk - no fix available</notes>
      <packageUrl regex="true">^pkg:npm/lodash@.*$</packageUrl>
      <cve>CVE-2023-67890</cve>
   </suppress>
   
   <suppress until="2025-06-01">
      <notes>Temporary suppression pending upgrade</notes>
      <gav regex="true">^com\.example:.*:.*$</gav>
      <vulnerabilityName>CVE-2024-11111</vulnerabilityName>
   </suppress>
</suppressions>
```

---

## SonarQube / SonarCloud (SAST + Code Quality)

Comprehensive code quality and security platform.

### Scanner Installation

```bash
# Download scanner
wget https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-5.0.1.3006-linux.zip
unzip sonar-scanner-cli-5.0.1.3006-linux.zip
export PATH=$PATH:$(pwd)/sonar-scanner-5.0.1.3006-linux/bin
```

### Usage

```bash
# Run analysis
sonar-scanner \
  -Dsonar.projectKey=my-project \
  -Dsonar.sources=./src \
  -Dsonar.host.url=https://sonarcloud.io \
  -Dsonar.token=$SONAR_TOKEN
```

### Configuration

Create `sonar-project.properties`:

```properties
# Project identification
sonar.projectKey=org_project
sonar.projectName=My Project
sonar.projectVersion=1.0

# Source configuration
sonar.sources=src
sonar.tests=test
sonar.sourceEncoding=UTF-8

# Language-specific settings
sonar.javascript.lcov.reportPaths=coverage/lcov.info
sonar.typescript.lcov.reportPaths=coverage/lcov.info

# Exclusions
sonar.exclusions=**/node_modules/**,**/*.test.js,**/test/**
sonar.coverage.exclusions=**/*.test.js,**/test/**

# Quality gate
sonar.qualitygate.wait=true
```

---

## Semgrep (SAST)

Lightweight, fast static analysis tool with pattern-based rules.

### Installation

```bash
# pip
pip install semgrep

# Homebrew
brew install semgrep

# Docker
docker pull returntocorp/semgrep
```

### Usage

```bash
# Run with default rules
semgrep --config auto .

# Use specific rulesets
semgrep --config p/security-audit .
semgrep --config p/owasp-top-ten .
semgrep --config p/cwe-top-25 .

# Output formats
semgrep --config auto --sarif --output results.sarif .
semgrep --config auto --json --output results.json .

# With severity filter
semgrep --config auto --severity ERROR .
```

### Custom Rules

Create `.semgrep/custom-rules.yaml`:

```yaml
rules:
  - id: hardcoded-password
    patterns:
      - pattern-either:
          - pattern: password = "..."
          - pattern: pwd = "..."
          - pattern: secret = "..."
    message: Hardcoded password detected
    languages: [python, javascript, typescript]
    severity: ERROR
    metadata:
      cwe: CWE-798
      owasp: A3:2017

  - id: sql-injection
    patterns:
      - pattern: |
          $QUERY = "..." + $USER_INPUT + "..."
          $DB.execute($QUERY)
    message: Potential SQL injection
    languages: [python]
    severity: ERROR
```

---

## OWASP ZAP (DAST)

Dynamic application security testing tool for finding runtime vulnerabilities.

### Installation

```bash
# Docker
docker pull ghcr.io/zaproxy/zaproxy:stable

# Download from https://www.zaproxy.org/download/
```

### Usage

```bash
# Baseline scan (quick)
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://target-app.com

# Full scan
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py -t https://target-app.com

# API scan
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py -t https://target-app.com/api/openapi.json -f openapi

# With report
docker run -v $(pwd):/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t https://target-app.com \
  -r report.html \
  -J report.json
```

### GitHub Action

```yaml
- name: OWASP ZAP Scan
  uses: zaproxy/action-baseline@v0.10.0
  with:
    target: 'https://staging.example.com'
    rules_file_name: '.zap/rules.tsv'
    cmd_options: '-a'
```

### Rules Configuration

Create `.zap/rules.tsv`:

```
10016	IGNORE	(Web Browser XSS Protection Not Enabled)
10017	WARN	(Cross-Domain JavaScript Source File Inclusion)
10019	FAIL	(Content-Type Header Missing)
10021	FAIL	(X-Content-Type-Options Header Missing)
```

---

## Checkov (IaC Security)

Infrastructure as Code scanner for Terraform, CloudFormation, Kubernetes, and more.

### Installation

```bash
# pip
pip install checkov

# Homebrew
brew install checkov

# Docker
docker pull bridgecrew/checkov
```

### Usage

```bash
# Scan directory
checkov -d ./terraform

# Scan file
checkov -f main.tf

# Output formats
checkov -d . -o json > results.json
checkov -d . -o sarif > results.sarif
checkov -d . -o junitxml > results.xml

# With baseline (ignore existing issues)
checkov -d . --create-baseline
checkov -d . --baseline baseline.json

# Specific framework
checkov -d . --framework terraform
```

### Configuration

Create `.checkov.yaml`:

```yaml
# Directories to scan
directory:
  - terraform
  - kubernetes

# Skip specific checks
skip-check:
  - CKV_AWS_18  # S3 bucket logging
  - CKV_AWS_21  # S3 versioning

# External checks
external-checks-dir:
  - ./custom-checks

# Soft fail (don't exit with error)
soft-fail: false

# Output
output: cli
```

### Custom Check

Create `custom-checks/require_tags.py`:

```python
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckCategories, CheckResult

class RequireEnvironmentTag(BaseResourceCheck):
    def __init__(self):
        name = "Ensure all resources have an 'Environment' tag"
        id = "CKV_CUSTOM_1"
        supported_resources = ['aws_*']
        categories = [CheckCategories.CONVENTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        tags = conf.get('tags', [{}])[0]
        if 'Environment' in tags:
            return CheckResult.PASSED
        return CheckResult.FAILED

check = RequireEnvironmentTag()
```

---

## tfsec (Terraform Security)

Fast Terraform security scanner.

### Installation

```bash
# Homebrew
brew install tfsec

# Go
go install github.com/aquasecurity/tfsec/cmd/tfsec@latest

# Docker
docker pull aquasec/tfsec:latest
```

### Usage

```bash
# Scan directory
tfsec ./terraform

# Output formats
tfsec . --format json > results.json
tfsec . --format sarif > results.sarif

# Minimum severity
tfsec . --minimum-severity HIGH

# Exclude checks
tfsec . --exclude-downloaded-modules
```

### Configuration

Create `.tfsec/config.yml`:

```yaml
minimum_severity: MEDIUM

exclude:
  - aws-s3-enable-bucket-logging

severity_overrides:
  aws-s3-enable-versioning: LOW
```

---

## Tool Comparison Matrix

| Feature | Trivy | Snyk | OWASP DC | Checkov |
|---------|-------|------|----------|---------|
| Container scanning | ✅ | ✅ | ❌ | ❌ |
| Dependency scanning | ✅ | ✅ | ✅ | ❌ |
| IaC scanning | ✅ | ✅ | ❌ | ✅ |
| Secret scanning | ✅ | ❌ | ❌ | ❌ |
| License checking | ✅ | ✅ | ❌ | ❌ |
| SBOM generation | ✅ | ✅ | ❌ | ❌ |
| Free/Open source | ✅ | Freemium | ✅ | ✅ |
| CI/CD integration | ✅ | ✅ | ✅ | ✅ |

---

## Recommended Tool Stack

### Minimal Setup (Open Source)

| Category | Tool | Rationale |
|----------|------|-----------|
| Multi-purpose | Trivy | Covers containers, deps, IaC, secrets |
| SAST | CodeQL | Native GitHub integration |
| Secrets | Gitleaks | Fast, configurable |

### Enterprise Setup

| Category | Primary | Secondary |
|----------|---------|-----------|
| SAST | SonarQube | CodeQL |
| SCA | Snyk | OWASP DC |
| Containers | Trivy | Docker Scout |
| Secrets | GitHub Secret Scanning | Gitleaks |
| IaC | Checkov | tfsec |
| DAST | OWASP ZAP | Nuclei |

---

## Related Documentation

- [README.md](README.md) - Main tutorial
- [github-actions.md](github-actions.md) - GitHub Actions configuration
- [azure-devops.md](azure-devops.md) - Azure DevOps configuration
