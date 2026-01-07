# GitHub Actions Security Scanning Configuration

This document provides complete workflow configurations for implementing security gates in GitHub Actions.

## Overview

GitHub provides multiple native security features that integrate directly with Actions workflows:

| Feature | Type | License |
|---------|------|---------|
| CodeQL | SAST | Free (public), GHAS (private) |
| Dependabot | SCA | Free |
| Secret Scanning | Secrets | Free (public), GHAS (private) |
| Dependency Review | SCA | GHAS |

---

## Complete Security Pipeline

This workflow implements a comprehensive security scanning pipeline:

```yaml
name: Security Scanning Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  schedule:
    # Run weekly on Monday at 9am UTC
    - cron: '0 9 * * 1'

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  # Job 1: Secret Detection
  secrets-scan:
    name: Secrets Detection
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for comprehensive scan

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_ENABLE_COMMENTS: true

  # Job 2: SAST with CodeQL
  codeql-analysis:
    name: CodeQL Analysis
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        language: ['javascript', 'python']
        # Add languages: 'csharp', 'java', 'go', 'ruby', 'cpp'
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          queries: +security-and-quality

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"

  # Job 3: Dependency Scanning
  dependency-scan:
    name: Dependency Vulnerability Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Trivy vulnerability scanner (filesystem)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-fs-results.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-fs-results.sarif'

  # Job 4: Container Scanning
  container-scan:
    name: Container Image Scan
    runs-on: ubuntu-latest
    needs: [secrets-scan, codeql-analysis]
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-image-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-image-results.sarif'

  # Job 5: IaC Scanning
  iac-scan:
    name: Infrastructure as Code Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Trivy IaC scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'config'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-iac-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

      - name: Upload Trivy IaC results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-iac-results.sarif'
```

---

## CodeQL Advanced Configuration

### Custom Query Packs

Include additional security queries:

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: ${{ matrix.language }}
    queries: |
      security-extended
      security-and-quality
    # Or use specific packs:
    # packs: codeql/javascript-queries:AlertSuppression.ql
```

### Configuration File

Create `.github/codeql/codeql-config.yml`:

```yaml
name: "CodeQL Config"

# Specify query packs
queries:
  - uses: security-extended
  - uses: security-and-quality

# Paths to scan
paths:
  - src
  - lib

# Paths to exclude
paths-ignore:
  - '**/test/**'
  - '**/tests/**'
  - '**/*.test.js'
  - '**/node_modules/**'
  - '**/vendor/**'

# Query filters
query-filters:
  - exclude:
      id: js/redundant-assignment
  - exclude:
      tags contain: maintainability
```

Reference in workflow:

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: javascript
    config-file: .github/codeql/codeql-config.yml
```

---

## Dependency Scanning Configuration

### Dependabot Configuration

Create `.github/dependabot.yml`:

```yaml
version: 2
updates:
  # JavaScript/npm
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "security"
    groups:
      development-dependencies:
        dependency-type: "development"
        update-types:
          - "minor"
          - "patch"

  # Python/pip
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "python"

  # Docker
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "docker"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "ci"

  # Terraform
  - package-ecosystem: "terraform"
    directory: "/infrastructure"
    schedule:
      interval: "weekly"

  # NuGet (.NET)
  - package-ecosystem: "nuget"
    directory: "/"
    schedule:
      interval: "weekly"
```

### npm Audit Integration

```yaml
npm-audit:
  name: npm Security Audit
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '20'
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run npm audit
      run: npm audit --audit-level=high
      continue-on-error: false
```

### .NET Dependency Scanning

```yaml
dotnet-scan:
  name: .NET Dependency Scan
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    
    - name: Setup .NET
      uses: actions/setup-dotnet@v4
      with:
        dotnet-version: '8.0.x'
    
    - name: Restore dependencies
      run: dotnet restore
    
    - name: Run dotnet list package vulnerable
      run: dotnet list package --vulnerable --include-transitive 2>&1 | tee vulnerabilities.txt
    
    - name: Check for vulnerabilities
      run: |
        if grep -q "has the following vulnerable packages" vulnerabilities.txt; then
          echo "::error::Vulnerable packages found"
          exit 1
        fi
```

---

## Secret Scanning Configuration

### Enable Secret Scanning

Configure in repository settings:
1. **Settings** > **Code security and analysis**
2. Enable **Secret scanning**
3. Enable **Push protection**

### Gitleaks Configuration

Create `.gitleaks.toml`:

```toml
title = "Gitleaks Configuration"

[extend]
# Use default ruleset as base
useDefault = true

# Custom rules
[[rules]]
id = "custom-api-key"
description = "Custom API Key Pattern"
regex = '''(?i)my_api_key\s*[=:]\s*['"]?([a-zA-Z0-9]{32,})['"]?'''
tags = ["key", "api"]

[[rules]]
id = "internal-token"
description = "Internal Service Token"
regex = '''INT_TOKEN_[A-Za-z0-9]{16,}'''
tags = ["token", "internal"]

# Allowlist
[allowlist]
description = "Global Allowlist"
paths = [
    '''(.*/)?\.gitleaks\.toml$''',
    '''(.*/)?test/.*''',
    '''(.*/)?tests/.*''',
    '''(.*/)?__tests__/.*'''
]
regexes = [
    '''EXAMPLE_API_KEY''',
    '''test-api-key-12345'''
]
```

### TruffleHog Integration

```yaml
trufflehog-scan:
  name: TruffleHog Secrets Scan
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0
    
    - name: TruffleHog OSS
      uses: trufflesecurity/trufflehog@main
      with:
        path: ./
        base: ${{ github.event.repository.default_branch }}
        head: HEAD
        extra_args: --only-verified
```

---

## Container Scanning

### Trivy Container Scan

```yaml
container-security:
  name: Container Security Scan
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    
    - name: Build image
      run: docker build -t myapp:${{ github.sha }} .
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'myapp:${{ github.sha }}'
        format: 'table'
        exit-code: '1'
        ignore-unfixed: true
        vuln-type: 'os,library'
        severity: 'CRITICAL,HIGH'
    
    - name: Run Trivy for SARIF
      uses: aquasecurity/trivy-action@master
      if: always()
      with:
        image-ref: 'myapp:${{ github.sha }}'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload to Security tab
      uses: github/codeql-action/upload-sarif@v3
      if: always()
      with:
        sarif_file: 'trivy-results.sarif'
```

### Docker Scout Integration

```yaml
docker-scout:
  name: Docker Scout Analysis
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    
    - name: Login to Docker Hub
      uses: docker/login-action@v3
      with:
        username: ${{ secrets.DOCKERHUB_USERNAME }}
        password: ${{ secrets.DOCKERHUB_TOKEN }}
    
    - name: Build image
      run: docker build -t myapp:${{ github.sha }} .
    
    - name: Docker Scout scan
      uses: docker/scout-action@v1
      with:
        command: cves
        image: myapp:${{ github.sha }}
        sarif-file: scout-results.sarif
        exit-code: true
    
    - name: Upload Scout results
      uses: github/codeql-action/upload-sarif@v3
      if: always()
      with:
        sarif_file: scout-results.sarif
```

---

## SBOM Generation

### Generate and Attest SBOM

```yaml
sbom:
  name: Generate SBOM
  runs-on: ubuntu-latest
  permissions:
    contents: read
    id-token: write
    attestations: write
  steps:
    - uses: actions/checkout@v4
    
    - name: Build image
      run: docker build -t myapp:${{ github.sha }} .
    
    - name: Generate SBOM with Trivy
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'myapp:${{ github.sha }}'
        format: 'cyclonedx'
        output: 'sbom.json'
    
    - name: Upload SBOM
      uses: actions/upload-artifact@v4
      with:
        name: sbom
        path: sbom.json
    
    - name: Attest SBOM
      uses: actions/attest-sbom@v1
      with:
        subject-name: myapp
        subject-digest: sha256:${{ github.sha }}
        sbom-path: sbom.json
```

---

## Branch Protection Rules

Configure branch protection to require security checks:

```json
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Secrets Detection",
      "CodeQL Analysis",
      "Dependency Vulnerability Scan",
      "Container Image Scan"
    ]
  },
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 1
  },
  "enforce_admins": true,
  "restrictions": null
}
```

---

## Security Findings in Pull Requests

### Dependency Review Action

```yaml
dependency-review:
  name: Dependency Review
  runs-on: ubuntu-latest
  if: github.event_name == 'pull_request'
  steps:
    - uses: actions/checkout@v4
    
    - name: Dependency Review
      uses: actions/dependency-review-action@v4
      with:
        fail-on-severity: high
        deny-licenses: GPL-3.0, AGPL-3.0
        allow-licenses: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause
```

### PR Comment with Findings

```yaml
- name: Comment on PR
  if: github.event_name == 'pull_request' && failure()
  uses: actions/github-script@v7
  with:
    script: |
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: '⚠️ Security scan detected vulnerabilities. Please review the Security tab for details.'
      })
```

---

## Scheduled Scanning

### Weekly Full Scan

```yaml
name: Weekly Security Scan

on:
  schedule:
    - cron: '0 2 * * 1'  # Monday at 2 AM UTC
  workflow_dispatch:  # Allow manual trigger

jobs:
  full-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      # Run comprehensive scans
      - name: Full Trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          format: 'json'
          output: 'full-scan-results.json'
          severity: 'CRITICAL,HIGH,MEDIUM'
      
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: weekly-scan-results
          path: full-scan-results.json
          retention-days: 90
```

---

## Reusable Workflow

Create `.github/workflows/security-scan.yml`:

```yaml
name: Reusable Security Scan

on:
  workflow_call:
    inputs:
      scan-type:
        description: 'Type of scan to run'
        required: true
        type: string
      severity:
        description: 'Severity threshold'
        required: false
        type: string
        default: 'CRITICAL,HIGH'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: ${{ inputs.scan-type }}
          severity: ${{ inputs.severity }}
          exit-code: '1'
```

Use in other workflows:

```yaml
jobs:
  call-security:
    uses: ./.github/workflows/security-scan.yml
    with:
      scan-type: 'fs'
      severity: 'CRITICAL'
```

---

## Related Documentation

- [README.md](README.md) - Main tutorial
- [azure-devops.md](azure-devops.md) - Azure DevOps configuration
- [tools.md](tools.md) - Security tools reference
