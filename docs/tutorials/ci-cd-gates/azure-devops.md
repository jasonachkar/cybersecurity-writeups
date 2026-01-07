# Azure DevOps Security Scanning Configuration

This document provides complete pipeline configurations for implementing security gates in Azure DevOps.

## Overview

Azure DevOps offers multiple approaches to security scanning:

| Approach | Description | License |
|----------|-------------|---------|
| GitHub Advanced Security for Azure DevOps | Native CodeQL, secret scanning, dependency scanning | Per-committer license |
| Microsoft Security DevOps Extension | Defender for Cloud integration | Free (extension) |
| Third-Party Extensions | Checkmarx, SonarQube, Snyk, etc. | Varies |
| CLI-Based Tools | Trivy, Gitleaks, etc. | Free (open source) |

---

## GitHub Advanced Security for Azure DevOps

### Enabling Advanced Security

1. Navigate to **Project Settings** > **Repos** > **Repositories**
2. Select the repository
3. Toggle **Advanced Security** to **On**
4. Review the billing estimate and confirm

### Features Enabled

| Feature | Activation | Description |
|---------|------------|-------------|
| Secret Scanning | Automatic | Push protection + repository scan |
| Dependency Scanning | Pipeline task required | SCA for dependencies |
| Code Scanning | Pipeline task required | CodeQL SAST |

---

## Complete Security Pipeline

### YAML Pipeline with All Security Gates

```yaml
trigger:
  branches:
    include:
      - main
      - develop
  paths:
    exclude:
      - '*.md'
      - 'docs/*'

pr:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  - name: trivyVersion
    value: '0.50.0'

stages:
  # Stage 1: Security Scanning
  - stage: SecurityScanning
    displayName: 'Security Scanning'
    jobs:
      # Job 1: Secret Detection
      - job: SecretsDetection
        displayName: 'Secrets Detection'
        steps:
          - checkout: self
            fetchDepth: 0

          - task: Bash@3
            displayName: 'Install Gitleaks'
            inputs:
              targetType: 'inline'
              script: |
                wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
                tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
                chmod +x gitleaks
                sudo mv gitleaks /usr/local/bin/

          - task: Bash@3
            displayName: 'Run Gitleaks Scan'
            inputs:
              targetType: 'inline'
              script: |
                gitleaks detect --source . --verbose --report-format sarif --report-path gitleaks-report.sarif
            continueOnError: false

          - task: PublishBuildArtifacts@1
            displayName: 'Publish Gitleaks Report'
            condition: always()
            inputs:
              pathToPublish: 'gitleaks-report.sarif'
              artifactName: 'CodeAnalysisLogs'

      # Job 2: SAST with CodeQL (Advanced Security)
      - job: CodeQLAnalysis
        displayName: 'CodeQL Analysis'
        steps:
          - checkout: self

          - task: AdvancedSecurity-Codeql-Init@1
            displayName: 'Initialize CodeQL'
            inputs:
              languages: 'csharp,javascript'
              querysuite: 'security-extended'

          - task: DotNetCoreCLI@2
            displayName: 'Build .NET Project'
            inputs:
              command: 'build'
              projects: '**/*.csproj'

          - task: AdvancedSecurity-Codeql-Analyze@1
            displayName: 'Perform CodeQL Analysis'

      # Job 3: Dependency Scanning (Advanced Security)
      - job: DependencyScanning
        displayName: 'Dependency Scanning'
        steps:
          - checkout: self

          - task: AdvancedSecurity-Dependency-Scanning@1
            displayName: 'Dependency Scanning'

      # Job 4: Trivy Filesystem Scan
      - job: TrivyFilesystemScan
        displayName: 'Trivy Filesystem Scan'
        steps:
          - checkout: self

          - task: Bash@3
            displayName: 'Install Trivy'
            inputs:
              targetType: 'inline'
              script: |
                wget https://github.com/aquasecurity/trivy/releases/download/v$(trivyVersion)/trivy_$(trivyVersion)_Linux-64bit.tar.gz
                tar -xzf trivy_$(trivyVersion)_Linux-64bit.tar.gz
                sudo mv trivy /usr/local/bin/

          - task: Bash@3
            displayName: 'Trivy Filesystem Scan'
            inputs:
              targetType: 'inline'
              script: |
                trivy fs --format sarif --output trivy-fs-results.sarif --severity HIGH,CRITICAL .

          - task: PublishBuildArtifacts@1
            displayName: 'Publish Trivy Results'
            condition: always()
            inputs:
              pathToPublish: 'trivy-fs-results.sarif'
              artifactName: 'CodeAnalysisLogs'

  # Stage 2: Build
  - stage: Build
    displayName: 'Build'
    dependsOn: SecurityScanning
    jobs:
      - job: BuildApplication
        displayName: 'Build Application'
        steps:
          - checkout: self

          - task: DotNetCoreCLI@2
            displayName: 'Restore packages'
            inputs:
              command: 'restore'
              projects: '**/*.csproj'

          - task: DotNetCoreCLI@2
            displayName: 'Build'
            inputs:
              command: 'build'
              projects: '**/*.csproj'
              arguments: '--configuration Release'

          - task: Docker@2
            displayName: 'Build Docker Image'
            inputs:
              command: 'build'
              Dockerfile: '**/Dockerfile'
              tags: '$(Build.BuildId)'

          - task: Bash@3
            displayName: 'Save Docker Image'
            inputs:
              targetType: 'inline'
              script: |
                docker save -o $(Build.ArtifactStagingDirectory)/app-image.tar myapp:$(Build.BuildId)

          - task: PublishBuildArtifacts@1
            displayName: 'Publish Docker Image'
            inputs:
              pathToPublish: '$(Build.ArtifactStagingDirectory)/app-image.tar'
              artifactName: 'docker-image'

  # Stage 3: Container Scanning
  - stage: ContainerScanning
    displayName: 'Container Scanning'
    dependsOn: Build
    jobs:
      - job: TrivyContainerScan
        displayName: 'Container Vulnerability Scan'
        steps:
          - task: DownloadBuildArtifacts@1
            displayName: 'Download Docker Image'
            inputs:
              buildType: 'current'
              downloadType: 'single'
              artifactName: 'docker-image'
              downloadPath: '$(System.ArtifactsDirectory)'

          - task: Bash@3
            displayName: 'Load Docker Image'
            inputs:
              targetType: 'inline'
              script: |
                docker load -i $(System.ArtifactsDirectory)/docker-image/app-image.tar

          - task: Bash@3
            displayName: 'Install Trivy'
            inputs:
              targetType: 'inline'
              script: |
                wget https://github.com/aquasecurity/trivy/releases/download/v$(trivyVersion)/trivy_$(trivyVersion)_Linux-64bit.tar.gz
                tar -xzf trivy_$(trivyVersion)_Linux-64bit.tar.gz
                sudo mv trivy /usr/local/bin/

          - task: Bash@3
            displayName: 'Trivy Container Scan'
            inputs:
              targetType: 'inline'
              script: |
                trivy image --format sarif --output trivy-container-results.sarif --severity HIGH,CRITICAL myapp:$(Build.BuildId)
                trivy image --exit-code 1 --severity CRITICAL myapp:$(Build.BuildId)

          - task: PublishBuildArtifacts@1
            displayName: 'Publish Container Scan Results'
            condition: always()
            inputs:
              pathToPublish: 'trivy-container-results.sarif'
              artifactName: 'CodeAnalysisLogs'

  # Stage 4: Deploy (only if all security checks pass)
  - stage: Deploy
    displayName: 'Deploy'
    dependsOn: ContainerScanning
    condition: succeeded()
    jobs:
      - deployment: DeployToStaging
        displayName: 'Deploy to Staging'
        environment: 'staging'
        strategy:
          runOnce:
            deploy:
              steps:
                - script: echo "Deploying to staging..."
```

---

## Microsoft Security DevOps Extension

### Installation

1. Go to [Visual Studio Marketplace](https://marketplace.visualstudio.com/)
2. Search for "Microsoft Security DevOps"
3. Click **Get it free** and install to your organization

### Basic Configuration

```yaml
steps:
  - task: MicrosoftSecurityDevOps@1
    displayName: 'Microsoft Security DevOps'
    inputs:
      categories: 'secrets,code,artifacts,IaC,containers'
```

### Advanced Configuration

```yaml
steps:
  - task: MicrosoftSecurityDevOps@1
    displayName: 'Microsoft Security DevOps'
    inputs:
      categories: 'IaC,secrets'
      tools: 'templateanalyzer,terrascan,trivy'
      break: true
      publish: true
```

### Tools Included

| Tool | Category | Description |
|------|----------|-------------|
| ESLint | Code | JavaScript/TypeScript linting |
| Template Analyzer | IaC | ARM/Bicep analysis |
| Terrascan | IaC | Terraform, K8s, Dockerfile |
| Trivy | Containers, IaC | Multi-purpose scanner |

---

## CodeQL for Azure DevOps

### Initialize and Analyze

```yaml
jobs:
  - job: CodeQL
    displayName: 'CodeQL Analysis'
    pool:
      vmImage: 'windows-latest'
    steps:
      - checkout: self
      
      - task: AdvancedSecurity-Codeql-Init@1
        displayName: 'Initialize CodeQL'
        inputs:
          languages: 'csharp'
          querysuite: 'security-extended'
          # Enable automatic installation
          enableAutomaticCodeQLInstall: true
      
      - task: DotNetCoreCLI@2
        displayName: 'Build Project'
        inputs:
          command: 'build'
          projects: '**/*.csproj'
          arguments: '--configuration Release'
      
      - task: AdvancedSecurity-Codeql-Analyze@1
        displayName: 'Analyze with CodeQL'
```

### Supported Languages

| Language | Build Mode |
|----------|------------|
| C# | autobuild or manual |
| Java/Kotlin | autobuild or manual |
| JavaScript/TypeScript | none |
| Python | none |
| Go | autobuild or manual |
| C/C++ | manual |
| Ruby | none |

### Multi-Language Scanning

```yaml
- task: AdvancedSecurity-Codeql-Init@1
  inputs:
    languages: 'csharp,javascript,python'
    querysuite: 'security-and-quality'
```

---

## Dependency Scanning

### Advanced Security Dependency Scanning

```yaml
steps:
  - checkout: self
  
  # For .NET projects, restore packages first
  - task: DotNetCoreCLI@2
    displayName: 'Restore packages'
    inputs:
      command: 'restore'
      projects: '**/*.csproj'
  
  - task: AdvancedSecurity-Dependency-Scanning@1
    displayName: 'Dependency Scanning'
```

### NuGet Audit (.NET 8+)

```yaml
- task: DotNetCoreCLI@2
  displayName: 'NuGet Audit'
  inputs:
    command: 'custom'
    custom: 'restore'
    arguments: '--locked-mode'
  env:
    NuGetAudit: true
    NuGetAuditLevel: high

- task: Bash@3
  displayName: 'Check for vulnerable packages'
  inputs:
    targetType: 'inline'
    script: |
      dotnet list package --vulnerable --include-transitive 2>&1 | tee vuln-report.txt
      if grep -q "has the following vulnerable packages" vuln-report.txt; then
        echo "##vso[task.logissue type=error]Vulnerable packages detected"
        exit 1
      fi
```

### npm Audit

```yaml
- task: Npm@1
  displayName: 'npm Audit'
  inputs:
    command: 'custom'
    customCommand: 'audit --audit-level=high'
  continueOnError: false
```

### Snyk Integration

```yaml
- task: SnykSecurityScan@1
  displayName: 'Snyk Security Scan'
  inputs:
    serviceConnectionEndpoint: 'snyk-connection'
    testType: 'app'
    monitorOnBuild: true
    failOnIssues: true
    additionalArguments: '--severity-threshold=high'
```

---

## Secret Scanning

### Push Protection

When Advanced Security is enabled, push protection automatically blocks commits containing secrets.

### Repository Scanning

Secret scanning runs automatically in the background for:
- Azure subscription keys
- AWS access keys
- GitHub tokens
- Database connection strings
- API keys

### Gitleaks in Pipeline

```yaml
- task: Bash@3
  displayName: 'Gitleaks Scan'
  inputs:
    targetType: 'inline'
    script: |
      # Install Gitleaks
      wget -q https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.18.0_linux_x64.tar.gz
      tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
      
      # Run scan
      ./gitleaks detect --source . --verbose --report-format json --report-path gitleaks-report.json
      
      # Check results
      if [ -s gitleaks-report.json ]; then
        echo "##vso[task.logissue type=error]Secrets detected in repository"
        cat gitleaks-report.json
        exit 1
      fi
```

### TruffleHog Integration

```yaml
- task: Bash@3
  displayName: 'TruffleHog Scan'
  inputs:
    targetType: 'inline'
    script: |
      pip install trufflehog
      trufflehog git file://$(Build.SourcesDirectory) --json --no-update > trufflehog-results.json
      
      if [ -s trufflehog-results.json ]; then
        echo "##vso[task.logissue type=warning]Potential secrets found"
        cat trufflehog-results.json
      fi
```

---

## Container Scanning

### Trivy Container Scan

```yaml
- task: Bash@3
  displayName: 'Trivy Container Scan'
  inputs:
    targetType: 'inline'
    script: |
      # Install Trivy
      curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.50.0
      
      # Scan image
      trivy image \
        --format sarif \
        --output trivy-container.sarif \
        --severity HIGH,CRITICAL \
        --ignore-unfixed \
        $(containerRegistry)/$(imageRepository):$(Build.BuildId)
      
      # Fail on critical
      trivy image \
        --exit-code 1 \
        --severity CRITICAL \
        --ignore-unfixed \
        $(containerRegistry)/$(imageRepository):$(Build.BuildId)

- task: PublishBuildArtifacts@1
  displayName: 'Publish Container Scan Results'
  condition: always()
  inputs:
    pathToPublish: 'trivy-container.sarif'
    artifactName: 'CodeAnalysisLogs'
```

### Microsoft Defender for Containers

```yaml
- task: AzureCLI@2
  displayName: 'Defender Container Scan'
  inputs:
    azureSubscription: 'azure-subscription'
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
    inlineScript: |
      az acr task run \
        --registry $(containerRegistry) \
        --name defender-scan \
        --context /dev/null \
        --file /dev/stdin << EOF
      version: v1.1.0
      steps:
        - cmd: mcr.microsoft.com/azure-cli az acr import --name $(containerRegistry) --source docker.io/library/nginx:latest --image nginx:latest
      EOF
```

---

## IaC Scanning

### Terraform Scanning with Trivy

```yaml
- task: Bash@3
  displayName: 'Trivy IaC Scan'
  inputs:
    targetType: 'inline'
    script: |
      trivy config \
        --format sarif \
        --output trivy-iac.sarif \
        --severity HIGH,CRITICAL \
        ./infrastructure
```

### Checkov Integration

```yaml
- task: Bash@3
  displayName: 'Checkov IaC Scan'
  inputs:
    targetType: 'inline'
    script: |
      pip install checkov
      checkov -d ./infrastructure --output junitxml --output-file checkov-results.xml

- task: PublishTestResults@2
  displayName: 'Publish Checkov Results'
  inputs:
    testResultsFormat: 'JUnit'
    testResultsFiles: 'checkov-results.xml'
```

### ARM Template Analyzer

```yaml
- task: MicrosoftSecurityDevOps@1
  displayName: 'ARM Template Analysis'
  inputs:
    tools: 'templateanalyzer'
```

---

## Build Validation Policies

### Configure Branch Policies

1. Navigate to **Repos** > **Branches**
2. Select the branch (e.g., main) > **Branch policies**
3. Enable **Build validation**
4. Add the security pipeline as a required build
5. Set policy to **Required**

### Policy Configuration

```json
{
  "isEnabled": true,
  "isBlocking": true,
  "displayName": "Security Scan",
  "buildDefinitionId": "<pipeline-id>",
  "queueOnSourceUpdateOnly": true,
  "manualQueueOnly": false,
  "validDuration": 720
}
```

---

## SARIF Results Integration

### View Results in Azure DevOps

1. Install **SARIF SAST Scans Tab** extension from Marketplace
2. Publish results to `CodeAnalysisLogs` artifact
3. View in pipeline **Scans** tab

### Publish SARIF Files

```yaml
- task: PublishBuildArtifacts@1
  displayName: 'Publish SARIF Results'
  inputs:
    pathToPublish: '$(Build.SourcesDirectory)/*.sarif'
    artifactName: 'CodeAnalysisLogs'
```

---

## Scheduled Scanning

### Weekly Full Scan

```yaml
trigger: none

schedules:
  - cron: '0 2 * * 0'  # Sunday at 2 AM
    displayName: 'Weekly Security Scan'
    branches:
      include:
        - main
    always: true

pool:
  vmImage: 'ubuntu-latest'

jobs:
  - job: FullSecurityScan
    displayName: 'Full Security Scan'
    steps:
      - checkout: self
        fetchDepth: 0
      
      - task: Bash@3
        displayName: 'Comprehensive Trivy Scan'
        inputs:
          targetType: 'inline'
          script: |
            trivy fs --format json --output full-scan.json --severity HIGH,CRITICAL,MEDIUM .
      
      - task: PublishBuildArtifacts@1
        inputs:
          pathToPublish: 'full-scan.json'
          artifactName: 'weekly-scan-$(Build.BuildId)'
```

---

## Pipeline Templates

### Security Scan Template

Create `templates/security-scan.yml`:

```yaml
parameters:
  - name: scanType
    type: string
    default: 'fs'
  - name: severity
    type: string
    default: 'HIGH,CRITICAL'
  - name: failOnVulnerabilities
    type: boolean
    default: true

steps:
  - task: Bash@3
    displayName: 'Install Trivy'
    inputs:
      targetType: 'inline'
      script: |
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

  - task: Bash@3
    displayName: 'Run Security Scan'
    inputs:
      targetType: 'inline'
      script: |
        trivy ${{ parameters.scanType }} \
          --format sarif \
          --output trivy-results.sarif \
          --severity ${{ parameters.severity }} \
          ${{ if eq(parameters.failOnVulnerabilities, true) }}--exit-code 1${{ endif }} \
          .

  - task: PublishBuildArtifacts@1
    condition: always()
    inputs:
      pathToPublish: 'trivy-results.sarif'
      artifactName: 'CodeAnalysisLogs'
```

### Use Template

```yaml
jobs:
  - job: SecurityScan
    steps:
      - template: templates/security-scan.yml
        parameters:
          scanType: 'fs'
          severity: 'CRITICAL'
          failOnVulnerabilities: true
```

---

## Service Connections

### Create Security Tool Connections

For third-party tools (Snyk, SonarQube, etc.):

1. Navigate to **Project Settings** > **Service connections**
2. Click **New service connection**
3. Select the tool type
4. Enter credentials and endpoint URL
5. Grant access to pipelines

---

## Related Documentation

- [README.md](README.md) - Main tutorial
- [github-actions.md](github-actions.md) - GitHub Actions configuration
- [tools.md](tools.md) - Security tools reference
