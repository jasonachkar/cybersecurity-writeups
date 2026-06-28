---
title: "Serverless Security: Function-Level IAM, Ephemeral Lifecycles, and Runtime Isolation"
type: cloud-security
tags: [Serverless, AWS Lambda, API Gateway, IAM, Application Security]
date: 2026-06
readingTime: 16
---

# Serverless Security: Function-Level IAM, Ephemeral Lifecycles, and Runtime Isolation

## Executive Summary

Serverless computing shifts the responsibility of server management, patch compliance, and operating system hardening to the cloud provider. However, this transfer of operational overhead does not eliminate application-level security risks. In fact, serverless introduces new attack vectors. Traditional security tools like host-based firewalls, network intrusion detection systems, and host agents cannot run in serverless environments. Security must therefore be implemented at the function level, focusing on identity, input validation, and runtime behavior.

A major failure mode in serverless architectures is overly broad IAM roles. Teams often reuse a single "catch-all" IAM execution role across hundreds of functions. This violates least privilege and allows an attacker who compromises one low-value function to pivot and access databases or secrets throughout the platform. Furthermore, developers often misunderstand the ephemeral lifecycle of functions, leading to security issues like the persistence of sensitive data in shared execution environments. This whitepaper explains the design patterns, execution lifecycles, and security controls needed to build secure serverless applications.

---

## Threat Model and Attack Surface

The serverless attack surface is characterized by highly distributed, event-driven entry points. The threat model assumes the adversary targets weak function permissions or exploits code vulnerabilities to compromise downstream services.

```
       [ Malicious Event Payload (e.g. S3 Metadata) ]
                            │
                            ▼
               [ Triggers Serverless Function ]
                            │
                ( Code Injection / Deserialization )
                            │
                            ▼
             [ Compromises Function Runtime ]
                            │
               ┌────────────┴────────────┐
               ▼                         ▼
      [ Queries local /tmp ]     [ Steals Execution IAM Role ]
               │                         │
               ▼                         ▼
      [ Extracts cached tokens ] [ Escalates via AWS API calls ]
```

### Threat Vectors and Kill-Chains

1. **Execution Context Reuse and /tmp Data Leakage**:
   - *Adversary Goal*: Extract secrets or PII cached from previous executions.
   - *Attack Vector*: AWS Lambda and Google Cloud Functions reuse execution environments (containers) across consecutive invocations to minimize cold starts. Files written to the `/tmp` directory persist between these invocations. An attacker exploits an input validation vulnerability (e.g. Local File Inclusion) in a function and reads files from `/tmp`, harvesting sensitive session keys or user data written by previous transactions.
2. **Privilege Escalation via Wildcard Function Execution Roles**:
   - *Adversary Goal*: Access backend databases or modify security configurations.
   - *Attack Vector*: A function responsible for converting images is compromised via a remote code execution vulnerability in an image parsing library. Because the function shares a broad IAM role with a database administration function, the attacker invokes AWS APIs (e.g., `dynamodb:Scan` or `secretsmanager:GetSecretValue`) directly from the function container to exfiltrate database records.
3. **Event Source Injection**:
   - *Adversary Goal*: Bypass API Gateway validation and execute unauthorized commands.
   - *Attack Vector*: An application trusts upstream event payloads (e.g., messages from SQS, SNS, or S3 bucket notifications) without validation. An attacker injects malicious commands into a filename in an S3 bucket. When the bucket notification triggers the function, the code passes the unvalidated filename to a shell command (e.g. `exec`), resulting in command injection.

---

## Deep Technical Body

### The Ephemeral Runtime Environment and Execution Context

To properly secure serverless functions, engineers must understand how cloud providers manage execution environments. When a function is first invoked, the provider initializes the runtime (the "cold start"). Subsequent invocations reuse this environment to avoid start-up latency (the "warm start").

#### The /tmp Directory Persistence Trap
Each execution environment includes a writable `/tmp` directory (typically up to 10GB in AWS Lambda). While this directory is useful for processing files, developers often treat it as private to a single execution. This is a critical security misunderstanding. If a function writes a temporary file containing decrypted data or a session token, that file remains in `/tmp` until the execution container is destroyed (which can take hours). 

#### Memory Scavenging
If the runtime process does not explicitly overwrite or clear variables in memory, sensitive data can persist in memory across invocations. An attacker who compromises the runtime can read the process memory of subsequent executions, leaking data from other users.

### Function-Level IAM and the Principle of Micro-Roles
In microservices architectures, each function must have its own dedicated IAM role. This limits the blast radius of a compromise. 

#### Unsafe: Shared Catch-All Role
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "dynamodb:PutItem",
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "*"
    }
  ]
}
```
If an attacker compromises a function using this policy, they gain broad access to all S3 buckets, DynamoDB tables, and secrets.

#### Safe: Dedicated Micro-Role
This policy restricts the function to a single S3 bucket and a specific DynamoDB table, strictly limiting the potential damage from a compromise.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::my-application-raw-uploads-prod/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem"
      ],
      "Resource": "arn:aws:dynamodb:us-west-2:123456789012:table/UserRegistrations"
    }
  ]
}
```

---

## Defensive Architecture

A secure serverless architecture relies on strict gateway validation, function-level isolation, and secure configuration management.

### Architecture Topology: Secure API Gateway to Serverless Integration

```
[ HTTP Request ] -> [ API Gateway (OIDC / JWT Auth Authorizer) ]
                          │
                          ▼
            [ Private VPC Link Integration ]
                          │
                          ▼
          [ AWS Lambda (Micro-IAM Execution Role) ]
                          │
      ┌───────────────────┼───────────────────┐
      ▼                   ▼                   ▼
[ S3 Uploads Bucket ]  [ DynamoDB Table ]  [ KMS (Decrypt Configs) ]
```

### Secure Configuration and Secrets Access Patterns
Do not store API keys or passwords directly in function environment variables, as these are visible in the AWS Management Console and via basic API queries (`lambda:GetFunctionConfiguration`). Instead, retrieve configuration settings from SSM Parameter Store or Secrets Manager dynamically, and decrypt them using customer-managed KMS keys.

#### Dynamic Retrieval Pattern (Go Example)
```go
package main

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

func GetSecureConfig(ctx context.Context, paramName string) (string, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", err
	}
	client := ssm.NewFromConfig(cfg)

	// Fetch parameter with decryption enabled
	input := &ssm.GetParameterInput{
		Name:           &paramName,
		WithDecryption: true,
	}

	result, err := client.GetParameter(ctx, input)
	if err != nil {
		return "", err
	}
	return *result.Parameter.Value, nil
}
```

---

## Tooling and Implementation

Deploy specialized serverless auditing and protection tools to monitor function behavior and code dependencies:

1. **Snyk / Aqua Security (tfsec/checkov)**: Use these static analysis tools to verify that Infrastructure-as-Code (IaC) templates (Terraform, Serverless Framework, AWS SAM) enforce least privilege IAM policies and restrict API Gateway endpoints.
2. **AWS Lambda Layers / Runtime Security Agents**: Integrate application security tools directly into the function runtime using AWS Lambda Layers. These tools monitor system calls and network traffic in real time, detecting anomalies like unauthorized network requests or attempts to run processes in `/tmp`.
3. **API Gateway WAF Integration**: Always configure a Web Application Firewall (WAF) in front of API Gateway. This blocks common application-layer attacks (SQL injection, cross-site scripting) before they reach the backend functions.

---

## Serverless Security Audit Checklist

| Item | Focus Area | Verification Step / Command | Target State |
| :--- | :--- | :--- | :--- |
| 1 | IAM Role Isolation | Check if multiple functions share the same IAM execution role. | Each function has a unique IAM role tailored to its specific requirements. |
| 2 | Environment Secrets | Audit function configuration files for hardcoded passwords or API keys. | All secrets are stored in Secrets Manager or SSM Parameter Store and retrieved dynamically. |
| 3 | Execution Environment | Verify that functions clean up sensitive data write operations. | Functions explicitly delete files in the `/tmp` directory before returning. |
| 4 | API Authorization | Inspect API Gateway configurations to ensure endpoints require authorization. | All public APIs route through Cognito, OIDC Authorizers, or API Key validators. |
| 5 | Egress VPC Isolation | Verify that functions requiring internal database access run within a private VPC subnet. | Functions run inside private subnets and use VPC endpoints for AWS service communications. |
| 6 | Timeout Policies | Check function timeout settings. | Timeout values are set to the minimum time required for successful execution, preventing denial-of-service bill inflation. |

---

## References

* *AWS Lambda Security Guidelines*: [AWS Documentation](https://docs.aws.amazon.com/lambda/latest/dg/security-best-practices.html)
* *OWASP Serverless Top 10 Project*: [OWASP Website](https://owasp.org/www-project-serverless-top-10/)
* *NIST Special Publication 800-204D (Functional Security in Microservices)*: [NIST SP 800-204D](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204D.pdf)
