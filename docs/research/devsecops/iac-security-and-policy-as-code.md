# IaC Security and Policy-as-Code

> Status: OUTLINE DRAFT – to be expanded with full research

## Executive Summary

This document covers secure design and operation of infrastructure-as-code (IaC) workflows and policy-as-code guardrails in cloud environments. It focuses on Terraform and similar tools, organizational policies, drift detection, and how NIST SP 800-204D and modern DevSecOps guidance recommend integrating IaC and policy controls into secure CI/CD pipelines.

## 1. IaC Threat Model

- Risks inherent to IaC (mass misconfiguration, environment-wide changes, embedded secrets).
- Attack paths via compromised IaC repositories, modules, or registries.
- Relationship between IaC threats and CI/CD pipeline compromise.

## 2. Secure IaC Authoring and Review

- Patterns for modular, reusable IaC with least privilege.
- Change management and review processes for IaC repositories.
- Using threat modeling and policy baselines when designing new IaC.

## 3. Policy-as-Code Guardrails

- Tools and frameworks (e.g., OPA, Conftest, Sentinel, Terraform Cloud/Enterprise policies).
- Organizational controls (landing zones, baseline policies, multi-account/multi-project structures).
- Integration of policy checks into CI/CD pipelines.

## 4. Drift Detection and Continuous Compliance

- Detecting and managing configuration drift between IaC and runtime environments.
- Continuous compliance scanning and remediation workflows.

## 5. Operational Practices and Case Studies

- Common failure modes in IaC security and how to avoid them.
- Example scenarios where policy-as-code and drift detection prevented incidents.
