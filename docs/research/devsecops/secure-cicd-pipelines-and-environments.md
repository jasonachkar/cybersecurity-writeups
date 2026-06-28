# Secure CI/CD Pipelines and Environments

> Status: OUTLINE DRAFT – to be expanded with full research

## Executive Summary

This document outlines strategies for designing and operating secure CI/CD pipelines and their execution environments, with a focus on integrating software supply chain security controls (SBOM, signing, provenance) in line with NIST SP 800-204D and related guidance.

## 1. Pipeline Threat Model

- Goals of an attacker (secrets theft, artifact tampering, bypassing controls).
- Assets: SCM, build system, artifact registry, deployment systems, credentials, policies.
- Typical attack paths across stages (from SCM compromise to production code execution).

## 2. Secure CI/CD Design Patterns

- Identity and access for pipelines (workload identities, short-lived credentials).
- Segregation of environments and stages (build, test, staging, prod).
- Hardening build agents/runners and isolating jobs.
- Policy gates (SAST, DAST, IaC scanning, license checks) as mandatory stages.

## 3. Software Supply Chain Security Controls

- SBOM generation and management.
- Artifact signing and verification (e.g., Sigstore/cosign).
- Provenance (SLSA levels, build integrity, and tamper evidence).

## 4. Operational Practices

- Monitoring pipeline events and anomalies.
- Incident response playbooks for pipeline compromise.
- Continual improvement and feedback loops between runtime findings and pipeline policies.
