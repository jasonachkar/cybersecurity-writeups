# Multi-Account Landing Zones and IAM at Scale

> Status: OUTLINE DRAFT – to be expanded with full research

## Executive Summary

This document covers how to design secure, scalable multi-account AWS environments using landing zones (AWS Control Tower or custom), with a focus on identity and access management, organizational unit (OU) design, and service control policies (SCPs). It is aimed at senior cloud security engineers who need to reason about blast radius, zero-trust boundaries, and guardrails across dozens or hundreds of accounts.

## 1. Why Multi-Account Architectures Matter

- Rationale for using multiple accounts for isolation, security, billing, and limits.
- Relationship between accounts, OUs, and workloads.
- How landing zones provide a baseline for multi-account IAM, networking, logging, and governance.

## 2. Landing Zone Building Blocks

- Shared accounts (management, log archive, audit) and their roles.
- Organizational units as containers for accounts and policy inheritance.
- Control Tower vs custom-built landing zones: trade-offs and when to choose each.

## 3. IAM at Scale

- Identity models for admins, developers, workloads, and automation.
- Cross-account access patterns (role assumption, resource-based policies).
- Least privilege and role design across environments (sandbox, dev, test, prod).

## 4. Service Control Policies and Guardrails

- SCP strategies (allow lists vs deny lists) and common guardrail patterns.
- Tag policies, backup policies, and other organization-level controls.
- Designing SCPs to be both safe and operationally manageable.

## 5. Network, Logging, and Detection

- High-level network segmentation patterns in multi-account setups.
- Centralized logging and monitoring via log archive and security accounts.
- How IAM and SCP design interacts with detection and response.

## 6. Operational Practices and Case Studies

- Typical failure modes in multi-account IAM and SCP design.
- Example scenarios illustrating good landing zone and guardrail designs.
