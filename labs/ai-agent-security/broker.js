#!/usr/bin/env node
"use strict";

/**
 * Tested teaching implementation for labs/ai-agent-security.
 *
 * This broker receives authenticated context separately from the model-proposed
 * call. It demonstrates deterministic authorization; it does not validate
 * identity tokens, make network requests, or issue real credentials.
 */

class BrokerDenied extends Error {
  constructor(code, message) {
    super(message);
    this.name = "BrokerDenied";
    this.code = code;
  }
}

function deny(code, message) {
  throw new BrokerDenied(code, message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireRecord(value, code, label) {
  if (!isRecord(value)) deny(code, `${label} must be an object`);
  return value;
}

function requireIdentifier(value, code, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 128) {
    deny(code, `${label} must be a nonempty string of at most 128 characters`);
  }
  return value;
}

function requireSafePositiveInteger(value, code, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    deny(code, `${label} must be a positive safe integer`);
  }
  return value;
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function safeAuditMetadata(authenticatedContext, proposedCall) {
  const args = isRecord(proposedCall?.arguments) ? proposedCall.arguments : {};
  return {
    principalId:
      typeof authenticatedContext?.principalId === "string"
        ? authenticatedContext.principalId
        : "<invalid>",
    tenantId:
      typeof proposedCall?.tenantId === "string"
        ? proposedCall.tenantId
        : "<invalid>",
    tool:
      typeof proposedCall?.tool === "string" ? proposedCall.tool : "<invalid>",
    amountCents:
      Number.isSafeInteger(args.amountCents) ? args.amountCents : null,
    destinationRef:
      typeof args.destinationRef === "string"
        ? args.destinationRef
        : "<invalid>",
  };
}

class ToolBroker {
  #approvalVerifier;
  #audit;
  #clock;
  #consumedApprovalIds = new Set();
  #executor;
  #isExecutionEnabled;
  #policy;

  constructor({
    policy,
    approvalVerifier,
    executor,
    isExecutionEnabled = () => true,
    audit = () => {},
    clock = () => Date.now(),
  }) {
    if (!isRecord(policy) || !isRecord(policy.principals)) {
      throw new TypeError("policy.principals must be an object");
    }
    if (typeof approvalVerifier !== "function") {
      throw new TypeError("approvalVerifier must be a function");
    }
    if (typeof executor !== "function") {
      throw new TypeError("executor must be a function");
    }
    if (typeof isExecutionEnabled !== "function") {
      throw new TypeError("isExecutionEnabled must be a function");
    }
    if (typeof audit !== "function") {
      throw new TypeError("audit must be a function");
    }
    if (typeof clock !== "function") {
      throw new TypeError("clock must be a function");
    }

    this.#policy = policy;
    this.#approvalVerifier = approvalVerifier;
    this.#executor = executor;
    this.#isExecutionEnabled = isExecutionEnabled;
    this.#audit = audit;
    this.#clock = clock;
  }

  async execute(authenticatedContext, proposedCall, approvalEvidence = null) {
    const auditMetadata = safeAuditMetadata(authenticatedContext, proposedCall);

    try {
      const authorizedCall = await this.#authorize(
        authenticatedContext,
        proposedCall,
        approvalEvidence,
      );

      // A production high-impact path should fail closed if this durable audit
      // decision cannot be recorded. This lab's injected audit sink is in-memory.
      this.#audit({
        event: "authorization_decision",
        outcome: "allow",
        reason: "POLICY_ALLOWED",
        ...auditMetadata,
        approvalId: authorizedCall.approvalId,
      });

      try {
        const result = await this.#executor(authorizedCall);
        this.#audit({
          event: "execution_outcome",
          outcome: "success",
          ...auditMetadata,
          approvalId: authorizedCall.approvalId,
        });
        return result;
      } catch (error) {
        this.#audit({
          event: "execution_outcome",
          outcome: "failure",
          reason: "EXECUTOR_FAILED",
          ...auditMetadata,
          approvalId: authorizedCall.approvalId,
        });
        throw error;
      }
    } catch (error) {
      if (error instanceof BrokerDenied) {
        this.#audit({
          event: "authorization_decision",
          outcome: "deny",
          reason: error.code,
          ...auditMetadata,
          approvalId:
            isRecord(approvalEvidence) &&
            typeof approvalEvidence.id === "string"
              ? approvalEvidence.id
              : null,
        });
      }
      throw error;
    }
  }

  async #authorize(authenticatedContext, proposedCall, approvalEvidence) {
    const context = requireRecord(
      authenticatedContext,
      "INVALID_CONTEXT",
      "authenticatedContext",
    );
    const principalId = requireIdentifier(
      context.principalId,
      "INVALID_CONTEXT",
      "authenticatedContext.principalId",
    );

    const call = requireRecord(
      proposedCall,
      "INVALID_CALL",
      "proposedCall",
    );
    const tenantId = requireIdentifier(
      call.tenantId,
      "INVALID_CALL",
      "proposedCall.tenantId",
    );
    const tool = requireIdentifier(
      call.tool,
      "INVALID_CALL",
      "proposedCall.tool",
    );
    const args = requireRecord(
      call.arguments,
      "INVALID_ARGUMENTS",
      "proposedCall.arguments",
    );

    const allowedArgumentNames = new Set([
      "amountCents",
      "destinationRef",
    ]);
    for (const argumentName of Object.keys(args)) {
      if (!allowedArgumentNames.has(argumentName)) {
        deny(
          "UNKNOWN_ARGUMENT",
          `argument ${argumentName} is not in the closed schema`,
        );
      }
    }

    const amountCents = requireSafePositiveInteger(
      args.amountCents,
      "INVALID_AMOUNT",
      "proposedCall.arguments.amountCents",
    );
    const destinationRef = requireIdentifier(
      args.destinationRef,
      "INVALID_DESTINATION",
      "proposedCall.arguments.destinationRef",
    );

    const executionEnabled = await this.#isExecutionEnabled({
      principalId,
      tenantId,
      tool,
    });
    if (executionEnabled !== true) {
      deny("EXECUTION_DISABLED", "the execution kill switch is active");
    }

    if (!hasOwn(this.#policy.principals, principalId)) {
      deny("UNAUTHORIZED_PRINCIPAL", "principal is not registered");
    }
    const principalPolicy = requireRecord(
      this.#policy.principals[principalId],
      "INVALID_POLICY",
      "principal policy",
    );

    if (
      !Array.isArray(principalPolicy.tenants) ||
      !principalPolicy.tenants.includes(tenantId)
    ) {
      deny("UNAUTHORIZED_TENANT", "principal cannot act for this tenant");
    }

    if (!isRecord(principalPolicy.tools) || !hasOwn(principalPolicy.tools, tool)) {
      deny("UNAUTHORIZED_TOOL", "tool is not allowed for this principal");
    }
    const toolPolicy = requireRecord(
      principalPolicy.tools[tool],
      "INVALID_POLICY",
      "tool policy",
    );

    const maxAmountCents = requireSafePositiveInteger(
      toolPolicy.maxAmountCents,
      "INVALID_POLICY",
      "tool policy maxAmountCents",
    );
    const approvalRequiredAtCents = requireSafePositiveInteger(
      toolPolicy.approvalRequiredAtCents,
      "INVALID_POLICY",
      "tool policy approvalRequiredAtCents",
    );
    if (approvalRequiredAtCents > maxAmountCents) {
      deny(
        "INVALID_POLICY",
        "approval threshold cannot exceed the maximum amount",
      );
    }

    if (amountCents > maxAmountCents) {
      deny("AMOUNT_EXCEEDS_POLICY", "amount exceeds the policy maximum");
    }

    if (
      !Array.isArray(toolPolicy.allowedDestinationRefs) ||
      !toolPolicy.allowedDestinationRefs.includes(destinationRef)
    ) {
      deny(
        "UNAUTHORIZED_DESTINATION",
        "destination is not allowed by policy",
      );
    }

    let approvalId = null;
    if (amountCents >= approvalRequiredAtCents) {
      const evidence = requireRecord(
        approvalEvidence,
        "APPROVAL_REQUIRED",
        "approvalEvidence",
      );
      approvalId = requireIdentifier(
        evidence.id,
        "INVALID_APPROVAL",
        "approvalEvidence.id",
      );

      if (this.#consumedApprovalIds.has(approvalId)) {
        deny("APPROVAL_REPLAYED", "approval has already been consumed");
      }

      const approval = await this.#approvalVerifier({ id: approvalId });
      if (!isRecord(approval) || approval.decision !== "approved") {
        deny("INVALID_APPROVAL", "approval service did not approve the action");
      }
      if (approval.id !== approvalId) {
        deny("INVALID_APPROVAL", "approval identifier does not match");
      }
      if (
        !Number.isSafeInteger(approval.expiresAtMs) ||
        approval.expiresAtMs <= this.#clock()
      ) {
        deny("APPROVAL_EXPIRED", "approval has expired");
      }

      const expectedBinding = {
        principalId,
        tenantId,
        tool,
        amountCents,
        destinationRef,
      };
      for (const [field, expectedValue] of Object.entries(expectedBinding)) {
        if (approval[field] !== expectedValue) {
          deny(
            "APPROVAL_SCOPE_MISMATCH",
            `approval is not bound to the requested ${field}`,
          );
        }
      }

      // Consume before invoking the executor. If execution becomes uncertain,
      // production systems should reconcile by idempotency key before retrying.
      this.#consumedApprovalIds.add(approvalId);
    }

    return Object.freeze({
      principalId,
      tenantId,
      tool,
      arguments: Object.freeze({
        amountCents,
        destinationRef,
      }),
      approvalId,
    });
  }
}

module.exports = {
  BrokerDenied,
  ToolBroker,
};
