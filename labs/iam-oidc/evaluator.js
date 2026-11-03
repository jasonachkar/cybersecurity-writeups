"use strict";

const STAGES = Object.freeze({
  SIGNATURE_INVALID: "SIGNATURE_INVALID",
  CLAIMS_REJECTED: "CLAIMS_REJECTED",
  TRUST_POLICY_REJECTED: "TRUST_POLICY_REJECTED",
  PERMISSIONS_DENIED: "PERMISSIONS_DENIED",
  AUTHORIZED: "AUTHORIZED",
});

function asArray(value) {
  if (value === undefined || value === null) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

function globMatches(pattern, value) {
  const escaped = String(pattern)
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`).test(String(value));
}

function anyPatternMatches(patterns, value) {
  return asArray(patterns).some((pattern) => globMatches(pattern, value));
}

function principalMatches(expectedPrincipal, actualPrincipal) {
  if (expectedPrincipal === undefined) {
    return true;
  }
  if (!actualPrincipal) {
    return false;
  }
  if (typeof expectedPrincipal === "string") {
    return anyPatternMatches(expectedPrincipal, actualPrincipal.value);
  }
  const expected = expectedPrincipal[actualPrincipal.type];
  return expected !== undefined && anyPatternMatches(expected, actualPrincipal.value);
}

function valuesEqual(actual, expected) {
  const actualValues = asArray(actual).map(String);
  const expectedValues = asArray(expected).map(String);
  return actualValues.some((value) => expectedValues.includes(value));
}

function valuesLike(actual, expected) {
  const actualValues = asArray(actual);
  const expectedValues = asArray(expected);
  return actualValues.some((value) =>
    expectedValues.some((pattern) => globMatches(pattern, value)),
  );
}

function conditionBlockMatches(operator, entries, context) {
  return Object.entries(entries).every(([key, expected]) => {
    const actual = context[key];

    switch (operator) {
      case "StringEquals":
      case "ArnEquals":
        return valuesEqual(actual, expected);
      case "StringLike":
      case "ArnLike":
        return valuesLike(actual, expected);
      case "ForAllValues:StringEquals": {
        const actualValues = asArray(actual);
        const expectedValues = asArray(expected).map(String);
        return actualValues.length > 0 &&
          actualValues.every((value) => expectedValues.includes(String(value)));
      }
      case "Null": {
        const isNull = actual === undefined || actual === null;
        return String(isNull) === String(expected).toLowerCase();
      }
      default:
        throw new Error(`Unsupported condition operator in lab model: ${operator}`);
    }
  });
}

function conditionsMatch(conditions = {}, context = {}) {
  return Object.entries(conditions).every(([operator, entries]) =>
    conditionBlockMatches(operator, entries, context),
  );
}

function statementMatches(statement, request) {
  const actionMatches = anyPatternMatches(statement.Action, request.action);
  const resourceMatches = statement.Resource === undefined ||
    anyPatternMatches(statement.Resource, request.resource || "*");

  return actionMatches &&
    resourceMatches &&
    principalMatches(statement.Principal, request.principal) &&
    conditionsMatch(statement.Condition, request.context);
}

function policyDecision(policy, request) {
  const matching = asArray(policy.Statement).filter((statement) =>
    statementMatches(statement, request),
  );
  if (matching.some((statement) => statement.Effect === "Deny")) {
    return "explicitDeny";
  }
  if (matching.some((statement) => statement.Effect === "Allow")) {
    return "allowed";
  }
  return "implicitDeny";
}

function permissionIsAllowed(identityPolicies, boundary, request) {
  const identityDecisions = asArray(identityPolicies).map((policy) =>
    policyDecision(policy, request),
  );
  if (identityDecisions.includes("explicitDeny")) {
    return false;
  }
  if (!identityDecisions.includes("allowed")) {
    return false;
  }
  if (!boundary) {
    return true;
  }
  return policyDecision(boundary, request) === "allowed";
}

function tokenAudienceMatches(actual, expected) {
  return asArray(actual).map(String).includes(String(expected));
}

function validateToken(token, requirements) {
  if (token.signatureVerified !== true) {
    return {
      stage: STAGES.SIGNATURE_INVALID,
      reason: "The external cryptographic-verifier boundary did not authenticate the token signature.",
    };
  }

  const now = requirements.now;
  const claimsValid =
    token.issuer === requirements.expectedIssuer &&
    tokenAudienceMatches(token.audience, requirements.expectedAudience) &&
    Number.isFinite(token.notBefore) &&
    Number.isFinite(token.expiresAt) &&
    token.notBefore <= now &&
    token.expiresAt > now;

  if (!claimsValid) {
    return {
      stage: STAGES.CLAIMS_REJECTED,
      reason: "The authenticated token failed issuer, audience, or lifetime validation.",
    };
  }

  return null;
}

function permissionStage(permissionSet) {
  if (!permissionSet) {
    return { stage: STAGES.AUTHORIZED, reason: "Trust was accepted; no post-assumption API was modeled." };
  }

  const allowed = permissionIsAllowed(
    permissionSet.identityPolicies,
    permissionSet.boundary,
    permissionSet.request,
  );
  return allowed
    ? { stage: STAGES.AUTHORIZED, reason: "Trust and the modeled post-assumption authorization both allowed the request." }
    : { stage: STAGES.PERMISSIONS_DENIED, reason: "The role session exists, but effective permissions denied the requested API." };
}

function evaluateAwsWebIdentity(scenario) {
  const tokenFailure = validateToken(scenario.token, scenario.claimRequirements);
  if (tokenFailure) {
    return tokenFailure;
  }

  const prefix = scenario.claimRequirements.conditionPrefix;
  const trustRequest = {
    action: "sts:AssumeRoleWithWebIdentity",
    principal: {
      type: "Federated",
      value: scenario.providerArn,
    },
    context: {
      [`${prefix}:aud`]: scenario.token.audience,
      [`${prefix}:sub`]: scenario.token.subject,
    },
  };

  if (policyDecision(scenario.trustPolicy, trustRequest) !== "allowed") {
    return {
      stage: STAGES.TRUST_POLICY_REJECTED,
      reason: "The token claims were authentic and protocol-valid, but the role trust policy did not authorize this principal/subject.",
    };
  }

  return permissionStage(scenario.permissionSet);
}

function evaluateAzureFederation(scenario) {
  const tokenFailure = validateToken(scenario.token, scenario.claimRequirements);
  if (tokenFailure) {
    return tokenFailure;
  }

  const credential = scenario.federatedCredential;
  const trustMatches =
    credential.issuer === scenario.token.issuer &&
    credential.subject === scenario.token.subject &&
    asArray(credential.audiences).length === 1 &&
    tokenAudienceMatches(scenario.token.audience, credential.audiences[0]);

  if (!trustMatches) {
    return {
      stage: STAGES.TRUST_POLICY_REJECTED,
      reason: "The token was protocol-valid, but it did not exactly match the configured federated credential.",
    };
  }

  const request = scenario.permissionSet.request;
  const actionAllowed = asArray(scenario.permissionSet.allowedActions).some((action) =>
    globMatches(action, request.action),
  );
  const scopeAllowed = asArray(scenario.permissionSet.allowedScopes).some((scope) =>
    globMatches(scope, request.scope),
  );

  return actionAllowed && scopeAllowed
    ? { stage: STAGES.AUTHORIZED, reason: "Token exchange trust and the modeled Azure authorization both allowed the request." }
    : { stage: STAGES.PERMISSIONS_DENIED, reason: "Token exchange succeeded, but the modeled Azure authorization denied the request." };
}

function evaluateAwsAssumeRole(scenario) {
  if (scenario.callerAuthenticated !== true) {
    return {
      stage: STAGES.SIGNATURE_INVALID,
      reason: "The fixture boundary did not authenticate the calling AWS principal.",
    };
  }

  const context = {
    "sts:ExternalId": scenario.externalId,
    "aws:TagKeys": Object.keys(scenario.sessionTags || {}),
  };
  for (const [key, value] of Object.entries(scenario.sessionTags || {})) {
    context[`aws:RequestTag/${key}`] = value;
  }

  const baseRequest = {
    principal: {
      type: "AWS",
      value: scenario.principalArn,
    },
    context,
  };

  const assumeAllowed = policyDecision(scenario.trustPolicy, {
    ...baseRequest,
    action: "sts:AssumeRole",
  }) === "allowed";
  const tagsAllowed = Object.keys(scenario.sessionTags || {}).length === 0 ||
    policyDecision(scenario.trustPolicy, {
      ...baseRequest,
      action: "sts:TagSession",
    }) === "allowed";

  if (!assumeAllowed || !tagsAllowed) {
    return {
      stage: STAGES.TRUST_POLICY_REJECTED,
      reason: "The caller, external ID, or requested session tags failed role-trust authorization.",
    };
  }

  return permissionStage(scenario.permissionSet);
}

module.exports = {
  STAGES,
  evaluateAwsAssumeRole,
  evaluateAwsWebIdentity,
  evaluateAzureFederation,
  permissionIsAllowed,
  policyDecision,
};
