"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {
  STAGES,
  evaluateAwsAssumeRole,
  evaluateAwsWebIdentity,
  evaluateAzureFederation,
  permissionIsAllowed,
  policyDecision,
} = require("../evaluator");

const lab = path.resolve(__dirname, "..");
const fixturesDirectory = path.join(lab, "fixtures");
const policiesDirectory = path.join(lab, "policies");
let evaluationCount = 0;

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function fixture(name) {
  return readJson(path.join(fixturesDirectory, name));
}

function policy(name) {
  return readJson(path.join(policiesDirectory, name));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function setPath(target, dottedPath, value) {
  const segments = dottedPath.split(".");
  let cursor = target;
  for (const segment of segments.slice(0, -1)) {
    assert.notEqual(cursor[segment], undefined, `Unknown mutation path: ${dottedPath}`);
    cursor = cursor[segment];
  }
  cursor[segments.at(-1)] = value;
}

function applyMutations(target, mutations) {
  for (const [dottedPath, value] of Object.entries(mutations)) {
    setPath(target, dottedPath, value);
  }
}

function hydratePermissionSet(permissionSet) {
  if (!permissionSet) {
    return permissionSet;
  }
  permissionSet.identityPolicies = (permissionSet.identityPolicies || []).map((item) =>
    typeof item === "string" ? policy(item) : item,
  );
  if (typeof permissionSet.boundary === "string") {
    permissionSet.boundary = policy(permissionSet.boundary);
  }
  return permissionSet;
}

function expectStage(name, actual, expected) {
  evaluationCount += 1;
  assert.equal(
    actual.stage,
    expected,
    `${name}: expected ${expected}, got ${actual.stage} (${actual.reason})`,
  );
}

function runAwsWebIdentityFixture(document) {
  const scenarios = document.scenarios || [document];
  for (const scenario of scenarios) {
    for (const testCase of scenario.cases) {
      const input = clone(scenario.base);
      input.trustPolicy = policy(scenario.trustPolicy);
      hydratePermissionSet(input.permissionSet);
      applyMutations(input, testCase.mutations);
      expectStage(
        `${scenario.name || scenario.trustPolicy}: ${testCase.name}`,
        evaluateAwsWebIdentity(input),
        testCase.expectedStage,
      );
    }
  }
}

function runAzureFixture(document) {
  for (const testCase of document.cases) {
    const input = clone(document.base);
    input.federatedCredential = policy(document.federatedCredential);
    applyMutations(input, testCase.mutations);
    expectStage(
      testCase.name,
      evaluateAzureFederation(input),
      testCase.expectedStage,
    );
  }
}

function runAssumeRoleFixture(document) {
  for (const testCase of document.cases) {
    const input = clone(document.base);
    input.trustPolicy = policy(document.trustPolicy);
    hydratePermissionSet(input.permissionSet);
    applyMutations(input, testCase.mutations);
    expectStage(
      testCase.name,
      evaluateAwsAssumeRole(input),
      testCase.expectedStage,
    );
  }
}

function runAuthorizationFixture(document) {
  const identityPolicy = policy(document.identityPolicy);
  for (const testCase of document.cases) {
    evaluationCount += 1;
    assert.equal(
      permissionIsAllowed([identityPolicy], null, testCase.request),
      testCase.expectedAllowed,
      testCase.name,
    );
  }
}

function assertPolicyDocument(document, name) {
  assert.equal(document.Version, "2012-10-17", `${name}: policy version`);
  assert.ok(Array.isArray(document.Statement), `${name}: Statement must be an array`);
  assert.ok(document.Statement.length > 0, `${name}: Statement must not be empty`);
}

function runStructuralTests() {
  const policyFiles = fs.readdirSync(policiesDirectory)
    .filter((name) => name.endsWith(".json") && name !== "azure-github-federated-credential.json");
  for (const name of policyFiles) {
    assertPolicyDocument(policy(name), name);
  }

  const githubMain = policy("aws-github-main-trust.json").Statement[0];
  const githubEnvironment = policy("aws-github-production-trust.json").Statement[0];
  for (const statement of [githubMain, githubEnvironment]) {
    assert.equal(statement.Action, "sts:AssumeRoleWithWebIdentity");
    assert.equal(
      statement.Principal.Federated,
      "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com",
    );
    const conditions = statement.Condition.StringEquals;
    assert.equal(conditions["token.actions.githubusercontent.com:aud"], "sts.amazonaws.com");
    assert.doesNotMatch(conditions["token.actions.githubusercontent.com:sub"], /[*?]/);
  }
  assert.equal(
    githubMain.Condition.StringEquals["token.actions.githubusercontent.com:sub"],
    "repo:example-security/cloud-controls:ref:refs/heads/main",
  );
  assert.equal(
    githubEnvironment.Condition.StringEquals["token.actions.githubusercontent.com:sub"],
    "repo:example-security/cloud-controls:environment:production",
  );

  const azureCredential = policy("azure-github-federated-credential.json");
  assert.equal(azureCredential.issuer, "https://token.actions.githubusercontent.com");
  assert.equal(
    azureCredential.subject,
    "repo:example-security/cloud-controls:environment:production",
  );
  assert.deepEqual(azureCredential.audiences, ["api://AzureADTokenExchange"]);

  const irsa = policy("eks-irsa-trust.json").Statement[0];
  assert.equal(irsa.Action, "sts:AssumeRoleWithWebIdentity");
  assert.equal(
    irsa.Condition.StringEquals[
      "oidc.eks.ca-central-1.amazonaws.com/id/EXAMPLECLUSTERID:sub"
    ],
    "system:serviceaccount:payments:reconciler",
  );
  assert.equal(
    irsa.Condition.StringEquals[
      "oidc.eks.ca-central-1.amazonaws.com/id/EXAMPLECLUSTERID:aud"
    ],
    "sts.amazonaws.com",
  );

  const thirdParty = policy("third-party-trust.json");
  const externalId =
    thirdParty.Statement[0].Condition.StringEquals["sts:ExternalId"];
  assert.equal(
    externalId,
    "example-tenant-a-7a7a7a7a-0000-4000-8000-000000000000",
  );
  assert.match(externalId, /^[\w+=,.@:\/-]{2,1224}$/);
  assert.equal(thirdParty.Statement[1].Action, "sts:TagSession");
  assert.deepEqual(
    thirdParty.Statement[1].Condition["ForAllValues:StringEquals"]["aws:TagKeys"],
    ["tenant-id", "workload"],
  );

  const delegated = policy("delegated-role-admin.json");
  const create = delegated.Statement.find((statement) =>
    statement.Sid === "CreateDelegatedRoleOnlyWithApprovedBoundary");
  assert.equal(
    create.Condition.ArnEquals["iam:PermissionsBoundary"],
    "arn:aws:iam::111122223333:policy/DelegatedWorkloadBoundary",
  );
  const boundaryDeny = delegated.Statement.find((statement) =>
    statement.Sid === "DenyBoundaryRemovalOrReplacement");
  assert.equal(boundaryDeny.Effect, "Deny");
  assert.deepEqual(
    new Set(boundaryDeny.Action),
    new Set(["iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary"]),
  );

  const passRole = policy("restricted-passrole.json").Statement[0];
  assert.equal(passRole.Action, "iam:PassRole");
  assert.equal(
    passRole.Resource,
    "arn:aws:iam::111122223333:role/service/ecs/payments-task",
  );
  assert.equal(
    passRole.Condition.StringEquals["iam:PassedToService"],
    "ecs-tasks.amazonaws.com",
  );
  assert.equal(
    policyDecision(policy("ecs-payments-task-trust.json"), {
      action: "sts:AssumeRole",
      principal: { type: "Service", value: "ecs-tasks.amazonaws.com" },
      context: {},
    }),
    "allowed",
    "The destination role must trust the service that receives it.",
  );
}

runStructuralTests();
runAwsWebIdentityFixture(fixture("github-oidc.json"));
runAzureFixture(fixture("azure-federation.json"));
runAwsWebIdentityFixture(fixture("eks-irsa.json"));
runAssumeRoleFixture(fixture("third-party-assume-role.json"));
runAuthorizationFixture(fixture("permission-boundary.json"));
runAuthorizationFixture(fixture("passrole.json"));

const requiredStages = new Set(Object.values(STAGES));
const githubStages = new Set(
  fixture("github-oidc.json").scenarios.flatMap((scenario) =>
    scenario.cases.map((testCase) => testCase.expectedStage),
  ),
);
assert.deepEqual(
  githubStages,
  requiredStages,
  "GitHub OIDC fixtures must preserve all four rejection/authorization stages.",
);

console.log(
  `PASS: ${evaluationCount} IAM/OIDC structural and policy-model evaluations completed.`,
);
