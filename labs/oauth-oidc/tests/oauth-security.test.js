"use strict";

const assert = require("node:assert/strict");
const { generateKeyPairSync } = require("node:crypto");
const {
  TokenValidationError,
  createExactRedirectMatcher,
  signJwt,
  validateAccessToken,
} = require("../oauth-security");

const NOW = 2_000_000_000;
const ISSUER = "https://issuer.example.test";
const AUDIENCE = "api://payments";
const TENANT = "tenant-blue";
const KID_OLD = "issuer-key-2026-01";
const KID_NEW = "issuer-key-2026-07";

const oldKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const newKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const attackerKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });

const baselineClaims = Object.freeze({
  aud: AUDIENCE,
  exp: NOW + 300,
  iss: ISSUER,
  nbf: NOW - 30,
  scope: "payments.read payments.refund",
  sub: "user-42",
  tid: TENANT,
});

function token(overrides = {}, signing = {}) {
  return signJwt(
    { ...baselineClaims, ...overrides },
    {
      privateKey: signing.privateKey ?? oldKeys.privateKey,
      kid: signing.kid ?? KID_OLD,
    },
  );
}

function config(overrides = {}) {
  return {
    audience: AUDIENCE,
    clockSkewSeconds: 0,
    issuer: ISSUER,
    now: NOW,
    requiredScopes: ["payments.read"],
    tenant: TENANT,
    trustedKeys: new Map([[KID_OLD, oldKeys.publicKey]]),
    ...overrides,
  };
}

function expectCode(expectedCode, operation) {
  assert.throws(
    operation,
    (error) =>
      error instanceof TokenValidationError && error.code === expectedCode,
    `expected ${expectedCode}`,
  );
}

const tests = [];
function test(name, operation) {
  tests.push({ name, operation });
}

test("accepts a correctly signed token with the configured security context", () => {
  const principal = validateAccessToken(token(), config());
  assert.deepEqual(
    principal,
    {
      issuer: ISSUER,
      scopes: ["payments.read", "payments.refund"],
      subject: "user-42",
      tenant: TENANT,
    },
  );
});

test("rejects a token signed by an attacker under a trusted kid", () => {
  const forged = token({}, { privateKey: attackerKeys.privateKey, kid: KID_OLD });
  expectCode("INVALID_SIGNATURE", () => validateAccessToken(forged, config()));
});

test("rejects the wrong issuer even when the signature is trusted", () => {
  expectCode(
    "INVALID_ISSUER",
    () => validateAccessToken(token({ iss: "https://other.example.test" }), config()),
  );
});

test("rejects the wrong audience", () => {
  expectCode(
    "INVALID_AUDIENCE",
    () => validateAccessToken(token({ aud: "api://inventory" }), config()),
  );
});

test("accepts the configured audience in an audience array", () => {
  const principal = validateAccessToken(
    token({ aud: ["api://reports", AUDIENCE] }),
    config(),
  );
  assert.equal(principal.subject, "user-42");
});

test("rejects an expired token at the exp boundary", () => {
  expectCode(
    "TOKEN_EXPIRED",
    () => validateAccessToken(token({ exp: NOW }), config()),
  );
});

test("rejects a token whose not-before time is in the future", () => {
  expectCode(
    "TOKEN_NOT_ACTIVE",
    () => validateAccessToken(token({ nbf: NOW + 1 }), config()),
  );
});

test("rejects a token from the wrong tenant", () => {
  expectCode(
    "INVALID_TENANT",
    () => validateAccessToken(token({ tid: "tenant-red" }), config()),
  );
});

test("rejects a token missing a required scope", () => {
  expectCode(
    "INSUFFICIENT_SCOPE",
    () => validateAccessToken(token({ scope: "payments.write" }), config()),
  );
});

test("accepts old and new keys during a bounded rotation overlap", () => {
  const overlap = config({
    trustedKeys: new Map([
      [KID_OLD, oldKeys.publicKey],
      [KID_NEW, newKeys.publicKey],
    ]),
  });
  assert.equal(validateAccessToken(token(), overlap).subject, "user-42");
  assert.equal(
    validateAccessToken(
      token({}, { privateKey: newKeys.privateKey, kid: KID_NEW }),
      overlap,
    ).subject,
    "user-42",
  );
});

test("rejects the retired key after the overlap window", () => {
  const afterRotation = config({
    trustedKeys: new Map([[KID_NEW, newKeys.publicKey]]),
  });
  expectCode(
    "UNKNOWN_KEY",
    () => validateAccessToken(token(), afterRotation),
  );
  assert.equal(
    validateAccessToken(
      token({}, { privateKey: newKeys.privateKey, kid: KID_NEW }),
      afterRotation,
    ).subject,
    "user-42",
  );
});

test("does not fetch or accept an unknown kid", () => {
  const unknownKey = token(
    {},
    { privateKey: attackerKeys.privateKey, kid: "https://attacker.test/key" },
  );
  expectCode("UNKNOWN_KEY", () => validateAccessToken(unknownKey, config()));
});

test("accepts only the exact registered redirect string", () => {
  const isAllowed = createExactRedirectMatcher([
    "https://app.example.test/oauth/callback?channel=web",
  ]);
  assert.equal(
    isAllowed("https://app.example.test/oauth/callback?channel=web"),
    true,
  );

  const nearMatches = [
    "https://APP.example.test/oauth/callback?channel=web",
    "https://app.example.test:443/oauth/callback?channel=web",
    "https://app.example.test/oauth/callback/?channel=web",
    "https://app.example.test/oauth/callback?CHANNEL=web",
    "https://app.example.test/oauth/callback?channel=web#fragment",
    "https://app.example.test@attacker.test/oauth/callback?channel=web",
    "https://evil.app.example.test/oauth/callback?channel=web",
  ];
  for (const nearMatch of nearMatches) {
    assert.equal(isAllowed(nearMatch), false, nearMatch);
  }
});

test("rejects unsafe values at redirect registration time", () => {
  assert.throws(
    () => createExactRedirectMatcher(["http://app.example.test/callback"]),
    /HTTPS/u,
  );
  assert.throws(
    () => createExactRedirectMatcher(["https://user@app.example.test/callback"]),
    /userinfo/u,
  );
});

let failures = 0;
for (const item of tests) {
  try {
    item.operation();
    console.log(`PASS: ${item.name}`);
  } catch (error) {
    failures += 1;
    console.error(`FAIL: ${item.name}`);
    console.error(error.stack || error.message);
  }
}

if (failures > 0) {
  console.error(`OAuth/OIDC lab failed: ${failures} of ${tests.length} checks failed.`);
  process.exit(1);
}
console.log(`OAuth/OIDC lab passed: ${tests.length} positive and negative checks.`);
