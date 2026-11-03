"use strict";

const {
  createSign,
  createVerify,
} = require("node:crypto");

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;

class TokenValidationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "TokenValidationError";
    this.code = code;
  }
}

function encodeJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function decodeJsonSegment(segment, label) {
  if (!segment || !BASE64URL_PATTERN.test(segment)) {
    throw new TokenValidationError("MALFORMED_TOKEN", `${label} is not base64url`);
  }

  try {
    const decoded = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
    if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
      throw new Error("decoded value is not an object");
    }
    return decoded;
  } catch {
    throw new TokenValidationError("MALFORMED_TOKEN", `${label} is not a JSON object`);
  }
}

function signJwt(claims, { privateKey, kid }) {
  if (!privateKey || typeof kid !== "string" || kid.length === 0) {
    throw new TypeError("privateKey and a nonempty kid are required");
  }

  const header = encodeJson({ alg: "RS256", kid, typ: "JWT" });
  const payload = encodeJson(claims);
  const signingInput = `${header}.${payload}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput, "ascii");
  signer.end();
  return `${signingInput}.${signer.sign(privateKey).toString("base64url")}`;
}

function parseScopeClaim(claims) {
  const value = claims.scope ?? claims.scp;
  if (typeof value !== "string") {
    throw new TokenValidationError("INVALID_SCOPE", "scope/scp must be a string");
  }
  return new Set(value.split(" ").filter(Boolean));
}

function audienceContains(audience, expectedAudience) {
  if (typeof audience === "string") return audience === expectedAudience;
  if (Array.isArray(audience)) {
    return audience.length > 0 &&
      audience.every((entry) => typeof entry === "string") &&
      audience.includes(expectedAudience);
  }
  return false;
}

function validateAccessToken(token, config) {
  const {
    issuer,
    audience,
    tenant,
    requiredScopes = [],
    trustedKeys,
    now = Math.floor(Date.now() / 1000),
    clockSkewSeconds = 0,
  } = config;

  if (!(trustedKeys instanceof Map) || trustedKeys.size === 0) {
    throw new TypeError("trustedKeys must be a nonempty Map");
  }
  if (!Number.isInteger(now) || !Number.isInteger(clockSkewSeconds) ||
      clockSkewSeconds < 0) {
    throw new TypeError("time settings must be integer seconds");
  }

  const parts = typeof token === "string" ? token.split(".") : [];
  if (parts.length !== 3 || !parts[2] || !BASE64URL_PATTERN.test(parts[2])) {
    throw new TokenValidationError("MALFORMED_TOKEN", "JWT must have three segments");
  }

  const header = decodeJsonSegment(parts[0], "header");
  const claims = decodeJsonSegment(parts[1], "payload");
  if (header.alg !== "RS256" || header.typ !== "JWT" ||
      typeof header.kid !== "string" || header.kid.length === 0) {
    throw new TokenValidationError(
      "UNSUPPORTED_HEADER",
      "alg=RS256, typ=JWT, and a trusted kid are required",
    );
  }
  if (header.jku !== undefined || header.x5u !== undefined ||
      header.crit !== undefined) {
    throw new TokenValidationError(
      "UNSUPPORTED_HEADER",
      "remote key URLs and unconfigured critical headers are rejected",
    );
  }

  const key = trustedKeys.get(header.kid);
  if (!key) {
    throw new TokenValidationError("UNKNOWN_KEY", "kid is not in the trusted key set");
  }

  const verifier = createVerify("RSA-SHA256");
  verifier.update(`${parts[0]}.${parts[1]}`, "ascii");
  verifier.end();
  if (!verifier.verify(key, Buffer.from(parts[2], "base64url"))) {
    throw new TokenValidationError("INVALID_SIGNATURE", "signature verification failed");
  }

  if (claims.iss !== issuer) {
    throw new TokenValidationError("INVALID_ISSUER", "issuer does not match");
  }
  if (!audienceContains(claims.aud, audience)) {
    throw new TokenValidationError("INVALID_AUDIENCE", "audience does not match");
  }
  if (typeof claims.sub !== "string" || claims.sub.length === 0) {
    throw new TokenValidationError("INVALID_SUBJECT", "nonempty sub is required");
  }
  if (!Number.isInteger(claims.exp) || now >= claims.exp + clockSkewSeconds) {
    throw new TokenValidationError("TOKEN_EXPIRED", "token is expired");
  }
  if (claims.nbf !== undefined &&
      (!Number.isInteger(claims.nbf) || now + clockSkewSeconds < claims.nbf)) {
    throw new TokenValidationError("TOKEN_NOT_ACTIVE", "token is not active");
  }
  if (claims.tid !== tenant) {
    throw new TokenValidationError("INVALID_TENANT", "tenant does not match");
  }

  const grantedScopes = parseScopeClaim(claims);
  for (const requiredScope of requiredScopes) {
    if (!grantedScopes.has(requiredScope)) {
      throw new TokenValidationError(
        "INSUFFICIENT_SCOPE",
        `required scope is absent: ${requiredScope}`,
      );
    }
  }

  return Object.freeze({
    issuer: claims.iss,
    subject: claims.sub,
    tenant: claims.tid,
    scopes: Object.freeze([...grantedScopes]),
  });
}

function validateRegisteredRedirect(uri) {
  if (typeof uri !== "string" || uri.length === 0) {
    throw new TypeError("registered redirect URI must be a nonempty string");
  }

  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    throw new TypeError("registered redirect URI must be an absolute URI");
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password ||
      parsed.hash) {
    throw new TypeError(
      "this web-client lab requires HTTPS without userinfo or a fragment",
    );
  }

  // URL serialization can normalize meaningful syntax. Registration is accepted
  // only when it is already in canonical serialized form; authorization requests
  // are still compared to the original string, without normalization.
  if (parsed.href !== uri) {
    throw new TypeError("registered redirect URI must use canonical URL syntax");
  }
}

function createExactRedirectMatcher(registeredUris) {
  if (!Array.isArray(registeredUris) || registeredUris.length === 0) {
    throw new TypeError("registeredUris must be a nonempty array");
  }
  for (const uri of registeredUris) validateRegisteredRedirect(uri);
  const exactValues = new Set(registeredUris);
  if (exactValues.size !== registeredUris.length) {
    throw new TypeError("registered redirect URIs must be unique");
  }
  return (requestedUri) =>
    typeof requestedUri === "string" && exactValues.has(requestedUri);
}

module.exports = {
  TokenValidationError,
  createExactRedirectMatcher,
  signJwt,
  validateAccessToken,
};
