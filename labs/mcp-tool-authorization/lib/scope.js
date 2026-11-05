"use strict";

/**
 * Scopes look like  capability:verb:resource  - for example
 *   notes:read:/workspace/notes/**     tickets:create:*     email:send:example.test
 * `*` matches one path segment (or, for a non-path resource, the whole value);
 * `**` matches any depth. The resource glob is matched against a validated, never
 * "repaired", resource: a path containing a `..` segment, a NUL, a backslash, a
 * relative form, or a double slash is rejected outright instead of being normalized
 * into something that happens to match.
 */

class ResourceError extends Error {}

function validatePath(raw) {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 256) throw new ResourceError("path must be a nonempty string of at most 256 characters");
  if (!raw.startsWith("/")) throw new ResourceError("path must be absolute");
  if (raw.includes("\u0000") || raw.includes("\\")) throw new ResourceError("path contains NUL or backslash");
  if (raw.includes("//")) throw new ResourceError("path contains an empty segment");
  if (raw.split("/").some((segment) => segment === ".." || segment === ".")) throw new ResourceError("path contains a dot segment");
  return raw;
}

function emailDomain(raw) {
  if (typeof raw !== "string" || raw.length > 254) throw new ResourceError("address too long");
  const match = raw.match(/^[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$/);
  if (!match) throw new ResourceError("not a single plain address");
  return match[1].toLowerCase();
}

function globToRegExp(glob) {
  let out = "^";
  for (let i = 0; i < glob.length; i += 1) {
    const ch = glob[i];
    if (ch === "*" && glob[i + 1] === "*") { out += ".*"; i += 1; }
    else if (ch === "*") out += "[^/]*";
    else out += ch.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`${out}$`);
}

function parseScope(scope) {
  const first = scope.indexOf(":");
  const second = scope.indexOf(":", first + 1);
  if (first < 1 || second < first + 2 || second === scope.length - 1) throw new ResourceError(`malformed scope ${JSON.stringify(scope)}`);
  return { capability: scope.slice(0, first), verb: scope.slice(first + 1, second), glob: scope.slice(second + 1) };
}

/** True when ANY scope grants capability+verb on this (already validated) resource. */
function allows(scopes, capability, verb, resource) {
  return scopes.some((scope) => {
    let parsed;
    try { parsed = parseScope(scope); } catch { return false; }
    return parsed.capability === capability && parsed.verb === verb && globToRegExp(parsed.glob).test(resource);
  });
}

module.exports = { ResourceError, allows, emailDomain, globToRegExp, parseScope, validatePath };
