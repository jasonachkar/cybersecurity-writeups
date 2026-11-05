"use strict";

/**
 * A deliberately small JSON-Schema subset validator, closed by default.
 * Supported: type (object, string, integer, boolean, array), properties, required,
 * maxLength, minLength, pattern, enum, minimum, maximum, items, maxItems.
 * Unknown properties are ALWAYS rejected, whether or not the schema says
 * additionalProperties:false - a gateway should not depend on a server's schema being strict.
 * Returns a list of error strings (empty means valid).
 */
function validate(schema, value, path = "$") {
  const errors = [];
  const type = schema.type;
  const typeOk = {
    object: (v) => v !== null && typeof v === "object" && !Array.isArray(v),
    string: (v) => typeof v === "string",
    integer: (v) => Number.isSafeInteger(v),
    boolean: (v) => typeof v === "boolean",
    array: (v) => Array.isArray(v),
  };
  if (type && !(typeOk[type] || (() => false))(value)) return [`${path}: expected ${type}`];
  if (type === "object") {
    for (const key of Object.keys(value)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") errors.push(`${path}.${key}: forbidden key`);
      else if (!schema.properties || !Object.hasOwn(schema.properties, key)) errors.push(`${path}.${key}: unknown property`);
    }
    for (const key of schema.required || []) if (!Object.hasOwn(value, key)) errors.push(`${path}.${key}: required`);
    for (const [key, sub] of Object.entries(schema.properties || {})) {
      if (Object.hasOwn(value, key)) errors.push(...validate(sub, value[key], `${path}.${key}`));
    }
  } else if (type === "string") {
    if (schema.maxLength !== undefined && value.length > schema.maxLength) errors.push(`${path}: longer than ${schema.maxLength}`);
    if (schema.minLength !== undefined && value.length < schema.minLength) errors.push(`${path}: shorter than ${schema.minLength}`);
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) errors.push(`${path}: does not match pattern`);
    if (value.includes("\u0000")) errors.push(`${path}: contains NUL`);
  } else if (type === "integer") {
    if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${path}: below minimum`);
    if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${path}: above maximum`);
  } else if (type === "array") {
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errors.push(`${path}: too many items`);
    if (schema.items) value.forEach((item, i) => errors.push(...validate(schema.items, item, `${path}[${i}]`)));
  }
  if (schema.enum && !schema.enum.includes(value)) errors.push(`${path}: not in enum`);
  return errors;
}

module.exports = { validate };
