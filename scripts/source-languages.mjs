export const SOURCE_LANGUAGE_DEFINITIONS = Object.freeze({
  javascript: Object.freeze({id: "javascript", displayName: "JavaScript", mode: "shiki", aliases: ["js", "node"]}),
  go: Object.freeze({id: "go", displayName: "Go", mode: "shiki", aliases: ["golang"]}),
  python: Object.freeze({id: "python", displayName: "Python", mode: "shiki", aliases: ["py"]}),
  sql: Object.freeze({id: "sql", displayName: "SQL", mode: "shiki", aliases: []}),
  yaml: Object.freeze({id: "yaml", displayName: "YAML", mode: "shiki", aliases: ["yml"]}),
  json: Object.freeze({id: "json", displayName: "JSON", mode: "shiki", aliases: []}),
  bicep: Object.freeze({id: "bicep", displayName: "Bicep", mode: "shiki", aliases: []}),
  rego: Object.freeze({id: "rego", displayName: "Rego", mode: "plaintext", aliases: []}),
});

const aliases = new Map();
for (const definition of Object.values(SOURCE_LANGUAGE_DEFINITIONS)) {
  aliases.set(definition.id, definition);
  for (const alias of definition.aliases) aliases.set(alias, definition);
}

export const SHIKI_SOURCE_LANGUAGES = Object.freeze(
  Object.values(SOURCE_LANGUAGE_DEFINITIONS).filter(item => item.mode === "shiki").map(item => item.id),
);

export function resolveSourceLanguage(value) {
  const normalized = String(value || "").trim().toLowerCase();
  const definition = aliases.get(normalized);
  if (!definition) throw new Error(`Unsupported source language ${JSON.stringify(value)}`);
  return definition;
}
