// Minimal, dependency-free build-time syntax highlighter. Runs once inside
// `npm run maintain` and emits plain <span class="tok-*"> markup — nothing is
// shipped to the browser to do this at runtime, and there is no CDN or remote
// highlighter involved. Deliberately supports only the languages actually
// used by the catalogued scripts/labs (Go, Python); anything else falls back
// to escaped plain text rather than guessing.

const escapeHtml = value => String(value)
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

const GO_KEYWORDS = new Set([
  "break", "case", "chan", "const", "continue", "default", "defer", "else", "fallthrough",
  "for", "func", "go", "goto", "if", "import", "interface", "map", "package", "range",
  "return", "select", "struct", "switch", "type", "var", "nil", "true", "false", "iota"
]);

const PY_KEYWORDS = new Set([
  "def", "return", "if", "elif", "else", "for", "while", "import", "from", "as", "class",
  "try", "except", "finally", "with", "raise", "assert", "pass", "break", "continue",
  "lambda", "None", "True", "False", "and", "or", "not", "in", "is", "global", "yield", "async", "await"
]);

const TOKEN_PATTERNS = {
  go: [
    {type: "comment", re: /\/\/[^\n]*|\/\*[\s\S]*?\*\//y},
    {type: "string", re: /`[^`]*`|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'/y},
    {type: "number", re: /\b0[xX][0-9a-fA-F]+\b|\b\d+(?:\.\d+)?\b/y},
    {type: "word", re: /[A-Za-z_][A-Za-z0-9_]*/y}
  ],
  python: [
    {type: "comment", re: /#[^\n]*/y},
    {type: "string", re: /"""[\s\S]*?"""|'''[\s\S]*?'''|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'/y},
    {type: "number", re: /\b0[xX][0-9a-fA-F]+\b|\b\d+(?:\.\d+)?\b/y},
    {type: "word", re: /[A-Za-z_][A-Za-z0-9_]*/y}
  ]
};

const KEYWORDS_BY_LANG = {go: GO_KEYWORDS, python: PY_KEYWORDS};

/** Tokenizes `source` for `language` and returns highlighted HTML (no outer <pre>/<code>). */
export function highlightCode(source, language) {
  const patterns = TOKEN_PATTERNS[language];
  if (!patterns) return escapeHtml(source);
  const keywords = KEYWORDS_BY_LANG[language] || new Set();
  let index = 0;
  let out = "";
  while (index < source.length) {
    let matched = false;
    for (const {type, re} of patterns) {
      re.lastIndex = index;
      const match = re.exec(source);
      if (!match || match.index !== index) continue;
      const text = match[0];
      if (type === "word") {
        out += keywords.has(text)
          ? `<span class="tok-keyword">${escapeHtml(text)}</span>`
          : escapeHtml(text);
      } else {
        out += `<span class="tok-${type}">${escapeHtml(text)}</span>`;
      }
      index += text.length;
      matched = true;
      break;
    }
    if (!matched) {
      out += escapeHtml(source[index]);
      index += 1;
    }
  }
  return out;
}
