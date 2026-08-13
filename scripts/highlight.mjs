// Deterministic build-time highlighting for the Scripts/Labs source viewer.
// Shiki and its grammars never ship to the browser; maintain-gh-pages.mjs writes
// the already-tokenized, safely escaped HTML into the committed static pages.
import {createHighlighter} from "shiki";
import {resolveSourceLanguage, SHIKI_SOURCE_LANGUAGES} from "./source-languages.mjs";

export const SOURCE_THEMES = Object.freeze({
  light: "github-light-default",
  dark: "github-dark-default"
});

const escapeHtml = value => String(value)
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

const highlighter = await createHighlighter({
  themes: Object.values(SOURCE_THEMES),
  langs: SHIKI_SOURCE_LANGUAGES
});

function conventionalLines(source) {
  if (!source) return [""];
  return source.endsWith("\n") ? source.slice(0, -1).split("\n") : source.split("\n");
}

function styleAttribute(style) {
  const value = Object.entries(style || {}).map(([property, setting]) => `${property}:${setting}`).join(";");
  return value ? ` style="${escapeHtml(value)}"` : "";
}

function renderPlaintext(source) {
  return conventionalLines(source)
    .map(line => `<span class="line">${escapeHtml(line)}</span>`)
    .join("\n") + (source.endsWith("\n") ? "\n" : "");
}

export function highlightSource(source, declaredLanguage) {
  const language = resolveSourceLanguage(declaredLanguage);
  if (language.mode === "plaintext") {
    return {
      html: renderPlaintext(source),
      language,
      highlighter: "plaintext",
      rootStyle: ""
    };
  }

  const result = highlighter.codeToTokens(source, {
    lang: language.id,
    themes: SOURCE_THEMES,
    defaultColor: false
  });
  let tokenLines = result.tokens;
  // Shiki represents a terminal newline as an extra empty token line. Omit that
  // visual line number, but keep a trailing text newline so code.textContent is
  // byte-faithful to the normalized LF source copied from the repository.
  if (source.endsWith("\n") && tokenLines.length > 1 && tokenLines.at(-1).length === 0) {
    tokenLines = tokenLines.slice(0, -1);
  }
  const html = tokenLines.map(tokens => {
    const line = tokens.map(token => `<span${styleAttribute(token.htmlStyle)}>${escapeHtml(token.content)}</span>`).join("");
    return `<span class="line">${line}</span>`;
  }).join("\n") + (source.endsWith("\n") ? "\n" : "");

  return {
    html,
    language,
    highlighter: "shiki",
    rootStyle: result.rootStyle
  };
}
