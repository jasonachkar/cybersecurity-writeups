import {createHighlighter} from "shiki";
import {resolveSourceLanguage, SHIKI_SOURCE_LANGUAGES} from "./source-languages.mjs";

const themes = {light: "github-light-default", dark: "github-dark-default"};
const highlighter = await createHighlighter({themes: Object.values(themes), langs: SHIKI_SOURCE_LANGUAGES});
const escapeHtml = value => String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;")
  .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

function styleAttribute(style) {
  const value = Object.entries(style || {}).map(([property, setting]) => `${property}:${setting}`).join(";");
  return value ? ` style="${escapeHtml(value)}"` : "";
}

function conventionalLines(source) {
  if (!source) return [""];
  return source.endsWith("\n") ? source.slice(0, -1).split("\n") : source.split("\n");
}

function lineMarkup(content, viewerId, index) {
  const anchor = `${viewerId}-L${index}`;
  return `<span class="line" id="${anchor}"><a class="docs-source-viewer__line-number" href="#${anchor}" aria-label="Link to line ${index}">${index}</a><span class="docs-source-viewer__line-content">${content || " "}</span></span>`;
}

export function highlightSource(source, declaredLanguage, viewerId) {
  const language = resolveSourceLanguage(declaredLanguage);
  if (language.mode === "plaintext") {
    return {
      html: conventionalLines(source).map((line, index) => lineMarkup(escapeHtml(line), viewerId, index + 1)).join("\n"),
      language, highlighter: "plaintext", rootStyle: "",
    };
  }
  const result = highlighter.codeToTokens(source, {lang: language.id, themes, defaultColor: false});
  let tokenLines = result.tokens;
  if (source.endsWith("\n") && tokenLines.length > 1 && tokenLines.at(-1).length === 0) tokenLines = tokenLines.slice(0, -1);
  return {
    html: tokenLines.map((tokens, index) => lineMarkup(tokens.map(token => `<span${styleAttribute(token.htmlStyle)}>${escapeHtml(token.content)}</span>`).join(""), viewerId, index + 1)).join("\n"),
    language, highlighter: "shiki", rootStyle: result.rootStyle,
  };
}
