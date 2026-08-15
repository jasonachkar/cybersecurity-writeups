(() => {
  "use strict";

  function active(viewer) {
    return viewer.querySelector("[data-source-panel]:not([hidden])");
  }

  function announce(viewer, message) {
    const status = viewer.querySelector("[data-source-status]");
    status.textContent = "";
    requestAnimationFrame(() => { status.textContent = message; });
  }

  function sourceText(panel) {
    return [...panel.querySelectorAll(".docs-source-viewer__line-content")]
      .map(line => line.textContent)
      .join("\n");
  }

  function activate(viewer, index, moveFocus = false) {
    const tabs = [...viewer.querySelectorAll("[data-source-tab]")];
    const panels = [...viewer.querySelectorAll("[data-source-panel]")];
    const tab = tabs.find(candidate => Number(candidate.dataset.index) === index);
    const panel = panels.find(candidate => Number(candidate.dataset.index) === index);
    if (!panel) return;
    tabs.forEach(candidate => {
      const selected = candidate === tab;
      candidate.setAttribute("aria-selected", String(selected));
      candidate.tabIndex = selected ? 0 : -1;
    });
    panels.forEach(candidate => { candidate.hidden = candidate !== panel; });
    viewer.querySelector("[data-source-active-filename]").textContent = panel.dataset.sourceFilename;
    viewer.querySelector("[data-source-active-language]").textContent = panel.dataset.sourceLanguage;
    viewer.querySelector("[data-source-active-lines]").textContent = `${panel.dataset.sourceLines} lines`;
    viewer.querySelector("[data-source-active-path]").textContent = panel.dataset.sourcePath;
    viewer.querySelector("[data-source-active-path]").title = panel.dataset.sourcePath;
    viewer.querySelector("[data-source-github]").href = panel.dataset.sourceGithub;
    viewer.querySelector("[data-source-raw]").href = panel.dataset.sourceRaw;
    const expand = viewer.querySelector("[data-expand-source]");
    expand.hidden = !panel.hasAttribute("data-source-expandable");
    expand.setAttribute("aria-expanded", "false");
    viewer.classList.remove("is-expanded");
    if (moveFocus && tab) tab.focus();
  }

  function initialize(viewer) {
    viewer.querySelectorAll("[data-source-tab]").forEach(tab => {
      tab.addEventListener("click", () => activate(viewer, Number(tab.dataset.index)));
      tab.addEventListener("keydown", event => {
        const tabs = [...viewer.querySelectorAll("[data-source-tab]")];
        const current = tabs.indexOf(tab);
        let next = current;
        if (event.key === "ArrowRight") next = (current + 1) % tabs.length;
        else if (event.key === "ArrowLeft") next = (current - 1 + tabs.length) % tabs.length;
        else if (event.key === "Home") next = 0;
        else if (event.key === "End") next = tabs.length - 1;
        else return;
        event.preventDefault();
        activate(viewer, Number(tabs[next].dataset.index), true);
      });
    });

    viewer.querySelector("[data-copy-source]").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(sourceText(active(viewer)));
        announce(viewer, "Source copied");
      } catch {
        announce(viewer, "Copy unavailable; use View raw");
      }
    });
    viewer.querySelector("[data-wrap-source]").addEventListener("click", event => {
      const wrapped = !viewer.classList.contains("is-wrapped");
      viewer.classList.toggle("is-wrapped", wrapped);
      event.currentTarget.setAttribute("aria-pressed", String(wrapped));
      announce(viewer, wrapped ? "Line wrapping enabled" : "Line wrapping disabled");
    });
    viewer.querySelector("[data-expand-source]").addEventListener("click", event => {
      const expanded = !viewer.classList.contains("is-expanded");
      viewer.classList.toggle("is-expanded", expanded);
      event.currentTarget.setAttribute("aria-expanded", String(expanded));
      event.currentTarget.textContent = expanded ? "Collapse" : "Expand";
    });
  }

  function start() {
    document.querySelectorAll("[data-source-viewer]").forEach(initialize);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
