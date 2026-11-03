(() => {
  "use strict";

  const focusKey = "docs-focus-mode";
  let focusReturn = null;

  function focusButtons() {
    return [...document.querySelectorAll("[data-docs-focus]")];
  }

  function setFocusMode(enabled, returnFocus = true) {
    const available = matchMedia("(min-width: 76.25em)").matches && focusButtons().length > 0;
    const active = available && enabled;
    document.body.classList.toggle("docs-focus-mode", active);
    focusButtons().forEach(button => {
      button.setAttribute("aria-pressed", String(active));
      const label = button.querySelector("[data-focus-label]");
      if (label) label.textContent = active ? "Exit focus" : "Focus";
    });
    sessionStorage.setItem(focusKey, active ? "true" : "false");
    if (!active && returnFocus && focusReturn?.isConnected) focusReturn.focus();
  }

  function openSearch() {
    const toggle = document.querySelector("label[for='__search']");
    if (toggle) toggle.click();
  }

  function initialize() {
    const dialog = document.querySelector(".md-search[role='dialog']");
    if (dialog && !dialog.getAttribute("aria-label")) dialog.setAttribute("aria-label", "Site search");
    document.querySelectorAll("nav.md-nav").forEach((nav, index) => {
      const labelledBy = nav.getAttribute("aria-labelledby");
      const label = labelledBy ? document.getElementById(labelledBy)?.textContent.trim() : "";
      nav.removeAttribute("aria-labelledby");
      nav.setAttribute("aria-label", `${label || "Documentation navigation"} ${index + 1}`);
    });
    document.querySelectorAll(".md-typeset__scrollwrap").forEach((region, index) => {
      region.tabIndex = 0;
      region.setAttribute("role", "region");
      region.setAttribute("aria-label", `Scrollable content ${index + 1}`);
    });
    focusButtons().forEach(button => button.addEventListener("click", () => {
      const enabled = !document.body.classList.contains("docs-focus-mode");
      if (enabled) focusReturn = button;
      setFocusMode(enabled);
    }));
    document.querySelectorAll("[data-docs-search-open]").forEach(button => button.addEventListener("click", openSearch));
    setFocusMode(sessionStorage.getItem(focusKey) === "true", false);
  }

  addEventListener("keydown", event => {
    if (event.key === "Escape" && document.body.classList.contains("docs-focus-mode")) {
      setFocusMode(false);
    }
  });
  addEventListener("resize", () => {
    if (!matchMedia("(min-width: 76.25em)").matches) setFocusMode(false, false);
  });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initialize);
  else initialize();
})();
