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
    const toggle = document.querySelector("[data-docs-search-toggle]");
    if (toggle) toggle.click();
  }

  const menuQuery = matchMedia("(max-width: 799px)");
  const themeQuery = matchMedia("(prefers-color-scheme: dark)");
  let menuReturn = null;
  let searchReturn = null;
  const readPreference = key => { try { return localStorage.getItem(key); } catch { return null; } };

  function applyTheme(value) {
    const dark = value === "dark" || (value === "auto" && themeQuery.matches);
    document.body.dataset.mdColorScheme = dark ? "slate" : "default";
    document.body.dataset.mdColorMedia = dark ? "(prefers-color-scheme: dark)" : "(prefers-color-scheme: light)";
    document.querySelectorAll("[data-docs-theme]").forEach(select => { select.value = value; });
    try {
      localStorage.setItem("docs-color-theme", value);
      localStorage.setItem("/.__palette", JSON.stringify({index: dark ? 1 : 0}));
    } catch { /* Preferences are optional when storage is unavailable. */ }
  }

  function setMenu(open, restoreFocus = false) {
    const active = open && menuQuery.matches;
    const toggle = document.getElementById("__drawer");
    toggle.checked = active;
    document.body.classList.toggle("docs-menu-open", active);
    const sidebar = document.querySelector(".docs-sidebar");
    if (active) {
      sidebar.setAttribute("popover", "manual");
      sidebar.showPopover();
    } else if (sidebar.hasAttribute("popover")) {
      sidebar.hidePopover();
      sidebar.removeAttribute("popover");
    }
    document.body.style.overflow = active ? "hidden" : "";
    const button = document.querySelector("[data-docs-menu]");
    button.setAttribute("aria-expanded", String(active));
    button.setAttribute("aria-label", active ? "Close navigation" : "Open navigation");
    document.querySelector(".md-content").inert = active;
    if (restoreFocus) menuReturn?.focus();
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
    let theme = readPreference("docs-color-theme");
    if (!["auto", "light", "dark"].includes(theme)) {
      try { const old = JSON.parse(readPreference("/.__palette")); theme = old ? (old.index === 1 ? "dark" : "light") : "auto"; }
      catch { theme = "auto"; }
    }
    applyTheme(theme);
    document.querySelectorAll("[data-docs-theme]").forEach(select => select.addEventListener("change", () => applyTheme(select.value)));
    themeQuery.addEventListener("change", () => { if (readPreference("docs-color-theme") === "auto") applyTheme("auto"); });
    document.querySelector("[data-docs-menu]").addEventListener("click", event => {
      menuReturn = event.currentTarget;
      setMenu(!document.getElementById("__drawer").checked);
    });
    menuQuery.addEventListener("change", () => setMenu(false));
    document.querySelectorAll(".docs-sidebar a").forEach(link => link.addEventListener("click", () => setMenu(false)));
    document.querySelectorAll("[data-docs-search-open]").forEach(button => button.addEventListener("click", () => {
      searchReturn = button;
      setMenu(false);
      openSearch();
      requestAnimationFrame(() => document.querySelector(".md-search__input")?.focus());
    }));
    document.querySelector(".md-search")?.addEventListener("click", event => {
      if (event.target.classList.contains("md-search")) {
        document.getElementById("__search").checked = false;
        searchReturn?.focus();
      }
    });
    const shortcut = document.querySelector("[data-search-shortcut]");
    if (shortcut && /Mac|iPhone|iPad/.test(navigator.platform)) shortcut.textContent = "⌘ K";
    setFocusMode(sessionStorage.getItem(focusKey) === "true", false);
  }

  addEventListener("keydown", event => {
    const editing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName) || document.activeElement?.isContentEditable;
    if (((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") || (event.key === "/" && !editing)) {
      event.preventDefault();
      document.querySelector("[data-docs-search-open]")?.click();
    }
    if (event.key === "Escape") {
      if (document.getElementById("__drawer").checked) setMenu(false, true);
      if (document.getElementById("__search").checked) {
        document.getElementById("__search").checked = false;
        searchReturn?.focus();
      }
    }
    if (event.key === "Tab" && document.getElementById("__drawer").checked) {
      const focusable = [document.querySelector("[data-docs-menu]"), ...document.querySelectorAll(".docs-sidebar a, .docs-sidebar summary, .docs-sidebar select")].filter(node => node.getClientRects().length);
      const first = focusable[0], last = focusable.at(-1);
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
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
