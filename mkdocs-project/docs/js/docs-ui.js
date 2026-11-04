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
    const drawer = document.getElementById("__drawer");
    if (drawer?.checked) drawer.click();
    const toggle = document.getElementById("__search");
    if (toggle && !toggle.checked) toggle.click();
    document.querySelector(".md-search__input")?.focus({preventScroll: true});
  }

  function initialize() {
    const dialog = document.querySelector(".md-search[role='dialog']");
    if (dialog && !dialog.getAttribute("aria-label")) dialog.setAttribute("aria-label", "Site search");
    document.querySelectorAll("nav.md-nav").forEach((nav, index) => {
      const labelledBy = nav.getAttribute("aria-labelledby");
      const label = labelledBy ? document.getElementById(labelledBy)?.textContent.trim() : "";
      nav.removeAttribute("aria-labelledby");
      nav.setAttribute("aria-label", label || nav.getAttribute("aria-label") || `Documentation navigation ${index + 1}`);
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
    const drawer = document.getElementById("__drawer");
    const menu = document.querySelector(".docs-menu");
    const sidebar = document.querySelector(".md-sidebar--primary");
    const navigation = document.getElementById("docs-navigation");
    const closeMenu = document.querySelector(".docs-nav-close");
    const searchToggle = document.getElementById("__search");
    const searchDialog = document.querySelector(".md-search");
    const searchButton = document.querySelector(".docs-mobile-search");
    const searchQuery = searchDialog?.querySelector(".md-search__input");
    // Material observes keyup. Also handle paste, dictation, and virtual keyboards.
    const updateQuery = () => searchQuery?.dispatchEvent(new KeyboardEvent("keyup", {bubbles: true}));
    searchQuery?.addEventListener("input", event => { if (!event.isComposing) updateQuery(); });
    searchQuery?.addEventListener("compositionend", updateQuery);
    searchQuery?.form?.addEventListener("reset", () => requestAnimationFrame(updateQuery));
    const mobileNavigation = matchMedia("(max-width: 76.234375em)");
    const mobileSearch = matchMedia("(max-width: 59.984375em)");
    let wasOpen = false;
    let wasSearchOpen = false;
    // Native buttons provide keyboard activation and a named search-back control.
    const searchLabel = searchDialog?.querySelector(".md-search__form > label[for='__search']");
    const searchBack = document.createElement("button");
    if (searchLabel) {
      searchBack.type = "button";
      searchBack.className = `${searchLabel.className} docs-search-back`;
      searchBack.innerHTML = searchLabel.innerHTML;
      searchLabel.replaceWith(searchBack);
      searchBack.addEventListener("click", () => {
        if (searchToggle?.checked) searchToggle.click();
        else openSearch();
      });
    }
    function syncBackground() {
      const drawerOpen = mobileNavigation.matches && Boolean(drawer?.checked);
      const searchOpen = mobileSearch.matches && Boolean(searchToggle?.checked);
      document.querySelectorAll(".md-content, .docs-brand, .docs-header-tools, .docs-mobile-search").forEach(element => { element.inert = drawerOpen || searchOpen; });
      if (sidebar) sidebar.inert = (mobileNavigation.matches && !drawerOpen) || searchOpen;
      if (searchDialog) searchDialog.inert = drawerOpen || (mobileSearch.matches && !searchOpen);
    }
    function syncDrawer() {
      const open = mobileNavigation.matches && Boolean(drawer?.checked);
      menu?.setAttribute("aria-expanded", String(open));
      document.body.classList.toggle("docs-drawer-open", open);
      syncBackground();
      if (open) {
        sidebar?.setAttribute("role", "dialog");
        sidebar?.setAttribute("aria-modal", "true");
        sidebar?.setAttribute("aria-label", "Documentation navigation");
        if (!wasOpen) {
          const resetNavigationScroll = () => sidebar?.querySelectorAll(".md-sidebar__scrollwrap, #docs-navigation > .md-nav__list").forEach(element => { element.scrollTop = 0; });
          resetNavigationScroll();
          closeMenu?.focus({preventScroll: true});
          // Keep the first group visible after the drawer finishes its initial layout.
          requestAnimationFrame(() => { if (drawer?.checked) resetNavigationScroll(); });
        }
      } else {
        sidebar?.removeAttribute("role");
        sidebar?.removeAttribute("aria-modal");
        sidebar?.removeAttribute("aria-label");
        if (wasOpen && mobileNavigation.matches) menu?.focus({preventScroll: true});
      }
      wasOpen = open;
    }
    function syncSearch() {
      const open = mobileSearch.matches && Boolean(searchToggle?.checked);
      syncBackground();
      document.body.classList.toggle("docs-search-open", open);
      searchBack.setAttribute("aria-label", searchToggle?.checked ? "Close search" : "Search");
      if (open) searchDialog?.setAttribute("aria-modal", "true");
      else {
        searchDialog?.removeAttribute("aria-modal");
        if (wasSearchOpen && mobileSearch.matches) searchButton?.focus({preventScroll: true});
      }
      wasSearchOpen = open;
    }
    function closeDrawer() {
      if (drawer?.checked) drawer.click();
      menu?.focus({preventScroll: true});
    }
    drawer?.addEventListener("change", syncDrawer);
    searchToggle?.addEventListener("change", syncSearch);
    mobileNavigation.addEventListener("change", () => {
      if (!mobileNavigation.matches && drawer?.checked) drawer.click();
      syncDrawer();
    });
    mobileSearch.addEventListener("change", syncSearch);
    syncDrawer();
    syncSearch();
    menu?.addEventListener("click", () => drawer?.click());
    closeMenu?.addEventListener("click", closeDrawer);
    document.addEventListener("keydown", event => {
      const drawerOpen = mobileNavigation.matches && drawer?.checked;
      const searchOpen = mobileSearch.matches && searchToggle?.checked;
      const overlay = drawerOpen ? navigation : searchOpen ? searchDialog : null;
      if (!overlay) return;
      if (event.key === "Escape") {
        event.stopPropagation();
        event.preventDefault();
        if (drawerOpen) closeDrawer();
        else searchToggle.click();
      } else if (event.key === "Tab") {
        event.stopPropagation();
        const controls = [...overlay.querySelectorAll("a[href], button, input, summary, [tabindex]")].filter(element => element.tabIndex >= 0 && element.getClientRects().length && !element.disabled);
        const first = controls[0];
        const last = controls.at(-1);
        if (event.shiftKey && (document.activeElement === first || !overlay.contains(document.activeElement))) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && (document.activeElement === last || !overlay.contains(document.activeElement))) {
          event.preventDefault();
          first?.focus();
        }
      }
    }, {capture: true});
    setFocusMode(sessionStorage.getItem(focusKey) === "true", false);
  }

  addEventListener("keydown", event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      openSearch();
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
