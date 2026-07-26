// docs-ui.js — small, dependency-free enhancements for the documentation shell.
// Everything here is progressive: the shell works without JavaScript (the left-nav
// drawer is a plain checkbox + CSS, disclosures are native <details>). This file only
// adds Escape handling with focus return, keyboard activation for the header's
// label-as-button triggers, persisted left-nav group state across page loads, and
// TOC active-section highlighting (synced across the desktop and inline TOC
// presentations, since only one is visible at a given viewport width).
(function () {
  "use strict";

  function onEscapeClose(toggle, trigger) {
    if (!toggle) return;
    document.addEventListener("keydown", function (event) {
      if (event.key !== "Escape" || !toggle.checked) return;
      toggle.checked = false;
      if (trigger) trigger.focus();
    });
  }

  // A <label for="checkbox"> toggles its control on a mouse click natively, but
  // not on a keyboard Enter/Space activation — needed now that these triggers
  // are also given tabindex="0" (see maintain-gh-pages.mjs) to be focusable at
  // all, e.g. so focus has somewhere real to land back on after Escape closes
  // the drawer or search overlay.
  function onKeyboardActivate(trigger, toggle) {
    if (!trigger || !toggle) return;
    trigger.addEventListener("keydown", function (event) {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      toggle.checked = !toggle.checked;
      toggle.dispatchEvent(new Event("change", {bubbles: true}));
    });
  }

  var drawerToggle = document.getElementById("__drawer");
  var drawerTrigger = document.querySelector('label.md-header__button[for="__drawer"]');
  var searchToggle = document.getElementById("__search");
  var searchTrigger = document.querySelector('label.md-header__button[for="__search"]');

  onKeyboardActivate(drawerTrigger, drawerToggle);
  onKeyboardActivate(searchTrigger, searchToggle);

  onEscapeClose(drawerToggle, drawerTrigger);
  onEscapeClose(
    searchToggle,
    searchTrigger
  );

  // Persist which left-nav groups a visitor expanded, so moving between pages does
  // not re-collapse sections they deliberately opened (the currently active section
  // is still expanded on first load server-side, independent of this).
  var STORAGE_KEY = "docs-nav-open-groups";
  var leftNav = document.querySelector(".docs-left-nav");
  if (leftNav) {
    var stored;
    try {
      stored = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || "[]");
    } catch (error) {
      stored = [];
    }
    var groups = leftNav.querySelectorAll("details.docs-nav-group");
    groups.forEach(function (details) {
      var summary = details.querySelector("summary");
      var key = summary ? summary.textContent.trim() : "";
      if (key && stored.indexOf(key) !== -1) details.open = true;
      details.addEventListener("toggle", function () {
        var open = [];
        groups.forEach(function (item) {
          if (!item.open) return;
          var label = item.querySelector("summary");
          if (label) open.push(label.textContent.trim());
        });
        try {
          sessionStorage.setItem(STORAGE_KEY, JSON.stringify(open));
        } catch (error) {
          // sessionStorage unavailable (private mode, quota) — state simply resets.
        }
      });
    });
  }

  // Highlight the TOC entry for the section currently being read, in both the
  // desktop aside and the inline in-article disclosure at once (only one of the two
  // is ever visible at a given viewport width, but both exist in the DOM and share
  // heading ids, so both get the active marker kept in sync).
  var tocLinks = document.querySelectorAll(".docs-right-toc nav a[href^='#'], .docs-inline-toc nav a[href^='#']");
  if (tocLinks.length) {
    var linksById = {};
    var headings = [];
    tocLinks.forEach(function (link) {
      var id = link.getAttribute("href").slice(1);
      var heading = id && document.getElementById(id);
      if (!heading) return;
      linksById[id] = linksById[id] || [];
      linksById[id].push(link);
      if (headings.indexOf(heading) === -1) headings.push(heading);
    });
    headings.sort(function (a, b) {
      return a.getBoundingClientRect().top - b.getBoundingClientRect().top;
    });

    var activeLinks = [];
    function setActive(id) {
      activeLinks.forEach(function (link) {
        link.removeAttribute("data-docs-toc-active");
      });
      activeLinks = (id && linksById[id]) || [];
      activeLinks.forEach(function (link) {
        link.setAttribute("data-docs-toc-active", "true");
      });
    }

    // The active section is the last heading whose top has scrolled up past the
    // reading offset — not "whichever heading currently intersects a narrow zone",
    // which clears itself out during a long section once the heading has scrolled
    // well past the top and the next one hasn't arrived yet.
    var READING_OFFSET = 96;
    function updateActiveToc() {
      var current = headings.length ? headings[0].id : null;
      headings.forEach(function (heading) {
        if (heading.getBoundingClientRect().top <= READING_OFFSET) current = heading.id;
      });
      setActive(current);
    }

    var ticking = false;
    function requestTocUpdate() {
      if (ticking) return;
      ticking = true;
      window.requestAnimationFrame(function () {
        updateActiveToc();
        ticking = false;
      });
    }

    window.addEventListener("scroll", requestTocUpdate, {passive: true});
    window.addEventListener("resize", requestTocUpdate);

    if (location.hash && linksById[location.hash.slice(1)]) {
      setActive(location.hash.slice(1));
    } else {
      updateActiveToc();
    }
  }
})();
