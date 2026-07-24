// docs-ui.js — small, dependency-free enhancements for the documentation shell.
// Everything here is progressive: the shell works without JavaScript (the left-nav
// drawer is a plain checkbox + CSS, disclosures are native <details>). This file only
// adds Escape handling with focus return, persisted left-nav group state across page
// loads, and right-TOC active-section highlighting.
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

  onEscapeClose(
    document.getElementById("__drawer"),
    document.querySelector('label.md-header__button[for="__drawer"]')
  );
  onEscapeClose(
    document.getElementById("__search"),
    document.querySelector('label.md-header__button[for="__search"]')
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

  // Highlight the right-TOC entry for the section currently in view.
  var tocLinks = document.querySelectorAll(".docs-right-toc nav a[href^='#']");
  if (tocLinks.length && "IntersectionObserver" in window) {
    var byId = {};
    var targets = [];
    tocLinks.forEach(function (link) {
      var id = link.getAttribute("href").slice(1);
      var heading = id && document.getElementById(id);
      if (!heading) return;
      byId[id] = link;
      targets.push(heading);
    });

    var active = null;
    function setActive(id) {
      if (active) active.removeAttribute("data-docs-toc-active");
      var link = id ? byId[id] : null;
      active = link || null;
      if (link) link.setAttribute("data-docs-toc-active", "true");
    }

    var visible = new Set();
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) visible.add(entry.target.id);
          else visible.delete(entry.target.id);
        });
        var current = targets.find(function (heading) {
          return visible.has(heading.id);
        });
        setActive(current ? current.id : null);
      },
      {rootMargin: "-96px 0px -70% 0px"}
    );
    targets.forEach(function (heading) {
      observer.observe(heading);
    });
  }
})();
