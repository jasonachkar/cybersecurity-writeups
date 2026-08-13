// Progressive enhancement for the reusable Scripts/Labs source viewer. The
// primary source is readable in static HTML; this file adds tab switching,
// active-file metadata, copying, wrapping, and per-file expansion.
(function () {
  "use strict";

  function activePanel(viewer) {
    return viewer.querySelector("[data-source-panel]:not([hidden])") || viewer.querySelector("[data-source-panel]");
  }

  function setText(viewer, selector, value) {
    var element = viewer.querySelector(selector);
    if (element) element.textContent = value;
  }

  function syncViewer(viewer) {
    var panel = activePanel(viewer);
    if (!panel) return;
    var filename = panel.getAttribute("data-source-filename") || "Source";
    var language = panel.getAttribute("data-source-language") || "Plain text";
    var lineCount = Number(panel.getAttribute("data-source-lines") || "0");
    var path = panel.getAttribute("data-source-path") || filename;
    setText(viewer, "[data-source-active-filename]", filename);
    setText(viewer, "[data-source-active-language]", language);
    setText(viewer, "[data-source-active-lines]", lineCount + " line" + (lineCount === 1 ? "" : "s"));
    setText(viewer, "[data-source-active-path]", path);
    var pathElement = viewer.querySelector("[data-source-active-path]");
    if (pathElement) pathElement.title = path;
    viewer.setAttribute("aria-label", "Source code: " + filename);

    var expandButton = viewer.querySelector("[data-expand-source]");
    if (expandButton) {
      var expandable = panel.hasAttribute("data-source-expandable");
      var expanded = panel.getAttribute("data-source-expanded") === "true";
      expandButton.hidden = !expandable;
      expandButton.setAttribute("aria-expanded", String(expandable && expanded));
      expandButton.textContent = expanded ? "Collapse" : "Expand";
    }
  }

  function activateTab(viewer, index, moveFocus) {
    var tabs = viewer.querySelectorAll("[data-source-tab]");
    var panels = viewer.querySelectorAll("[data-source-panel]");
    var selectedTab = null;
    tabs.forEach(function (tab) {
      var selected = tab.getAttribute("data-index") === String(index);
      tab.setAttribute("aria-selected", String(selected));
      tab.tabIndex = selected ? 0 : -1;
      tab.toggleAttribute("data-current-tab", selected);
      if (selected) selectedTab = tab;
    });
    panels.forEach(function (panel) {
      panel.hidden = panel.getAttribute("data-index") !== String(index);
    });
    syncViewer(viewer);
    if (selectedTab) {
      selectedTab.scrollIntoView({block: "nearest", inline: "nearest"});
      if (moveFocus) selectedTab.focus();
    }
  }

  function showStatus(viewer, message) {
    var status = viewer.querySelector("[data-source-status]");
    if (!status) return;
    window.clearTimeout(viewer.__docsSourceStatusTimer);
    status.textContent = message;
    viewer.__docsSourceStatusTimer = window.setTimeout(function () {
      status.textContent = "";
    }, 1800);
  }

  function copyText(text, success, failure) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(success, failure);
      return;
    }
    try {
      var textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.setAttribute("readonly", "");
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      var copied = document.execCommand("copy");
      textarea.remove();
      if (copied) success();
      else failure();
    } catch (error) {
      failure();
    }
  }

  document.querySelectorAll("[data-source-viewer]").forEach(function (viewer) {
    var tabs = Array.prototype.slice.call(viewer.querySelectorAll("[data-source-tab]"));
    tabs.forEach(function (tab, position) {
      tab.addEventListener("click", function () {
        activateTab(viewer, tab.getAttribute("data-index"), true);
      });
      tab.addEventListener("keydown", function (event) {
        if (["ArrowRight", "ArrowLeft", "Home", "End"].indexOf(event.key) === -1) return;
        event.preventDefault();
        var next = position;
        if (event.key === "ArrowRight") next = (position + 1) % tabs.length;
        else if (event.key === "ArrowLeft") next = (position - 1 + tabs.length) % tabs.length;
        else if (event.key === "Home") next = 0;
        else if (event.key === "End") next = tabs.length - 1;
        activateTab(viewer, tabs[next].getAttribute("data-index"), true);
      });
    });

    var copyButton = viewer.querySelector("[data-copy-source]");
    if (copyButton) {
      copyButton.addEventListener("click", function () {
        var panel = activePanel(viewer);
        var code = panel && panel.querySelector("code");
        if (!code) return;
        copyText(code.textContent, function () { showStatus(viewer, "Copied"); }, function () { showStatus(viewer, "Copy failed"); });
      });
    }

    var wrapButton = viewer.querySelector("[data-wrap-source]");
    if (wrapButton) {
      wrapButton.addEventListener("click", function () {
        var wrapped = viewer.getAttribute("data-source-wrapped") === "true";
        viewer.setAttribute("data-source-wrapped", String(!wrapped));
        wrapButton.setAttribute("aria-pressed", String(!wrapped));
        showStatus(viewer, wrapped ? "Line wrapping off" : "Lines wrapped");
      });
    }

    var expandButton = viewer.querySelector("[data-expand-source]");
    if (expandButton) {
      expandButton.addEventListener("click", function () {
        var panel = activePanel(viewer);
        if (!panel || !panel.hasAttribute("data-source-expandable")) return;
        var expanded = panel.getAttribute("data-source-expanded") === "true";
        panel.setAttribute("data-source-expanded", String(!expanded));
        syncViewer(viewer);
      });
    }

    viewer.setAttribute("data-enhanced", "true");
    syncViewer(viewer);
  });
})();
