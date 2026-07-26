// docs-source-viewer.js — progressive enhancement for the .docs-source-viewer
// component (Scripts and Labs). Without this script the primary file's source
// is still fully visible and readable (only the extra file tabs, if any, need
// JS to switch between panels); this file only adds tab switching, copy, and
// expand/collapse. No network request, no external dependency.
(function () {
  "use strict";

  function activateTab(viewer, index) {
    var tabs = viewer.querySelectorAll("[data-source-tab]");
    var panels = viewer.querySelectorAll("[data-source-panel]");
    tabs.forEach(function (tab) {
      var isTarget = tab.getAttribute("data-index") === String(index);
      tab.setAttribute("aria-selected", isTarget ? "true" : "false");
      tab.tabIndex = isTarget ? 0 : -1;
      if (isTarget) tab.setAttribute("data-current-tab", "");
      else tab.removeAttribute("data-current-tab");
    });
    panels.forEach(function (panel) {
      if (panel.getAttribute("data-index") === String(index)) panel.removeAttribute("hidden");
      else panel.setAttribute("hidden", "");
    });
    var toolbarTitle = viewer.querySelector(".docs-source-viewer__toolbar-title");
    var activePanel = viewer.querySelector('[data-source-panel][data-index="' + index + '"]');
    var filename = activePanel && activePanel.querySelector(".docs-source-viewer__filename");
    if (toolbarTitle && filename) toolbarTitle.textContent = filename.textContent;
  }

  function currentPanelCode(viewer) {
    var panel = viewer.querySelector("[data-source-panel]:not([hidden])") || viewer.querySelector("[data-source-panel]");
    return panel ? panel.querySelector("code") : null;
  }

  function announce(button, message) {
    var original = button.textContent;
    button.textContent = message;
    window.setTimeout(function () {
      button.textContent = original;
    }, 1600);
  }

  document.querySelectorAll("[data-source-viewer]").forEach(function (viewer) {
    var tabs = Array.prototype.slice.call(viewer.querySelectorAll("[data-source-tab]"));
    tabs.forEach(function (tab, position) {
      tab.addEventListener("click", function () {
        activateTab(viewer, tab.getAttribute("data-index"));
        tab.focus();
      });
      tab.addEventListener("keydown", function (event) {
        if (event.key !== "ArrowRight" && event.key !== "ArrowLeft" && event.key !== "Home" && event.key !== "End") return;
        event.preventDefault();
        var nextPosition = position;
        if (event.key === "ArrowRight") nextPosition = (position + 1) % tabs.length;
        else if (event.key === "ArrowLeft") nextPosition = (position - 1 + tabs.length) % tabs.length;
        else if (event.key === "Home") nextPosition = 0;
        else if (event.key === "End") nextPosition = tabs.length - 1;
        var nextTab = tabs[nextPosition];
        activateTab(viewer, nextTab.getAttribute("data-index"));
        nextTab.focus();
      });
    });

    var copyButton = viewer.querySelector("[data-copy-source]");
    if (copyButton) {
      copyButton.addEventListener("click", function () {
        var code = currentPanelCode(viewer);
        if (!code) return;
        var text = code.textContent;
        var done = function () { announce(copyButton, "Copied"); };
        var failed = function () { announce(copyButton, "Copy failed"); };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done, failed);
        } else {
          try {
            var textarea = document.createElement("textarea");
            textarea.value = text;
            textarea.style.position = "fixed";
            textarea.style.opacity = "0";
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand("copy");
            document.body.removeChild(textarea);
            done();
          } catch (error) {
            failed();
          }
        }
      });
    }

    var expandButton = viewer.querySelector("[data-expand-source]");
    if (expandButton) {
      expandButton.addEventListener("click", function () {
        var expanded = expandButton.getAttribute("aria-expanded") === "true";
        var next = !expanded;
        expandButton.setAttribute("aria-expanded", String(next));
        expandButton.textContent = next ? "Collapse source" : "Expand full source";
        viewer.querySelectorAll(".docs-source-viewer__code").forEach(function (code) {
          code.classList.toggle("docs-source-expanded", next);
        });
      });
    }
  });
})();
