/**
 * Portfolio accessibility helpers for Material-generated markup.
 *
 * Labels code-block navigation landmarks and makes horizontal scroll
 * wrappers keyboard-focusable. Uses a narrowly scoped MutationObserver
 * for dynamically injected nodes. Attribute writes are skipped when the
 * required values already exist so the observer does not loop.
 */
(function () {
  var scheduled = false;
  var observer = null;

  function labelCodeNav(root) {
    var scope = root && root.querySelectorAll ? root : document;
    var navs = scope.querySelectorAll
      ? scope.querySelectorAll(".md-code__nav")
      : [];
    if (root && root.classList && root.classList.contains("md-code__nav")) {
      navs = [root];
    }
    Array.prototype.forEach.call(navs, function (nav, index) {
      if (!nav.getAttribute("aria-label") && !nav.getAttribute("aria-labelledby")) {
        nav.setAttribute("aria-label", "Code block actions " + (index + 1));
      }
    });
  }

  function focusableScrollRegions(root) {
    var scope = root && root.querySelectorAll ? root : document;
    var wraps = scope.querySelectorAll
      ? scope.querySelectorAll(".md-typeset__scrollwrap")
      : [];
    if (root && root.classList && root.classList.contains("md-typeset__scrollwrap")) {
      wraps = [root];
    }
    Array.prototype.forEach.call(wraps, function (wrap, index) {
      if (!wrap.hasAttribute("tabindex")) {
        wrap.setAttribute("tabindex", "0");
      }
      if (!wrap.getAttribute("role")) {
        wrap.setAttribute("role", "region");
      }
      if (!wrap.getAttribute("aria-label") && !wrap.getAttribute("aria-labelledby")) {
        wrap.setAttribute("aria-label", "Scrollable content " + (index + 1));
      }
    });
  }

  function applyAll(root) {
    labelCodeNav(root);
    focusableScrollRegions(root);
  }

  function scheduleApply(root) {
    if (scheduled) return;
    scheduled = true;
    window.requestAnimationFrame(function () {
      scheduled = false;
      applyAll(root || document);
    });
  }

  function startObserver() {
    if (observer || typeof MutationObserver !== "function") return;
    var target = document.querySelector(".md-content") || document.body;
    if (!target) return;
    observer = new MutationObserver(function (mutations) {
      for (var i = 0; i < mutations.length; i += 1) {
        var mutation = mutations[i];
        if (mutation.type !== "childList") continue;
        if (mutation.addedNodes && mutation.addedNodes.length) {
          scheduleApply(target);
          return;
        }
      }
    });
    observer.observe(target, {childList: true, subtree: true});
  }

  function boot() {
    applyAll(document);
    startObserver();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
