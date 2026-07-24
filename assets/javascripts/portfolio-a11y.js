/**
 * Portfolio accessibility helpers.
 * Labels Material-generated code-block navigation landmarks so duplicate
 * role="navigation" regions remain distinguishable for assistive tech.
 */
(function () {
  function labelCodeNav() {
    var navs = document.querySelectorAll(".md-code__nav");
    navs.forEach(function (nav, index) {
      if (!nav.getAttribute("aria-label") && !nav.getAttribute("aria-labelledby")) {
        nav.setAttribute("aria-label", "Code block actions " + (index + 1));
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", labelCodeNav);
  } else {
    labelCodeNav();
  }
  // Material may inject code tooling after first paint.
  window.setTimeout(labelCodeNav, 0);
  window.setTimeout(labelCodeNav, 250);
})();
