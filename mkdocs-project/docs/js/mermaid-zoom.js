(() => {
  "use strict";

  const MIN_SCALE = 0.5;
  const MAX_SCALE = 4;
  const SCALE_STEP = 0.25;
  const PAN_STEP = 60;
  const PAN_KEYS = {ArrowLeft: [PAN_STEP, 0], ArrowRight: [-PAN_STEP, 0], ArrowUp: [0, PAN_STEP], ArrowDown: [0, -PAN_STEP]};

  function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
  }

  function enhance(mermaidEl) {
    if (mermaidEl.dataset.zoomReady === "true") return;
    mermaidEl.dataset.zoomReady = "true";

    const wrapper = document.createElement("div");
    wrapper.className = "docs-mermaid";
    const viewport = document.createElement("div");
    viewport.className = "docs-mermaid__viewport";
    viewport.tabIndex = 0;
    viewport.setAttribute("role", "group");
    viewport.setAttribute("aria-label", "Diagram viewer. Drag to pan. Use the zoom controls, plus and minus, or the arrow keys.");

    mermaidEl.insertAdjacentElement("beforebegin", wrapper);
    wrapper.append(viewport);
    viewport.append(mermaidEl);

    const controls = document.createElement("div");
    controls.className = "docs-mermaid__controls";
    controls.innerHTML = `
      <button type="button" data-mermaid-zoom-out aria-label="Zoom out">−</button>
      <span class="docs-mermaid__zoom-level" data-mermaid-zoom-level aria-live="polite">100%</span>
      <button type="button" data-mermaid-zoom-in aria-label="Zoom in">+</button>
      <button type="button" data-mermaid-reset aria-label="Reset diagram view">Reset</button>
    `;
    wrapper.append(controls);

    const hint = document.createElement("p");
    hint.className = "docs-mermaid__hint";
    hint.textContent = "Drag to pan. Hold Ctrl and scroll, or pinch, to zoom.";
    wrapper.append(hint);

    const zoomLevel = controls.querySelector("[data-mermaid-zoom-level]");
    let scale = 1;
    let x = 0;
    let y = 0;
    let panning = false;
    let startX = 0;
    let startY = 0;

    function apply() {
      mermaidEl.style.transform = (scale === 1 && x === 0 && y === 0) ? "" : `translate(${x}px, ${y}px) scale(${scale})`;
      zoomLevel.textContent = `${Math.round(scale * 100)}%`;
    }

    function setScale(next) {
      scale = clamp(next, MIN_SCALE, MAX_SCALE);
      apply();
    }

    function reset() {
      scale = 1;
      x = 0;
      y = 0;
      apply();
    }

    controls.querySelector("[data-mermaid-zoom-in]").addEventListener("click", () => setScale(scale + SCALE_STEP));
    controls.querySelector("[data-mermaid-zoom-out]").addEventListener("click", () => setScale(scale - SCALE_STEP));
    controls.querySelector("[data-mermaid-reset]").addEventListener("click", reset);

    viewport.addEventListener("wheel", event => {
      if (!event.ctrlKey && !event.metaKey) return;
      event.preventDefault();
      setScale(scale + (event.deltaY > 0 ? -SCALE_STEP : SCALE_STEP));
    }, {passive: false});

    viewport.addEventListener("pointerdown", event => {
      if (event.button !== 0) return;
      panning = true;
      startX = event.clientX - x;
      startY = event.clientY - y;
      viewport.classList.add("is-panning");
      viewport.setPointerCapture(event.pointerId);
    });
    viewport.addEventListener("pointermove", event => {
      if (!panning) return;
      x = event.clientX - startX;
      y = event.clientY - startY;
      apply();
    });
    ["pointerup", "pointercancel"].forEach(type => viewport.addEventListener(type, () => {
      panning = false;
      viewport.classList.remove("is-panning");
    }));

    viewport.addEventListener("dblclick", reset);

    viewport.addEventListener("keydown", event => {
      if (PAN_KEYS[event.key]) {
        event.preventDefault();
        const [dx, dy] = PAN_KEYS[event.key];
        x += dx;
        y += dy;
        apply();
      } else if (event.key === "+" || event.key === "=") {
        event.preventDefault();
        setScale(scale + SCALE_STEP);
      } else if (event.key === "-" || event.key === "_") {
        event.preventDefault();
        setScale(scale - SCALE_STEP);
      } else if (event.key === "0") {
        event.preventDefault();
        reset();
      }
    });
  }

  // Material renders each diagram into a closed shadow root (mermaid.render() + attachShadow),
  // so there is no SVG or data-processed attribute to observe from the light DOM. The `div.mermaid`
  // itself only exists once rendering is done (it replaces `pre.mermaid` at that point), so its
  // insertion is the completion signal.
  function scan() {
    document.querySelectorAll("div.mermaid").forEach(enhance);
  }

  function start() {
    scan();
    new MutationObserver(scan).observe(document.body, {childList: true, subtree: true});
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
