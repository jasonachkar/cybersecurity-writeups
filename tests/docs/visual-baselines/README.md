# Documentation visual baselines

The `darwin/` and `linux/` directories contain reviewed screenshots for macOS and
Linux. Playwright selects the directory using `process.platform`; native fonts
and SVG rounding can differ between operating systems. Both sets use the pinned
Playwright version in `package-lock.json` and its matching Chromium browser.

After an intentional UI change, run `npm run docs:update-snapshots` on each
supported platform, inspect the resulting images, then run
`npm run docs:test:visual` without updating snapshots. The Linux set is also
checked by the Ubuntu documentation CI job. Do not increase the pixel tolerance
to accept a new design or an unexplained rendering change.

Coverage includes light/dark pages, mobile and desktop sizes, the navigation
drawer, focus mode, expanded source, article pagination, and a colorful diagram.


`npm run docs:test:mobile` separately exercises Chromium with Android touch
emulation and WebKit with an iPhone profile. It checks every indexable route at
320px, plus phone, landscape, and tablet layouts in both themes; navigation and
search focus, touch actions, source controls, pagination, diagram behavior, and
open-overlay accessibility are covered. Screenshots and the run report are
written under `.artifacts/qa/`. This is browser emulation, not a physical-device
certification.


Native touch-scroll/pan injection is additionally checked through Chromium's
DevTools gesture API on macOS. That check is skipped in the pinned Linux
headless container: even a plain-page control does not scroll under the injected
gesture there. Both browser engines still run the touch-tap, layout, overlay,
source, pagination, and diagram-control checks on Linux. The platform limitation
is also recorded in the mobile run report.
