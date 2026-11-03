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
