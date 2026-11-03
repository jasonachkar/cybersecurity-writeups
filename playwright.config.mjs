import {defineConfig} from "playwright/test";

export default defineConfig({
  testDir: ".",
  timeout: 30_000,
  expect: {timeout: 5_000, toHaveScreenshot: {animations: "disabled", caret: "hide", maxDiffPixelRatio: 0.01}},
  fullyParallel: false,
  workers: 1,
  reporter: "line",
  // Native fonts and SVG rounding differ across macOS and Linux. Review both
  // baselines instead of weakening the pixel comparison.
  snapshotPathTemplate: `{testDir}/tests/docs/visual-baselines/${process.platform}/{arg}{ext}`,
  outputDir: ".artifacts/playwright",
  use: {locale: "en-CA", timezoneId: "America/Toronto", reducedMotion: "reduce"},
});
