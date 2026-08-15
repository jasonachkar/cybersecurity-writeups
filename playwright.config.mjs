import {defineConfig} from "playwright/test";

export default defineConfig({
  testDir: ".",
  timeout: 30_000,
  expect: {timeout: 5_000, toHaveScreenshot: {animations: "disabled", caret: "hide", maxDiffPixelRatio: 0.01}},
  fullyParallel: false,
  workers: 1,
  reporter: "line",
  snapshotPathTemplate: "{testDir}/tests/docs/visual-baselines/{arg}{ext}",
  outputDir: ".artifacts/playwright",
  use: {locale: "en-CA", timezoneId: "America/Toronto", reducedMotion: "reduce"},
});
