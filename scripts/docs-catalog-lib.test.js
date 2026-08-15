"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { buildCatalog, connectRelations, derivedReadingTime, safeSourcePath } = require("./docs-catalog-lib");

function relationItem(kind, id, order = 10) {
  return {
    kind, id, order, title: id, navTitle: id, url: `/${id}/`, summary: "",
    domainLabel: "Test", sourcePath: `${id}.md`, related: {research: [], labs: [], scripts: []},
    declaredRelated: {},
  };
}

test("reading time ignores fenced code and rounds prose at 225 words", () => {
  const prose = Array.from({length: 226}, () => "control").join(" ");
  assert.equal(derivedReadingTime(`${prose}\n\n\`\`\`js\n${"token ".repeat(500)}\n\`\`\``), 2);
  assert.equal(derivedReadingTime("short article"), 1);
});

test("relations become reciprocal and retain their declared type", () => {
  const research = relationItem("research", "research-item");
  const lab = relationItem("lab", "lab-item");
  research.declaredRelated = {labs: ["lab-item"]};
  connectRelations([research, lab]);
  assert.deepEqual(research.related.labs.map(item => item.id), ["lab-item"]);
  assert.deepEqual(lab.related.research.map(item => item.id), ["research-item"]);
});

test("unknown, duplicate, and self relations fail closed", () => {
  const missing = relationItem("research", "missing-owner");
  missing.declaredRelated = {labs: ["not-a-lab"]};
  assert.throws(() => connectRelations([missing]), /references unknown/);

  const duplicate = relationItem("research", "duplicate-owner");
  duplicate.declaredRelated = {research: ["target", "target"]};
  assert.throws(() => connectRelations([duplicate, relationItem("research", "target")]), /unique IDs/);

  const self = relationItem("research", "self-owner");
  self.declaredRelated = {research: ["self-owner"]};
  assert.throws(() => connectRelations([self]), /self relation/);
});

test("source paths reject traversal and accept repository files", () => {
  assert.throws(() => safeSourcePath("../outside", "test path"), /normalized repository-relative/);
  assert.equal(safeSourcePath("package.json", "test path"), "package.json");
});

test("catalog navigation and output are deterministic", () => {
  const first = buildCatalog();
  const second = buildCatalog();
  assert.equal(JSON.stringify(first), JSON.stringify(second));
  assert.equal(first.featured.length, 4);
  assert.equal(first.recent.length, 5);
  assert.deepEqual(first.navigation.researchGroups.map(group => group.title), [
    "Cloud Security", "Application Security", "DevSecOps", "Threat Intelligence",
  ]);
  for (const group of first.navigation.researchGroups) {
    const orders = group.children.map(child => first.research.find(item => item.sourcePath === child.path).order);
    assert.deepEqual(orders, orders.slice().sort((a, b) => a - b));
  }
});
