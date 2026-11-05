"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");
const { analyzeCompose, analyzeDockerfile, analyzePath } = require("./policy-check");

const lab = path.resolve(__dirname, "..");
const ids = (findings) => [...new Set(findings.map((f) => f.rule))].sort();

// A compliant service used as the base for single-rule mutations.
const GOOD_SERVICE = `
services:
  app:
    build: .
    user: "65532:65532"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 64m
    pids_limit: 32
    cpus: 0.5
    ports: ["127.0.0.1:8080:8080"]
`;

function composeWith(extra) {
  return GOOD_SERVICE.replace("    build: .\n", `    build: .\n${extra}`);
}

test("the compliant base service has no findings", () => {
  assert.deepEqual(analyzeCompose(GOOD_SERVICE), []);
});

// ---- Compose rules: each is triggered by exactly its own mutation ----------
const composeCases = [
  ["DC001", "    privileged: true\n"],
  ["DC002", "    cap_add: [SYS_ADMIN]\n"],
  ["DC002", "    cap_add: [CAP_NET_ADMIN]\n"],
  ["DC004", "    security_opt: [\"seccomp=unconfined\"]\n"],
  ["DC006", "    volumes: [\"/var/run/docker.sock:/var/run/docker.sock:ro\"]\n"],
  ["DC006", "    volumes: [\"/var/run/docker.sock:/var/run/docker.sock\"]\n"],
  ["DC006", "    volumes: [\"/run/containerd/containerd.sock:/run/containerd/containerd.sock\"]\n"],
  ["DC007", "    volumes: [\"/etc:/host-etc:ro\"]\n"],
  ["DC007", "    volumes: [\"/srv/data:/data\"]\n"],
  ["DC008", "    pid: host\n"],
  ["DC008", "    network_mode: host\n"],
  ["DC014", "    ports: [\"8080:8080\"]\n"],
  ["DC014", "    ports: [\"0.0.0.0:8080:8080\"]\n"],
];
for (const [rule, mutation] of composeCases) {
  test(`${rule} fires for ${mutation.trim()}`, () => {
    // Mutations that replace an existing key are applied by overriding via text edit.
    let source = composeWith(mutation);
    if (mutation.startsWith("    security_opt")) source = GOOD_SERVICE.replace(/    security_opt:.*\n/, mutation);
    if (mutation.startsWith("    ports")) source = GOOD_SERVICE.replace(/    ports:.*\n/, mutation);
    assert.ok(ids(analyzeCompose(source)).includes(rule), JSON.stringify(analyzeCompose(source)));
  });
}

test("a read-only bind mount of a non-sensitive path is accepted", () => {
  assert.deepEqual(analyzeCompose(composeWith("    volumes: [\"/srv/data:/data:ro\"]\n")), []);
});

test("DC007 handles ${VAR:?message} sources without splitting on the colon", () => {
  const findings = analyzeCompose(composeWith("    volumes: [\"${DIR:?set me}:/data\"]\n"));
  assert.deepEqual(ids(findings), ["DC007"]);
  assert.match(findings[0].message, /\$\{DIR:\?set me\}/);
});

test("each missing hardening attribute is reported independently", () => {
  const bare = analyzeCompose("services:\n  app:\n    build: .\n");
  assert.deepEqual(ids(bare), ["DC003", "DC005", "DC009", "DC010", "DC011", "DC012", "DC013"]);
});

test("external images must be digest-pinned; locally built images are exempt", () => {
  const withImage = (image) => composeWith("").replace("    build: .\n", `    image: ${image}\n`);
  assert.ok(ids(analyzeCompose(withImage("busybox:1.37"))).includes("DC015"));
  assert.ok(ids(analyzeCompose(withImage("busybox:latest"))).includes("DC016"));
  assert.deepEqual(analyzeCompose(withImage(`busybox:1.37@sha256:${"a".repeat(64)}`)), []);
  assert.deepEqual(analyzeCompose(GOOD_SERVICE), []);
});

// ---- Dockerfile rules --------------------------------------------------------
const PINNED = `sha256:${"b".repeat(64)}`;
const GOOD_DOCKERFILE = `
FROM golang:1.27-alpine@${PINNED} AS build
RUN go build -o /out/app .
FROM gcr.io/distroless/static-debian12:nonroot@${PINNED}
COPY --from=build /out/app /app/app
USER 65532:65532
HEALTHCHECK CMD ["/app/app", "healthcheck"]
ENTRYPOINT ["/app/app"]
`;

test("the compliant Dockerfile has no findings", () => {
  assert.deepEqual(analyzeDockerfile(GOOD_DOCKERFILE), []);
});

const dockerfileCases = [
  ["DF001", GOOD_DOCKERFILE.replace(`golang:1.27-alpine@${PINNED}`, "golang:1.27-alpine")],
  ["DF002", GOOD_DOCKERFILE.replace(`golang:1.27-alpine@${PINNED}`, `golang:latest@${PINNED}`)],
  ["DF002", GOOD_DOCKERFILE.replace(`golang:1.27-alpine@${PINNED}`, `golang@${PINNED}`)],
  ["DF003", GOOD_DOCKERFILE.replace("USER 65532:65532\n", "")],
  ["DF003", GOOD_DOCKERFILE.replace("USER 65532:65532", "USER root")],
  ["DF004", GOOD_DOCKERFILE.replace("USER 65532:65532", "USER 65532:65532\nENV DB_PASSWORD=<placeholder>")],
  ["DF004", GOOD_DOCKERFILE.replace("USER 65532:65532", "USER 65532:65532\nARG NPM_TOKEN=<placeholder>")],
  ["DF005", GOOD_DOCKERFILE.replace("go build", "chmod -R 777 /src && go build")],
  ["DF006", GOOD_DOCKERFILE.replace(/HEALTHCHECK.*\n/, "")],
  ["DF007", GOOD_DOCKERFILE.replace('ENTRYPOINT ["/app/app"]', "ENTRYPOINT /app/app")],
  ["DF008", GOOD_DOCKERFILE.replace("go build", "curl -fsSL https://example.invalid/i.sh | sh && go build")],
  ["DF008", GOOD_DOCKERFILE.replace("COPY --from", "ADD https://example.invalid/x.tgz /x\nCOPY --from")],
  ["DF009", `FROM golang:1.27-alpine@${PINNED}\nUSER 65532\nHEALTHCHECK CMD [\"x\"]\nRUN go build -o /app .\nENTRYPOINT [\"/app\"]\n`],
];
for (const [rule, source] of dockerfileCases) {
  test(`${rule} fires on its Dockerfile mutation`, () => {
    assert.ok(ids(analyzeDockerfile(source)).includes(rule), JSON.stringify(analyzeDockerfile(source)));
  });
}

test("a stage reference in FROM is not mistaken for an unpinned external image", () => {
  const source = `${GOOD_DOCKERFILE}\nFROM build AS extra\nUSER 1\nHEALTHCHECK CMD [\"x\"]\nENTRYPOINT [\"x\"]\n`;
  assert.deepEqual(ids(analyzeDockerfile(source)).filter((id) => id === "DF001" || id === "DF002"), []);
});

test("a non-secret-looking ENV is not reported as a secret", () => {
  const source = GOOD_DOCKERFILE.replace("USER 65532:65532", "USER 65532:65532\nENV LOG_LEVEL=info\nENV TOKEN_TTL_SECONDS=");
  assert.deepEqual(ids(analyzeDockerfile(source)).filter((id) => id === "DF004"), []);
});

test("line continuations are joined before rules are applied", () => {
  const source = GOOD_DOCKERFILE.replace("go build -o /out/app .", "go build \\\n  -o /out/app . \\\n  && chmod -R 777 /src");
  assert.ok(ids(analyzeDockerfile(source)).includes("DF005"));
});

// ---- The two real stacks -------------------------------------------------------
test("the insecure stack violates every rule the hardened stack is designed to satisfy", () => {
  const found = ids(analyzePath(path.join(lab, "insecure")));
  for (const required of [
    "DF001", "DF003", "DF004", "DF005", "DF006", "DF007", "DF009",
    "DC001", "DC002", "DC003", "DC004", "DC005", "DC006", "DC007", "DC008",
    "DC009", "DC010", "DC011", "DC012", "DC013", "DC014", "DC015",
  ]) {
    assert.ok(found.includes(required), `insecure stack should trigger ${required}; got ${found.join(",")}`);
  }
});

test("the hardened stack has zero findings", () => {
  assert.deepEqual(analyzePath(path.join(lab, "hardened")), []);
});

test("the hardened stack's seccomp profile is default-deny and does not allow escape-relevant syscalls", () => {
  const profile = require(path.join(lab, "hardened", "seccomp.json"));
  assert.equal(profile.defaultAction, "SCMP_ACT_ERRNO");
  const allowed = new Set(
    profile.syscalls.filter((rule) => rule.action === "SCMP_ACT_ALLOW").flatMap((rule) => rule.names),
  );
  for (const name of [
    "mount", "umount2", "setns", "unshare", "ptrace", "bpf", "keyctl", "perf_event_open",
    "userfaultfd", "kexec_load", "init_module", "finit_module", "open_by_handle_at",
    "pivot_root", "chroot", "reboot", "mknodat", "fchownat", "fsopen", "fsmount", "move_mount",
  ]) {
    assert.ok(!allowed.has(name), `${name} must not be allowlisted`);
  }
  // clone is allowed only with a namespace-flag mask; clone3 must fall back via ENOSYS.
  const cloneRule = profile.syscalls.find((rule) => rule.names.includes("clone"));
  assert.equal(cloneRule.args[0].op, "SCMP_CMP_MASKED_EQ");
  assert.equal(cloneRule.args[0].value, 0x7e020000);
  assert.equal(cloneRule.args[0].valueTwo, 0);
  const clone3Rule = profile.syscalls.find((rule) => rule.names.includes("clone3"));
  assert.equal(clone3Rule.action, "SCMP_ACT_ERRNO");
  assert.equal(clone3Rule.errnoRet, 38);
  // The service must still be able to serve: sockets and the runtime hand-off set.
  for (const name of ["socket", "bind", "listen", "accept4", "fstatfs", "statx", "execve"]) {
    assert.ok(allowed.has(name), `${name} must be allowlisted for the service to start`);
  }
});
