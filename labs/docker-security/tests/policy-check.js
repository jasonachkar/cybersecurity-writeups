#!/usr/bin/env node
"use strict";

/**
 * Static policy gate for Dockerfiles and Compose files (no Docker required).
 *
 * This is deliberately a small, readable rule set that encodes the control
 * decisions in the lab README. It is NOT a replacement for a maintained
 * misconfiguration scanner; the lab runs Trivy as well and records where the
 * two disagree. Every rule has a positive and a negative test in
 * policy-check.test.js.
 *
 * Usage: node policy-check.js <dir-or-file>...   (exit 1 when any finding exists)
 */

const fs = require("node:fs");
const path = require("node:path");
const YAML = require("yaml");

const DANGEROUS_CAPS = new Set([
  "ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO",
  "DAC_READ_SEARCH", "SYS_BOOT", "MAC_ADMIN", "BPF", "PERFMON",
]);
const SENSITIVE_HOST_PATHS = ["/", "/etc", "/proc", "/sys", "/dev", "/root", "/home", "/var/lib/docker", "/var/run", "/run"];
const SECRET_NAME = /(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)/i;

/** Logical Dockerfile instructions (line continuations joined, comments dropped). */
function parseDockerfile(source) {
  const lines = source.split(/\r?\n/);
  const out = [];
  let buffer = "";
  let startLine = 0;
  lines.forEach((raw, index) => {
    const trimmed = raw.trim();
    if (!buffer && (trimmed === "" || trimmed.startsWith("#"))) return;
    if (!buffer) startLine = index + 1;
    const continued = trimmed.endsWith("\\");
    buffer += (buffer ? " " : "") + (continued ? trimmed.slice(0, -1).trim() : trimmed);
    if (!continued) {
      const space = buffer.search(/\s/);
      const instruction = (space === -1 ? buffer : buffer.slice(0, space)).toUpperCase();
      const args = space === -1 ? "" : buffer.slice(space + 1).trim();
      out.push({ instruction, args, line: startLine });
      buffer = "";
    }
  });
  return out;
}

function analyzeDockerfile(source, file = "Dockerfile") {
  const findings = [];
  const add = (rule, line, message) => findings.push({ file, rule, line, message });
  const items = parseDockerfile(source);
  const froms = items.filter((item) => item.instruction === "FROM");

  for (const from of froms) {
    const ref = from.args.replace(/^--platform=\S+\s+/, "").split(/\s+/)[0];
    const stageRefs = froms.map((candidate) => (candidate.args.match(/\bAS\s+(\S+)/i) || [])[1]).filter(Boolean);
    if (stageRefs.includes(ref) || ref === "scratch") continue;
    if (!ref.includes("@sha256:")) add("DF001", from.line, `base image ${ref} is not pinned by digest`);
    const tag = ref.split("@")[0].split("/").pop();
    if (!tag.includes(":") || tag.endsWith(":latest")) add("DF002", from.line, `base image ${ref} uses latest or an implicit tag`);
  }

  if (froms.length) {
    const finalStart = items.indexOf(froms[froms.length - 1]);
    const finalStage = items.slice(finalStart);
    const users = finalStage.filter((item) => item.instruction === "USER");
    const lastUser = users.length ? users[users.length - 1].args.split(/\s+/)[0].split(":")[0] : null;
    if (!lastUser || lastUser === "root" || lastUser === "0") add("DF003", froms[froms.length - 1].line, "final stage runs as root (no non-root USER)");
    if (!finalStage.some((item) => item.instruction === "HEALTHCHECK")) add("DF006", froms[froms.length - 1].line, "final stage defines no HEALTHCHECK");
    for (const item of finalStage) {
      if ((item.instruction === "CMD" || item.instruction === "ENTRYPOINT") && !item.args.startsWith("[")) {
        add("DF007", item.line, `${item.instruction} uses shell form; PID 1 will be a shell that does not forward signals`);
      }
    }
    if (froms.length === 1 && items.some((item) => item.instruction === "RUN" && /\b(go build|npm (ci|install)|pip3? install|apt-get install|apk add|make|gcc)\b/.test(item.args))) {
      add("DF009", froms[0].line, "single-stage build: compiler or package manager ships in the runtime image");
    }
  }

  for (const item of items) {
    if ((item.instruction === "ENV" || item.instruction === "ARG")) {
      const match = item.args.match(/^([A-Za-z_][A-Za-z0-9_]*)(?:=|\s+)(.+)$/);
      if (match && SECRET_NAME.test(match[1]) && match[2].replace(/["']/g, "").trim() !== "") {
        add("DF004", item.line, `${item.instruction} ${match[1]} carries a literal value; it persists in image metadata`);
      }
    }
    if (item.instruction === "RUN" && /\bchmod\b[^;&|]*\b(-R\s+)?(0?777|a\+rwx)\b/.test(item.args)) add("DF005", item.line, "world-writable permissions set in the image");
    if (item.instruction === "ADD" && /^(--\S+\s+)*https?:\/\//.test(item.args)) add("DF008", item.line, "ADD from a remote URL is neither pinned nor verified");
    if (item.instruction === "RUN" && /(curl|wget)[^|;&]*\|\s*(sudo\s+)?(sh|bash)\b/.test(item.args)) add("DF008", item.line, "pipes a downloaded script into a shell");
  }
  return findings;
}

function asList(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : Object.entries(value).map(([k, v]) => `${k}=${v}`);
}

/** Split "source:target[:mode]" where source may be a ${VAR:?message} expression. */
function splitVolume(spec) {
  const match = spec.match(/^(\$\{[^}]*\}|[^:]+):(.*)$/);
  return match ? { source: match[1], rest: match[2] } : { source: spec, rest: "" };
}

function normalizeCap(cap) {
  return String(cap).toUpperCase().replace(/^CAP_/, "");
}

function analyzeCompose(source, file = "compose.yaml") {
  const findings = [];
  const document = YAML.parse(source) || {};
  const services = document.services || {};
  for (const [name, service] of Object.entries(services)) {
    const add = (rule, message) => findings.push({ file, service: name, rule, message });
    const local = service.build !== undefined;
    const image = service.image || "";

    if (service.privileged === true) add("DC001", "privileged: true grants all capabilities and device access");
    const capAdd = asList(service.cap_add).map(normalizeCap);
    for (const cap of capAdd) if (DANGEROUS_CAPS.has(cap)) add("DC002", `cap_add ${cap}`);
    const capDrop = asList(service.cap_drop).map(normalizeCap);
    if (!capDrop.includes("ALL")) add("DC003", "cap_drop does not include ALL");

    const securityOpt = asList(service.security_opt).map(String);
    if (securityOpt.some((opt) => /^(seccomp|apparmor)[=:]unconfined$/.test(opt))) add("DC004", "seccomp or AppArmor confinement disabled");
    if (!securityOpt.some((opt) => /^no-new-privileges(:|=)true$/.test(opt) || opt === "no-new-privileges")) add("DC005", "no-new-privileges is not set");

    for (const volume of asList(service.volumes)) {
      const spec = typeof volume === "string" ? volume : `${volume.source}:${volume.target}${volume.read_only ? ":ro" : ""}`;
      const { source, rest } = splitVolume(spec);
      if (/(docker|podman|containerd|crio)\.sock(:|$)/.test(spec)) add("DC006", "container runtime socket mounted (host-root equivalent; :ro on a socket file does not restrict API calls)");
      else if (source.startsWith("/") || source.startsWith("${") || source.startsWith(".")) {
        const normalized = path.posix.normalize(source);
        if (SENSITIVE_HOST_PATHS.includes(normalized)) add("DC007", `sensitive host path ${normalized} bind-mounted`);
        else if (!/(^|:)ro(,|$)/.test(rest.split(":").slice(1).join(":"))) add("DC007", `host bind mount ${source} is writable`);
      }
    }

    for (const key of ["pid", "ipc", "uts", "userns_mode", "network_mode"]) {
      if (service[key] === "host") add("DC008", `${key}: host shares a host namespace`);
    }

    const user = service.user === undefined ? "" : String(service.user);
    if (!user || user === "root" || user.split(":")[0] === "0") add("DC009", "container user is root or unset");
    if (service.read_only !== true) add("DC010", "root filesystem is writable (read_only is not true)");
    const limits = (service.deploy && service.deploy.resources && service.deploy.resources.limits) || {};
    if (!service.mem_limit && !limits.memory) add("DC011", "no memory limit");
    if (!service.pids_limit && !limits.pids) add("DC012", "no PID limit");
    if (!service.cpus && !limits.cpus && !service.cpu_quota) add("DC013", "no CPU limit");

    for (const port of asList(service.ports)) {
      const spec = typeof port === "string" ? port : `${port.host_ip || ""}:${port.published}:${port.target}`;
      const parts = spec.split(":");
      const hostIp = parts.length >= 3 ? parts[0] : "";
      if (hostIp !== "127.0.0.1" && hostIp !== "::1") add("DC014", `published port ${spec} binds all interfaces`);
    }

    if (!local && image && !image.includes("@sha256:")) add("DC015", `external image ${image} is not pinned by digest`);
    if (!local && /:latest$/.test(image)) add("DC016", `external image ${image} uses latest`);
  }
  return findings;
}

function collect(target) {
  const stat = fs.statSync(target);
  if (stat.isDirectory()) {
    return fs.readdirSync(target).sort().flatMap((entry) => collect(path.join(target, entry)));
  }
  return [target];
}

function analyzePath(target) {
  const findings = [];
  for (const file of collect(target)) {
    const base = path.basename(file);
    const text = () => fs.readFileSync(file, "utf8");
    if (base === "Dockerfile" || base.startsWith("Dockerfile.")) findings.push(...analyzeDockerfile(text(), file));
    else if (/^(docker-)?compose(\.[\w-]+)?\.ya?ml$/.test(base)) findings.push(...analyzeCompose(text(), file));
  }
  return findings;
}

module.exports = { analyzeCompose, analyzeDockerfile, analyzePath, parseDockerfile };

if (require.main === module) {
  const targets = process.argv.slice(2);
  if (!targets.length) {
    console.error("usage: policy-check.js <dir-or-file>...");
    process.exit(2);
  }
  const findings = targets.flatMap(analyzePath);
  for (const f of findings) {
    const where = f.line ? `${f.file}:${f.line}` : `${f.file} [${f.service}]`;
    console.log(`${f.rule}  ${where}  ${f.message}`);
  }
  console.log(`${findings.length} finding(s)`);
  process.exit(findings.length ? 1 : 0);
}
