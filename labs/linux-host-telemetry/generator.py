#!/usr/bin/env python3
"""Deterministic SYNTHETIC host telemetry with labeled scenarios.

Nothing here records or simulates a real intrusion. Every event is generated from a
fixed seed, carries "synthetic": true, and describes a behaviour only as data
(a path, an exe name, a destination in a documentation address range). No malicious
code exists in this lab. Scenarios are labeled so detections can be scored:

  malicious_pattern  - a behaviour a detection SHOULD flag
  benign_lookalike   - legitimate activity that resembles a malicious pattern
  evasion            - a malicious pattern the shipped rules are KNOWN to miss
  control            - ordinary activity that nothing should flag

Usage: generator.py [--seed N] [--out events.jsonl] [--scenarios scenarios.json]
"""
import argparse
import datetime as dt
import json
import random
import sys

HOST = "lab-host-01"
BOOT = "boot-0001-synthetic"
T0 = dt.datetime(2026, 11, 5, 9, 0, 0, tzinfo=dt.timezone.utc)

# Documentation-only address ranges (RFC 5737): never route to a real host.
PUBLIC_A, PUBLIC_B = "203.0.113.50", "198.51.100.7"


class Builder:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.events = []
        self.scenarios = []
        self.next_pid = 2000
        self.clock = 0.0  # seconds since T0
        self.start_ns = 1_000_000_000

    # ---- primitives -------------------------------------------------------
    def tick(self, seconds=None):
        self.clock += seconds if seconds is not None else self.rng.uniform(0.2, 3.0)
        return self.clock

    def ts(self, offset):
        return (T0 + dt.timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def proc(self, ppid, ppstart, exe, cmdline, uid=0, tty=None, pid=None):
        pid = pid or self.next_pid
        if pid == self.next_pid:
            self.next_pid += self.rng.randint(1, 9)
        self.start_ns += self.rng.randint(10_000_000, 900_000_000)
        return {"pid": pid, "pstart": self.start_ns, "ppid": ppid, "ppstart": ppstart, "exe": exe, "cmdline": cmdline, "uid": uid, "tty": tty}

    def emit(self, scenario, kind, source, proc, lag=None, **extra):
        t = self.tick()
        lag = self.rng.uniform(0.2, 2.5) if lag is None else lag
        event = {
            "ts": self.ts(t), "ingest_ts": self.ts(t + lag), "host": HOST, "boot_id": BOOT,
            "source": source, "event": kind, "pid": proc["pid"], "pstart": proc["pstart"],
            "ppid": proc["ppid"], "ppstart": proc["ppstart"], "uid": proc["uid"], "exe": proc["exe"],
            "cmdline": proc["cmdline"], "tty": proc["tty"], "scenario": scenario, "synthetic": True, "origin": "synthetic-generator",
        }
        event.update(extra)
        self.events.append(event)
        return event

    def start(self, scenario, proc, lag=None):
        return self.emit(scenario, "process_start", "exec", proc, lag=lag)

    def scenario(self, sid, name, klass, expect, note, requires=(), evades=()):
        self.scenarios.append({"id": sid, "name": name, "class": klass, "expected_rules": sorted(expect), "evades": sorted(evades), "note": note, "requires_sources": sorted(requires)})
        return sid


def build(seed):
    b = Builder(seed)
    R = b.rng

    # A long-running parent chain that scenarios hang off: init -> sshd -> bash (admin) and init -> nginx master.
    init = b.proc(0, 0, "/sbin/init", "/sbin/init", pid=1)
    b.start("bg", init)
    sshd = b.proc(1, init["pstart"], "/usr/sbin/sshd", "sshd: /usr/sbin/sshd -D")
    b.start("bg", sshd)
    admin_bash = b.proc(sshd["pid"], sshd["pstart"], "/usr/bin/bash", "-bash", uid=1000, tty="pts/0")
    b.start("bg", admin_bash)
    nginx = b.proc(1, init["pstart"], "/usr/sbin/nginx", "nginx: master process")
    b.start("bg", nginx)
    nginx_worker = b.proc(nginx["pid"], nginx["pstart"], "/usr/sbin/nginx", "nginx: worker process", uid=33)
    b.start("bg", nginx_worker)
    phpfpm = b.proc(1, init["pstart"], "/usr/sbin/php-fpm8.3", "php-fpm: master process")
    b.start("bg", phpfpm)
    phpfpm_w = b.proc(phpfpm["pid"], phpfpm["pstart"], "/usr/sbin/php-fpm8.3", "php-fpm: pool www", uid=33)
    b.start("bg", phpfpm_w)
    gunicorn = b.proc(1, init["pstart"], "/usr/bin/gunicorn", "gunicorn: master [app]", uid=1001)
    b.start("bg", gunicorn)
    cron = b.proc(1, init["pstart"], "/usr/sbin/cron", "/usr/sbin/cron -f")
    b.start("bg", cron)

    # ---- background noise: ordinary activity nothing should flag -------------
    for i in range(400):
        kind = R.choice(["cronjob", "nginx_read", "sshd_login", "logrotate", "apt"])
        if kind == "cronjob":
            p = b.proc(cron["pid"], cron["pstart"], "/usr/bin/run-parts", "run-parts --report /etc/cron.hourly")
            b.start("bg", p)
            c = b.proc(p["pid"], p["pstart"], "/usr/bin/find", "find /var/tmp -mtime +7 -delete")
            b.start("bg", c)
        elif kind == "nginx_read":
            b.emit("bg", "file_read", "file", nginx_worker, path=R.choice(["/var/www/html/index.html", "/etc/nginx/mime.types", "/var/www/html/app.js"]))
        elif kind == "sshd_login":
            p = b.proc(sshd["pid"], sshd["pstart"], "/usr/sbin/unix_chkpwd", "unix_chkpwd alice nullok")
            b.start("bg", p)
            b.emit("bg", "file_read", "file", p, path="/etc/shadow")
        elif kind == "logrotate":
            p = b.proc(cron["pid"], cron["pstart"], "/usr/sbin/logrotate", "logrotate /etc/logrotate.conf")
            b.start("bg", p)
            b.emit("bg", "file_truncate", "file", p, path=R.choice(["/var/log/syslog", "/var/log/auth.log"]))
        else:
            p = b.proc(cron["pid"], cron["pstart"], "/usr/bin/dpkg", "dpkg --configure -a")
            b.start("bg", p)
            b.emit("bg", "file_write", "file", p, path=R.choice(["/etc/cron.d/logrotate", "/etc/default/locale", "/etc/passwd"]))
        b.tick(R.uniform(0.5, 4.0))

    # ======================= LNX-001  service spawns shell ======================
    b.tick(30)
    s = b.scenario("S01", "nginx worker starts a shell", "malicious_pattern", ["LNX-001"], "depth-1 ancestry from a network-facing service")
    sh = b.proc(nginx_worker["pid"], nginx_worker["pstart"], "/bin/sh", "sh -c id", uid=33)
    b.start(s, sh)

    s = b.scenario("S02", "php-fpm worker descendant starts bash", "malicious_pattern", ["LNX-001"], "depth-2 ancestry: service > helper > shell")
    helper = b.proc(phpfpm_w["pid"], phpfpm_w["pstart"], "/usr/bin/php8.3", "php /var/www/html/upload.php", uid=33)
    b.start(s, helper)
    bash = b.proc(helper["pid"], helper["pstart"], "/usr/bin/bash", "bash -i", uid=33)
    b.start(s, bash)

    s = b.scenario("S03", "php-fpm runs an allowlisted image converter via sh", "benign_lookalike", [], "suppressed by an allowlist entry with an owner and an expiry")
    b.start(s, b.proc(phpfpm_w["pid"], phpfpm_w["pstart"], "/bin/sh", "sh -c convert /tmp/in.png -resize 200x /tmp/out.png", uid=33))

    s = b.scenario("S04", "gunicorn app shells out to git", "benign_lookalike", ["LNX-001"], "RESIDUAL FALSE POSITIVE: legitimate, not allowlisted; needs an owner decision")
    b.start(s, b.proc(gunicorn["pid"], gunicorn["pstart"], "/bin/sh", "sh -c git rev-parse HEAD", uid=1001))

    s = b.scenario("S05", "admin reloads nginx from an ssh session", "control", [], "parent is the admin shell, not the service")
    b.start(s, b.proc(admin_bash["pid"], admin_bash["pstart"], "/usr/sbin/nginx", "nginx -t", uid=1000, tty="pts/0"))

    # S06: PID reuse. Process A (pid 61000) was a child of nginx; it exits. The kernel reuses
    # 61000 for B, a child of the admin shell, which then starts a shell C. Resolving C's parent by pid
    # alone can land on A (a nginx descendant) and wrongly alert; resolving by pid + start time cannot.
    s = b.scenario("S06", "PID reuse: a benign shell reuses pid 61000 of a former nginx child", "control", [], "identity (pid + start time) prevents misattribution; a pid-only join would alert")
    a = b.proc(nginx_worker["pid"], nginx_worker["pstart"], "/usr/bin/gzip", "gzip -c access.log", uid=33, pid=61000)
    b.start(s, a)
    reused = b.proc(admin_bash["pid"], admin_bash["pstart"], "/usr/bin/bash", "bash -c ls", uid=1000, tty="pts/0", pid=61000)
    b.start(s, reused)
    child = b.proc(61000, reused["pstart"], "/bin/sh", "sh -c ls", uid=1000, tty="pts/0")
    b.start(s, child)

    # ======================= LNX-002  cron persistence ===========================
    b.tick(30)
    s = b.scenario("S10", "shell writes /etc/cron.d", "malicious_pattern", ["LNX-002"], "non-package-manager writer creates a system cron entry")
    p = b.proc(sshd["pid"], sshd["pstart"], "/bin/sh", "sh -c echo '* * * * * root /tmp/.x/u' > /etc/cron.d/update", uid=0)
    b.start(s, p)
    b.emit(s, "file_write", "file", p, path="/etc/cron.d/update")

    s = b.scenario("S11", "dpkg updates /etc/cron.d during an upgrade", "benign_lookalike", [], "package manager writer")
    p = b.proc(admin_bash["pid"], admin_bash["pstart"], "/usr/bin/dpkg", "dpkg --configure cron", uid=0)
    b.start(s, p)
    b.emit(s, "file_write", "file", p, path="/etc/cron.d/e2scrub_all")

    s = b.scenario("S12", "configuration management writes /etc/cron.d", "benign_lookalike", [], "suppressed by an allowlist entry with an owner and an expiry")
    p = b.proc(sshd["pid"], sshd["pstart"], "/usr/bin/python3", "python3 /root/.ansible/tmp/ansible-tmp-1/AnsiballZ_cron.py", uid=0)
    b.start(s, p)
    b.emit(s, "file_write", "file", p, path="/etc/cron.d/backup")

    s = b.scenario("S13", "admin edits /etc/cron.d/backup with vim", "benign_lookalike", ["LNX-002"], "RESIDUAL FALSE POSITIVE: a legitimate manual change; correlate with a change record")
    p = b.proc(admin_bash["pid"], admin_bash["pstart"], "/usr/bin/vim.basic", "vim /etc/cron.d/backup", uid=0, tty="pts/0")
    b.start(s, p)
    b.emit(s, "file_write", "file", p, path="/etc/cron.d/backup")

    s = b.scenario("S14", "user crontab written by the crontab binary", "evasion", [], "KNOWN MISS: the per-user spool is excluded because crontab(1) is its legitimate writer", evades=["LNX-002"])
    p = b.proc(sshd["pid"], sshd["pstart"], "/usr/bin/crontab", "crontab -", uid=33)
    b.start(s, p)
    b.emit(s, "file_write", "file", p, path="/var/spool/cron/crontabs/www-data")

    # ======================= LNX-003  systemd unit from a writable dir ==========
    b.tick(30)
    s = b.scenario("S20", "shell installs a unit whose ExecStart is under /tmp", "malicious_pattern", ["LNX-003"], "persistence via a unit pointing at a world-writable path")
    p = b.proc(sshd["pid"], sshd["pstart"], "/bin/sh", "sh -c cat > /etc/systemd/system/update-helper.service", uid=0)
    b.start(s, p)
    b.emit(s, "file_write", "file", p, path="/etc/systemd/system/update-helper.service", exec_start="/tmp/.x/helper")

    s = b.scenario("S21", "dpkg installs a service unit", "benign_lookalike", [], "package manager writer, ExecStart in /usr")
    p = b.proc(admin_bash["pid"], admin_bash["pstart"], "/usr/bin/dpkg", "dpkg --unpack foo.deb", uid=0)
    b.start(s, p)
    b.emit(s, "file_write", "file", p, path="/lib/systemd/system/foo.service", exec_start="/usr/bin/foo")

    s = b.scenario("S22", "admin installs an app unit under /opt", "benign_lookalike", [], "non-package writer but ExecStart is not under a writable directory")
    p = b.proc(admin_bash["pid"], admin_bash["pstart"], "/usr/bin/tee", "tee /etc/systemd/system/app.service", uid=0, tty="pts/0")
    b.start(s, p)
    b.emit(s, "file_write", "file", p, path="/etc/systemd/system/app.service", exec_start="/opt/app/bin/app")

    s = b.scenario("S23", "developer user unit under /home", "benign_lookalike", ["LNX-003"], "RESIDUAL FALSE POSITIVE: user units under /home are a normal developer workflow")
    p = b.proc(admin_bash["pid"], admin_bash["pstart"], "/usr/bin/bash", "bash -c systemctl --user edit dev", uid=1000, tty="pts/0")
    b.start(s, p)
    b.emit(s, "file_write", "file", p, path="/home/dev/.config/systemd/user/dev.service", exec_start="/home/dev/bin/serve")

    # ======================= LNX-004  egress from an unexpected process ==========
    b.tick(30)
    s = b.scenario("S30", "binary in /tmp connects to a public address", "malicious_pattern", ["LNX-004"], "exe under a world-writable directory with a public destination", requires=["net"])
    p = b.proc(sshd["pid"], sshd["pstart"], "/tmp/.cache/agent", "/tmp/.cache/agent", uid=33)
    b.start(s, p)
    b.emit(s, "net_connect", "net", p, dest_ip=PUBLIC_A, dest_port=4444, dest_class="public")

    s = b.scenario("S31", "binary in /dev/shm connects out over 443", "malicious_pattern", ["LNX-004"], "same rule, TLS port: the port is not the signal", requires=["net"])
    p = b.proc(sshd["pid"], sshd["pstart"], "/dev/shm/x", "/dev/shm/x", uid=33)
    b.start(s, p)
    b.emit(s, "net_connect", "net", p, dest_ip=PUBLIC_B, dest_port=443, dest_class="public")

    s = b.scenario("S32", "admin curls a public HTTPS endpoint", "control", [], "ordinary exe path", requires=["net"])
    p = b.proc(admin_bash["pid"], admin_bash["pstart"], "/usr/bin/curl", "curl https://example.invalid/", uid=1000, tty="pts/0")
    b.start(s, p)
    b.emit(s, "net_connect", "net", p, dest_ip=PUBLIC_B, dest_port=443, dest_class="public")

    s = b.scenario("S33", "CI toolchain unpacked in /tmp fetches dependencies", "benign_lookalike", ["LNX-004"], "RESIDUAL FALSE POSITIVE: build tools run from /tmp; allowlist by exe hash or run builds elsewhere", requires=["net"])
    p = b.proc(admin_bash["pid"], admin_bash["pstart"], "/tmp/ci-tools/bin/node", "/tmp/ci-tools/bin/node install", uid=1000)
    b.start(s, p)
    b.emit(s, "net_connect", "net", p, dest_ip=PUBLIC_B, dest_port=443, dest_class="public")

    s = b.scenario("S34", "system bash makes an outbound connection", "evasion", [], "KNOWN MISS: the exe path is ordinary, so path-based egress logic does not see it", requires=["net"], evades=["LNX-004"])
    p = b.proc(sshd["pid"], sshd["pstart"], "/usr/bin/bash", "bash -i", uid=33)
    b.start(s, p)
    b.emit(s, "net_connect", "net", p, dest_ip=PUBLIC_A, dest_port=4444, dest_class="public")

    # ======================= LNX-005  sensitive file read ========================
    b.tick(30)
    s = b.scenario("S40", "python reads /etc/shadow as www-data", "malicious_pattern", ["LNX-005"], "unexpected reader of the shadow file")
    p = b.proc(phpfpm_w["pid"], phpfpm_w["pstart"], "/usr/bin/python3", "python3 -c open('/etc/shadow')", uid=33)
    b.start(s, p)
    b.emit(s, "file_read", "file", p, path="/etc/shadow")

    s = b.scenario("S41", "binary in /tmp reads cloud credentials", "malicious_pattern", ["LNX-005"], "credential file read by an unexpected process")
    p = b.proc(sshd["pid"], sshd["pstart"], "/tmp/.x/h", "/tmp/.x/h", uid=1000)
    b.start(s, p)
    b.emit(s, "file_read", "file", p, path="/home/alice/.aws/credentials")

    s = b.scenario("S42", "unix_chkpwd reads /etc/shadow at login", "control", [], "the designed reader; also covered in the background noise")
    p = b.proc(sshd["pid"], sshd["pstart"], "/usr/sbin/unix_chkpwd", "unix_chkpwd bob nullok")
    b.start(s, p)
    b.emit(s, "file_read", "file", p, path="/etc/shadow")

    s = b.scenario("S43", "backup agent reads shadow and ssh keys", "benign_lookalike", [], "suppressed by an allowlist entry with an owner and an expiry")
    p = b.proc(cron["pid"], cron["pstart"], "/opt/backup/agent", "/opt/backup/agent --nightly")
    b.start(s, p)
    b.emit(s, "file_read", "file", p, path="/etc/shadow")

    s = b.scenario("S44", "nightly audit scanner reads /etc/shadow", "benign_lookalike", ["LNX-005"], "RESIDUAL FALSE POSITIVE: a legitimate scanner with no allowlist entry")
    p = b.proc(cron["pid"], cron["pstart"], "/opt/auditscan/scan", "/opt/auditscan/scan --permissions")
    b.start(s, p)
    b.emit(s, "file_read", "file", p, path="/etc/shadow")

    s = b.scenario("S45", "an allowlisted tool keeps running after its exception expired", "malicious_pattern", ["LNX-005"], "the exception for /opt/legacy/sync expired 2026-06-30; the same behaviour must alert again")
    p = b.proc(cron["pid"], cron["pstart"], "/opt/legacy/sync", "/opt/legacy/sync --all")
    b.start(s, p)
    b.emit(s, "file_read", "file", p, path="/etc/shadow")

    # ======================= LNX-006  privileged configuration change ============
    b.tick(30)
    s = b.scenario("S50", "shell drops a NOPASSWD sudoers file as www-data", "malicious_pattern", ["LNX-001", "LNX-006"], "write to sudoers.d by a non-admin tool")
    p = b.proc(phpfpm_w["pid"], phpfpm_w["pstart"], "/bin/sh", "sh -c echo 'www-data ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-web", uid=0)
    b.start(s, p)
    b.emit(s, "file_write", "file", p, path="/etc/sudoers.d/90-web")

    s = b.scenario("S51", "write to /etc/ld.so.preload", "malicious_pattern", ["LNX-006"], "a loader preload entry is not a routine change")
    p = b.proc(sshd["pid"], sshd["pstart"], "/bin/sh", "sh -c echo /tmp/.x/lib.so > /etc/ld.so.preload", uid=0)
    b.start(s, p)
    b.emit(s, "file_write", "file", p, path="/etc/ld.so.preload")

    s = b.scenario("S52", "visudo edits /etc/sudoers", "benign_lookalike", [], "designed editor")
    p = b.proc(admin_bash["pid"], admin_bash["pstart"], "/usr/sbin/visudo", "visudo", uid=0, tty="pts/0")
    b.start(s, p)
    b.emit(s, "file_write", "file", p, path="/etc/sudoers")

    s = b.scenario("S53", "useradd updates passwd, shadow and group", "benign_lookalike", [], "designed account tool")
    p = b.proc(admin_bash["pid"], admin_bash["pstart"], "/usr/sbin/useradd", "useradd -m carol", uid=0, tty="pts/0")
    b.start(s, p)
    for path in ("/etc/passwd", "/etc/shadow", "/etc/group"):
        b.emit(s, "file_write", "file", p, path=path)

    s = b.scenario("S54", "admin applies an approved sudoers.d change with tee", "benign_lookalike", ["LNX-006"], "RESIDUAL FALSE POSITIVE: legitimate and approved; the detection cannot know that without a change record")
    p = b.proc(admin_bash["pid"], admin_bash["pstart"], "/usr/bin/tee", "tee /etc/sudoers.d/dev-team", uid=0, tty="pts/0")
    b.start(s, p)
    b.emit(s, "file_write", "file", p, path="/etc/sudoers.d/dev-team")

    # ======================= LNX-007  setuid / setgid bit set =====================
    b.tick(30)
    s = b.scenario("S60", "chmod u+s on a file in /tmp", "malicious_pattern", ["LNX-007"], "setuid bit set outside a package manager")
    p = b.proc(sshd["pid"], sshd["pstart"], "/bin/chmod", "chmod u+s /tmp/.x/helper", uid=0)
    b.start(s, p)
    b.emit(s, "file_chmod", "file", p, path="/tmp/.x/helper", mode=0o4755, is_dir=False)

    s = b.scenario("S61", "dpkg sets the setuid bit on sudo", "benign_lookalike", [], "package manager writer")
    p = b.proc(admin_bash["pid"], admin_bash["pstart"], "/usr/bin/dpkg", "dpkg --configure sudo", uid=0)
    b.start(s, p)
    b.emit(s, "file_chmod", "file", p, path="/usr/bin/sudo", mode=0o4755, is_dir=False)

    s = b.scenario("S62", "admin sets setgid on a shared directory", "benign_lookalike", [], "directories are excluded: setgid on a directory is a normal sharing pattern")
    p = b.proc(admin_bash["pid"], admin_bash["pstart"], "/bin/chmod", "chmod 2775 /srv/shared", uid=0, tty="pts/0")
    b.start(s, p)
    b.emit(s, "file_chmod", "file", p, path="/srv/shared", mode=0o2775, is_dir=True)

    # ======================= LNX-008  execution from a deleted file or memfd ======
    b.tick(30)
    s = b.scenario("S70", "execution from an anonymous memory file", "malicious_pattern", ["LNX-008"], "fileless execution pattern")
    b.start(s, b.proc(sshd["pid"], sshd["pstart"], "/memfd:payload (deleted)", "/memfd:payload (deleted)", uid=33))

    s = b.scenario("S71", "execution of a binary that was deleted after launch", "malicious_pattern", ["LNX-008"], "the file was unlinked to hide it")
    b.start(s, b.proc(sshd["pid"], sshd["pstart"], "/tmp/.x/h (deleted)", "/tmp/.x/h", uid=33))

    s = b.scenario("S72", "ordinary exec of a system binary", "control", [], "nothing unusual about the path")
    b.start(s, b.proc(admin_bash["pid"], admin_bash["pstart"], "/usr/bin/uname", "uname -a", uid=1000, tty="pts/0"))

    # ======================= LNX-009  audit / log tampering =======================
    b.tick(30)
    s = b.scenario("S80", "shell truncates auth.log and disables auditing", "malicious_pattern", ["LNX-009"], "log truncation by a non-rotation tool, plus auditctl -e 0")
    p = b.proc(sshd["pid"], sshd["pstart"], "/bin/sh", "sh -c : > /var/log/auth.log", uid=0)
    b.start(s, p)
    b.emit(s, "file_truncate", "file", p, path="/var/log/auth.log")
    b.start(s, b.proc(sshd["pid"], sshd["pstart"], "/sbin/auditctl", "auditctl -e 0", uid=0))

    s = b.scenario("S81", "logrotate rotates auth.log", "control", [], "designed rotation tool")
    p = b.proc(cron["pid"], cron["pstart"], "/usr/sbin/logrotate", "logrotate /etc/logrotate.conf")
    b.start(s, p)
    b.emit(s, "file_truncate", "file", p, path="/var/log/auth.log")

    s = b.scenario("S82", "admin truncates a huge log to free disk", "benign_lookalike", ["LNX-009"], "RESIDUAL FALSE POSITIVE: legitimate emergency action; the response is to ask, not to isolate")
    p = b.proc(admin_bash["pid"], admin_bash["pstart"], "/usr/bin/truncate", "truncate -s 0 /var/log/syslog", uid=0, tty="pts/0")
    b.start(s, p)
    b.emit(s, "file_truncate", "file", p, path="/var/log/syslog")

    # ======================= repeated behaviour (deduplication) ====================
    b.tick(30)
    s = b.scenario("S90", "the same suspicious write repeated 50 times", "malicious_pattern", ["LNX-002"], "deduplication: 50 events must produce one alert with a count")
    p = b.proc(sshd["pid"], sshd["pstart"], "/bin/sh", "sh -c while :; do echo x >> /etc/cron.d/loop; done", uid=0)
    b.start(s, p)
    for _ in range(50):
        b.emit(s, "file_write", "file", p, path="/etc/cron.d/loop")
        b.tick(R.uniform(0.2, 1.5))

    # ======================= late-arriving telemetry (ingestion lag) =================
    s = b.scenario("S91", "a detectable write that reaches the pipeline 125 seconds late", "malicious_pattern", ["LNX-001", "LNX-006"], "event time and ingest time diverge: detection latency is dominated by ingestion, not by the rule")
    p = b.proc(phpfpm_w["pid"], phpfpm_w["pstart"], "/bin/sh", "sh -c echo 'x ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/91-late", uid=0)
    b.start(s, p, lag=125.0)
    b.emit(s, "file_write", "file", p, lag=125.0, path="/etc/sudoers.d/91-late")

    return b


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20261105)
    ap.add_argument("--out", default="events.jsonl")
    ap.add_argument("--scenarios", default="scenarios.json")
    args = ap.parse_args()
    b = build(args.seed)
    events = sorted(b.events, key=lambda e: (e["ingest_ts"], e["ts"]))
    for index, event in enumerate(events, 1):
        event["id"] = index
    with open(args.out, "w") as fh:
        for event in events:
            fh.write(json.dumps(event, sort_keys=True) + "\n")
    with open(args.scenarios, "w") as fh:
        json.dump({"seed": args.seed, "scenarios": b.scenarios}, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"{len(events)} synthetic events, {len(b.scenarios)} labeled scenarios (seed {args.seed})", file=sys.stderr)


if __name__ == "__main__":
    main()
