# Security+ Lab: Identity & Access Management (IAM) — Enterprise-Style (Local Lab)

## Why this lab is impressive (portfolio value)
This lab produces **verifiable proof** of IAM controls:
- RBAC and least privilege (roles mapped to real permissions)
- Strong auth (password policy, lockouts, SSH key auth, optional TOTP MFA)
- Privileged Access Management concepts (JIT-style command whitelisting, audited elevation)
- Auditing evidence (auth logs, sudo logs, optional auditd rules)
- Optional: local SSO (Keycloak + OIDC) to demonstrate modern IAM patterns

You’ll end with:
- A working lab environment
- Screenshots/commands showing allowed vs denied actions
- A clean “Findings & Evidence” section you can commit to GitHub

---

## Lab topology (choose one)
### Option A — VM (recommended)
- Ubuntu Server 22.04+ (or Debian)
- OpenSSH enabled
- Snapshots for safe rollback

### Option B — Docker (okay for basics)
- Docker Desktop
- Less realistic for PAM/SSHD edge cases, but still useful

> If your goal is “enterprise-like,” use a VM.

---

## What you will build
A Linux “app server” with:
- Users and roles (RBAC via groups)
- App folders protected by POSIX permissions + ACLs
- SSH access restricted by role
- Sudo-based privilege separation (command allow-list)
- Password policy enforcement + lockout protection
- Evidence collection (logs, optional auditd)
- Optional: Keycloak SSO and OIDC-protected service

---

## Success criteria (checklist)
You can demonstrate:
1. **RBAC**: users have only the permissions their role needs
2. **Least privilege**: sensitive config is not readable by non-admin roles
3. **Authentication hardening**: password policy + lockouts OR key-only SSH
4. **Privileged access**: admin actions are constrained and logged
5. **Auditing**: you can point to log entries proving access attempts and elevation

---

## Prerequisites
On the server VM:
```bash
sudo apt update
sudo apt install -y openssh-server acl sudo curl jq
sudo systemctl enable --now ssh
````

Create a snapshot now:

* Name it: `baseline-iam`

---

# Part 1 — Identities and Roles (RBAC)

## 1.1 Create role groups

We’ll create three roles:

* `app_readers`: read-only access to app data
* `app_writers`: can write data/logs, but not config
* `app_admins`: can administer config + controlled privileged actions

```bash
sudo groupadd app_readers
sudo groupadd app_writers
sudo groupadd app_admins
```

## 1.2 Create users

```bash
sudo useradd -m -s /bin/bash alice
sudo useradd -m -s /bin/bash bob
sudo useradd -m -s /bin/bash carol

sudo passwd alice
sudo passwd bob
sudo passwd carol
```

## 1.3 Assign roles

```bash
sudo usermod -aG app_readers alice
sudo usermod -aG app_writers bob
sudo usermod -aG app_admins carol

id alice && id bob && id carol
getent group app_readers
getent group app_writers
getent group app_admins
```

**Expected**

* `alice` has readers group
* `bob` has writers group
* `carol` has admins group

---

# Part 2 — Authorization (Least Privilege on Real Resources)

## 2.1 Create an “app” resource tree

```bash
sudo mkdir -p /srv/app/{config,data,logs,bin}
sudo tee /srv/app/data/public.txt >/dev/null <<< "public info"
sudo tee /srv/app/config/appsettings.secret >/dev/null <<< "sensitive config - do not expose"
sudo tee /srv/app/config/admin-notes.txt >/dev/null <<< "admin-only notes"
```

## 2.2 Apply base permissions

### Strategy

* `/srv/app/config`: admins only
* `/srv/app/data`: readers can read, writers can write, admins full
* `/srv/app/logs`: writers + admins
* `/srv/app/bin`: restricted scripts, admins can manage, others can only run if allowed (later)

```bash
sudo chown -R root:app_admins /srv/app
sudo chmod 750 /srv/app

# config: admins only
sudo chown -R root:app_admins /srv/app/config
sudo chmod 770 /srv/app/config

# data/logs: writers group ownership
sudo chown -R root:app_writers /srv/app/data /srv/app/logs
sudo chmod 770 /srv/app/data /srv/app/logs

# bin: admins manage; execution rules come later
sudo chown -R root:app_admins /srv/app/bin
sudo chmod 750 /srv/app/bin
```

## 2.3 Add ACL for read-only group on data

```bash
sudo setfacl -R -m g:app_readers:rx /srv/app/data
sudo setfacl -R -m d:g:app_readers:rx /srv/app/data
sudo getfacl /srv/app/data | sed -n '1,80p'
```

## 2.4 Validate authorization (allowed vs denied)

### Test as `alice` (reader)

```bash
sudo -iu alice bash -lc '
set -e
echo "[alice] read data:"; cat /srv/app/data/public.txt
echo "[alice] try write data:"; (echo "nope" >> /srv/app/data/public.txt) && echo "UNEXPECTED" || echo "DENIED as expected"
echo "[alice] try read config:"; (cat /srv/app/config/appsettings.secret) && echo "UNEXPECTED" || echo "DENIED as expected"
'
```

### Test as `bob` (writer)

```bash
sudo -iu bob bash -lc '
set -e
echo "[bob] write data:"; echo "writer ok" >> /srv/app/data/public.txt
echo "[bob] create log:"; echo "$(date) bob log" >> /srv/app/logs/bob.log
echo "[bob] try read config:"; (cat /srv/app/config/appsettings.secret) && echo "UNEXPECTED" || echo "DENIED as expected"
'
```

### Test as `carol` (admin role)

```bash
sudo -iu carol bash -lc '
set -e
echo "[carol] read config:"; (cat /srv/app/config/appsettings.secret) && echo "ALLOWED as expected"
echo "[carol] write config:"; echo "admin changed config $(date)" >> /srv/app/config/admin-notes.txt
'
```

**Evidence tip:** screenshot these outputs.

---

# Part 3 — Authentication Hardening

## 3.1 Enforce stronger password quality (PAM)

Install:

```bash
sudo apt install -y libpam-pwquality
```

Edit:

```bash
sudo nano /etc/pam.d/common-password
```

Add or ensure a `pam_pwquality` line exists (example policy):

* minlen 14
* require upper/lower/digit/special
* limit repeats

Example (may vary by distro; keep it simple and documented):

```conf
password requisite pam_pwquality.so retry=3 minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=2
```

### Validate

Try setting a weak password for `alice` and observe rejection, then set a strong one.

**Evidence:** capture terminal output.

---

## 3.2 Account lockouts with pam_faillock (VM snapshot recommended)

On Ubuntu, this can be configured via `/etc/security/faillock.conf` and PAM stack changes (implementation varies by distro and version). If you’re uncomfortable, do it in a snapshot and roll back if needed.

### Configure faillock policy

Edit:

```bash
sudo nano /etc/security/faillock.conf
```

Suggested policy (reasonable for lab):

```conf
deny = 5
unlock_time = 600
fail_interval = 600
```

### Enable pam_faillock in PAM stack (Ubuntu-style)

Edit:

```bash
sudo nano /etc/pam.d/common-auth
```

Common pattern (place near `pam_unix.so` lines; order matters):

```conf
auth required pam_faillock.so preauth silent
auth [default=die] pam_faillock.so authfail
auth sufficient pam_faillock.so authsucc
```

> If your distro uses `pam-auth-update` profiles, you may need to create a file under `/usr/share/pam-configs/` and enable it (document what you did).

### Validate lockout

Attempt 5 bad passwords for `bob` via SSH or `su`, then test correct password and confirm lockout behavior. Check counters:

```bash
sudo faillock --user bob
```

**Evidence:** show lockout message + faillock counters.

---

## 3.3 Passwordless SSH (strong baseline)

### Generate SSH key on your host

```bash
ssh-keygen -t ed25519 -C "iam-lab"
```

### Copy key for admin role (carol)

```bash
ssh-copy-id carol@<vm-ip>
```

### Disable risky SSH settings (recommended)

Edit:

```bash
sudo nano /etc/ssh/sshd_config
```

Set:

```conf
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
```

Restart:

```bash
sudo systemctl restart ssh
```

### Validate

* Confirm you can log in via SSH key
* Confirm password SSH login fails

---

# Part 4 — Authorization at the Door (Restrict SSH by Role)

Only allow SSH for users in `app_admins` and optionally `app_writers`.
This is extremely common in real environments.

Edit:

```bash
sudo nano /etc/ssh/sshd_config
```

Add:

```conf
AllowGroups app_admins app_writers
```

Restart:

```bash
sudo systemctl restart ssh
```

Validate:

* `alice` should be denied SSH
* `bob` allowed
* `carol` allowed

**Evidence:** capture the denial/accept.

---

# Part 5 — Privileged Access Management Concepts (JIT-ish + Command Whitelisting)

## 5.1 Create a controlled admin action script

Create a “safe admin action” (restart a service, rotate logs, view status).
Example: a log rotation script in `/srv/app/bin/rotate-logs.sh`.

```bash
sudo tee /srv/app/bin/rotate-logs.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="/srv/app/logs"
ARCHIVE_DIR="/srv/app/logs/archive"
mkdir -p "$ARCHIVE_DIR"

ts="$(date +%Y%m%d_%H%M%S)"
tar -czf "${ARCHIVE_DIR}/logs_${ts}.tar.gz" -C "$LOG_DIR" .
find "$LOG_DIR" -maxdepth 1 -type f -name "*.log" -delete

echo "Rotated logs at ${ts}"
EOF

sudo chmod 750 /srv/app/bin/rotate-logs.sh
sudo chown root:app_admins /srv/app/bin/rotate-logs.sh
```

## 5.2 Allow ONLY this command via sudo (least privilege)

Edit:

```bash
sudo visudo
```

Add:

```conf
# Command allow-list: carol can run only this as root
carol ALL=(root) NOPASSWD: /srv/app/bin/rotate-logs.sh
```

Validate:

```bash
sudo -iu carol bash -lc "sudo /srv/app/bin/rotate-logs.sh"
```

Try something not allowed:

```bash
sudo -iu carol bash -lc "sudo cat /etc/shadow && echo UNEXPECTED || echo DENIED as expected"
```

**Why this matters**
This demonstrates the PAM idea of “privileged operations” without giving blanket root access.

---

# Part 6 — Auditing & Evidence (Logs + Optional auditd)

## 6.1 SSH and sudo logs

On Ubuntu/Debian, SSH auth and sudo are typically recorded in:

* `/var/log/auth.log`

View recent:

```bash
sudo tail -n 80 /var/log/auth.log
sudo grep -iE "sshd|sudo|pam" /var/log/auth.log | tail -n 80
```

If your system uses systemd-only logging, use:

```bash
sudo journalctl -u ssh --no-pager | tail -n 120
```

## 6.2 Optional: auditd for high-signal auditing (impressive)

Install:

```bash
sudo apt install -y auditd audispd-plugins
sudo systemctl enable --now auditd
```

Track access to sensitive config:

```bash
sudo auditctl -w /srv/app/config -p rwa -k app_config_access
```

Generate events (attempt reads/writes), then search:

```bash
sudo ausearch -k app_config_access --start today
```

> Document what you observed and why audit logs are valuable for investigations.

---

# Part 7 (Optional Advanced) — Local SSO with Keycloak + OIDC (Very Impressive)

This section demonstrates modern IAM:

* IdP (Keycloak)
* OIDC client
* Group-to-role mapping conceptually

> This is “bonus mode.” It’s okay if you skip; include it if you want your portfolio to stand out.

## 7.1 Run Keycloak (Docker)

On your machine (or VM with Docker):

```bash
docker run -d --name keycloak \
  -p 8081:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

Open:

* [http://localhost:8081](http://localhost:8081)
  Login:
* admin / admin

## 7.2 Create realm + users + groups

In Keycloak:

1. Create Realm: `iam-lab`
2. Create Groups: `app_readers`, `app_writers`, `app_admins`
3. Create Users: `alice`, `bob`, `carol`
4. Assign each user to the matching group

## 7.3 (Optional) Protect a local app via OIDC

You can run an OIDC-aware reverse proxy such as oauth2-proxy in front of a simple app.
If you do this, document:

* Client registration
* Redirect URI
* Proof that unauthenticated users are redirected
* Proof that group claim can be used to enforce role-based access

**Portfolio tip:** even if you only complete realm/users/groups, that’s still valuable evidence of IdP concepts.

---

# Evidence Pack (What to commit)

Create a folder:
`docs/certification-notes/security-plus/labs/evidence/iam/`

Include:

* `01-rbac-tests.txt` (copy terminal outputs)
* `02-ssh-allowgroups.txt`
* `03-password-policy.txt`
* `04-lockout-faillock.txt` (if done)
* `05-sudo-allowlist.txt`
* `06-audit-logs.txt` (if done)
* Screenshots (redact IPs/usernames if desired)

---

# Troubleshooting

## SSH denied unexpectedly

* Check group membership: `id <user>`
* SSH reads groups at login; ensure user logs out fully and retries.
* Confirm `AllowGroups` is correct and sshd restarted.

## auth.log missing

* Some distros rely on systemd journal:

  * `journalctl -u ssh` or `journalctl -t sshd`

## PAM changes broke logins

* Roll back to snapshot `baseline-iam`
* Or revert changes in `/etc/pam.d/common-*`

---

# Findings / Reflection (fill this in)

* What is the difference between authentication and authorization in your lab?
* Which control had the biggest security impact (and why)?
* What usability trade-offs did you notice?
* What would you change for production (centralized IAM, SSO, PAM vault, etc.)?

---

# Security+ Mapping Notes (quick)

* RBAC, least privilege, privileged access concepts
* Password best practices, passwordless (SSH keys), account lockout
* Auditing and monitoring via logs / auditd
* Optional: IdP/SSO with OIDC (modern enterprise IAM)
