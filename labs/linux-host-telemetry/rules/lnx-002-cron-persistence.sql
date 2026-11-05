-- id: LNX-002
-- title: System cron entry written by something other than a package manager
-- severity: medium
-- requires: file
-- response: Identify the writer and its parent. If unexplained, preserve the file and its timestamps, then remove the entry; ask the owner before touching a managed host. Per-user spools are NOT covered (see S14).
SELECT e.id AS event_id,
       e.host AS host,
       e.path AS subject,
       'written by ' || e.exe AS detail
FROM events e
WHERE e.event = 'file_write'
  AND (e.path GLOB '/etc/cron.d/*' OR e.path GLOB '/etc/cron.hourly/*' OR e.path GLOB '/etc/cron.daily/*'
       OR e.path GLOB '/etc/cron.weekly/*' OR e.path GLOB '/etc/cron.monthly/*' OR e.path = '/etc/crontab')
  AND basename(e.exe) NOT IN ('dpkg', 'apt', 'apt-get', 'rpm', 'dnf', 'yum', 'unattended-upgr')
  AND NOT is_allowed('LNX-002', e.ts, e.exe, e.cmdline, e.path, '');
