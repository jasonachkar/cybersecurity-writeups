-- id: LNX-009
-- title: Log truncated or deleted by a non-rotation tool, or auditing switched off
-- severity: high
-- requires: file, exec
-- response: Ask before acting: emergency disk clean-ups truncate logs too. Verify the log shipper already holds the pre-truncation data, then correlate with what the actor did in the preceding minutes.
SELECT e.id AS event_id,
       e.host AS host,
       e.path AS subject,
       e.event || ' by ' || e.exe AS detail
FROM events e
WHERE e.event IN ('file_truncate', 'file_delete')
  AND (e.path GLOB '/var/log/*' OR e.path GLOB '/var/log/audit/*' OR e.path GLOB '/var/log/journal/*' OR e.path GLOB '/run/log/journal/*')
  AND basename(e.exe) NOT IN ('logrotate', 'systemd-journald', 'rsyslogd', 'journalctl')
  AND NOT is_allowed('LNX-009', e.ts, e.exe, e.cmdline, e.path, '')
UNION ALL
SELECT e.id, e.host, 'auditctl -e 0', 'cmdline ' || e.cmdline
FROM events e
WHERE e.event = 'process_start'
  AND basename(e.exe) = 'auditctl'
  AND e.cmdline GLOB '*-e 0*'
  AND NOT is_allowed('LNX-009', e.ts, e.exe, e.cmdline, '', '');
