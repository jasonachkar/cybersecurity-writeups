-- id: LNX-003
-- title: systemd unit written by a non-package-manager whose ExecStart is in a writable directory
-- severity: high
-- requires: file
-- requires_fields: exec_start
-- response: Disable and preserve the unit (do not delete), capture the referenced binary and its hash, and review how the writer got here. Telemetry must carry the parsed ExecStart (a file-integrity sensor that parses units); a bare path event cannot support this rule.
SELECT e.id AS event_id,
       e.host AS host,
       e.path AS subject,
       'ExecStart=' || e.exec_start || ' written by ' || e.exe AS detail
FROM events e
WHERE e.event = 'file_write'
  AND (e.path GLOB '/etc/systemd/system/*' OR e.path GLOB '/usr/lib/systemd/system/*' OR e.path GLOB '/lib/systemd/system/*'
       OR e.path GLOB '/home/*/.config/systemd/user/*' OR e.path GLOB '/root/.config/systemd/user/*')
  AND basename(e.exe) NOT IN ('dpkg', 'apt', 'apt-get', 'rpm', 'dnf', 'yum', 'unattended-upgr')
  AND (e.exec_start GLOB '/tmp/*' OR e.exec_start GLOB '/var/tmp/*' OR e.exec_start GLOB '/dev/shm/*'
       OR e.exec_start GLOB '/home/*' OR e.exec_start GLOB '/root/*')
  AND NOT is_allowed('LNX-003', e.ts, e.exe, e.cmdline, e.path, '');
