-- id: LNX-007
-- title: setuid or setgid bit set on a file by a non-package-manager
-- severity: high
-- requires: file
-- response: Hash the file, list who can execute it, and remove the bit only after capturing evidence. Directories are excluded because setgid on a shared directory is a normal pattern.
SELECT e.id AS event_id,
       e.host AS host,
       e.path AS subject,
       'mode ' || printf('%o', e.mode) || ' set by ' || e.exe AS detail
FROM events e
WHERE e.event = 'file_chmod'
  AND (e.mode & 2048 OR e.mode & 1024)
  AND (e.is_dir IS NULL OR e.is_dir = 0)
  AND basename(e.exe) NOT IN ('dpkg', 'apt', 'apt-get', 'rpm', 'dnf', 'yum', 'unattended-upgr')
  AND NOT is_allowed('LNX-007', e.ts, e.exe, e.cmdline, e.path, '');
