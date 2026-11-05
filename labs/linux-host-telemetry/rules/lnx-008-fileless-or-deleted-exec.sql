-- id: LNX-008
-- title: Process started from an anonymous memory file or from a deleted executable
-- severity: high
-- requires: exec
-- response: Capture /proc/<pid>/exe and the memory mappings while the process is alive (the file is gone, so this is the only copy). Containment follows evidence capture, not the other way round.
SELECT e.id AS event_id,
       e.host AS host,
       e.exe AS subject,
       'cmdline ' || e.cmdline AS detail
FROM events e
WHERE e.event = 'process_start'
  AND (e.exe GLOB '*(deleted)' OR e.exe GLOB '/memfd:*' OR e.exe GLOB '/proc/self/fd/*' OR e.exe GLOB '/dev/fd/*')
  AND NOT is_allowed('LNX-008', e.ts, e.exe, e.cmdline, '', '');
