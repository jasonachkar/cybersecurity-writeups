-- id: LNX-001
-- title: Network-facing service or its descendant starts a shell or interpreter
-- severity: high
-- requires: exec
-- response: Read-only triage first (process tree, the request that preceded it). Contain the workload only after ruling out an owned pattern; do not isolate a production host on this alert alone.
-- Ancestry is resolved by process IDENTITY (host, boot, pid, start time), not pid alone,
-- so a recycled pid cannot attach a process to the wrong parent.
WITH RECURSIVE anc(child_id, host, boot_id, pid, pstart, ppid, ppstart, depth, exe) AS (
  SELECT e.id, e.host, e.boot_id, e.pid, e.pstart, e.ppid, e.ppstart, 0, e.exe
  FROM events e
  WHERE e.event = 'process_start'
    AND basename(e.exe) IN ('sh', 'bash', 'dash', 'ash', 'zsh', 'ksh', 'perl', 'ruby', 'nc', 'ncat', 'socat')
  UNION ALL
  SELECT a.child_id, p.host, p.boot_id, p.pid, p.pstart, p.ppid, p.ppstart, a.depth + 1, p.exe
  FROM anc a
  JOIN events p
    ON p.event = 'process_start'
   AND p.host = a.host AND p.boot_id = a.boot_id
   AND p.pid = a.ppid AND p.pstart = a.ppstart
  WHERE a.depth < 3
)
SELECT c.id AS event_id,
       c.host AS host,
       basename(a.exe) || ' > ' || basename(c.exe) AS subject,
       'service ancestor ' || a.exe || ' at depth ' || MIN(a.depth) AS detail
FROM anc a
JOIN events c ON c.id = a.child_id
WHERE a.depth BETWEEN 1 AND 3
  AND basename(a.exe) IN ('nginx', 'apache2', 'httpd', 'php-fpm8.3', 'php-fpm', 'gunicorn', 'uwsgi', 'tomcat9', 'node')
  AND NOT is_allowed('LNX-001', c.ts, c.exe, c.cmdline, '', a.exe)
GROUP BY c.id;
