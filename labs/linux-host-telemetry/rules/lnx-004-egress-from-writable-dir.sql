-- id: LNX-004
-- title: Executable in a world-writable directory connects to a public address
-- severity: high
-- requires: net
-- response: Capture the connection and the binary (hash it) before blocking. A block at the egress layer is reversible and preferred to killing the process. Path-based: a binary run from a normal path is NOT covered (see S34).
SELECT e.id AS event_id,
       e.host AS host,
       e.exe || ' -> ' || e.dest_ip || ':' || e.dest_port AS subject,
       'destination class ' || e.dest_class AS detail
FROM events e
WHERE e.event = 'net_connect'
  AND e.dest_class = 'public'
  AND (e.exe GLOB '/tmp/*' OR e.exe GLOB '/var/tmp/*' OR e.exe GLOB '/dev/shm/*')
  AND NOT is_allowed('LNX-004', e.ts, e.exe, e.cmdline, '', '');
