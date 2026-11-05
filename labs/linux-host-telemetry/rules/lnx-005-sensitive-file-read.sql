-- id: LNX-005
-- title: Credential or key file read by a process that is not its designed reader
-- severity: high
-- requires: file
-- response: Find the process owner and parent. Treat the credential as exposed only after the reader is confirmed unexpected, then rotate; a nightly scanner or backup agent should be allowlisted with an owner and an expiry rather than left to fire.
SELECT e.id AS event_id,
       e.host AS host,
       e.exe || ' reads ' || e.path AS subject,
       'uid ' || e.uid AS detail
FROM events e
WHERE e.event = 'file_read'
  AND (e.path IN ('/etc/shadow', '/etc/gshadow')
       OR e.path GLOB '/etc/ssh/ssh_host_*_key'
       OR e.path GLOB '/root/.ssh/id_*' OR e.path GLOB '/home/*/.ssh/id_*'
       OR e.path GLOB '/root/.aws/credentials' OR e.path GLOB '/home/*/.aws/credentials'
       OR e.path GLOB '/home/*/.kube/config')
  AND basename(e.exe) NOT IN ('sshd', 'login', 'passwd', 'su', 'sudo', 'unix_chkpwd', 'chage', 'vipw', 'vigr',
                              'useradd', 'usermod', 'userdel', 'systemd-logind', 'ssh-keygen')
  AND NOT is_allowed('LNX-005', e.ts, e.exe, e.cmdline, e.path, '');
