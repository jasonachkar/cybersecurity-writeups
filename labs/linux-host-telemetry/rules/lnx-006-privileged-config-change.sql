-- id: LNX-006
-- title: Authentication, authorization or loader configuration written by a non-designed tool
-- severity: high
-- requires: file
-- response: Compare the file with the last known-good copy and the change record. If there is no record, treat as unauthorized: preserve, revert, and review the writer's session. Legitimate manual changes (tee, editors) alert by design; attach a change reference rather than allowlisting the tool.
SELECT e.id AS event_id,
       e.host AS host,
       e.path AS subject,
       'written by ' || e.exe AS detail
FROM events e
WHERE e.event = 'file_write'
  AND (e.path = '/etc/sudoers' OR e.path GLOB '/etc/sudoers.d/*'
       OR e.path IN ('/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow', '/etc/ld.so.preload')
       OR e.path GLOB '/etc/pam.d/*' OR e.path GLOB '/etc/ssh/sshd_config*')
  AND basename(e.exe) NOT IN ('visudo', 'useradd', 'usermod', 'userdel', 'groupadd', 'groupmod', 'groupdel',
                              'passwd', 'chpasswd', 'chage', 'vipw', 'vigr',
                              'dpkg', 'apt', 'apt-get', 'rpm', 'dnf', 'yum', 'unattended-upgr')
  AND NOT is_allowed('LNX-006', e.ts, e.exe, e.cmdline, e.path, '');
