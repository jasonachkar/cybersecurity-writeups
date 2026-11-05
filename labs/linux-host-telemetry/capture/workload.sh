#!/bin/sh
# Runs INSIDE a throwaway busybox container as PID 1. Every action is a harmless
# analog of a behaviour the detection rules look for: it writes placeholder files in
# the container's own filesystem and reads the container's own /etc/shadow. Nothing
# is persisted outside the container and nothing leaves the private lab network.
# $CANARY is the IP of a local busybox httpd on the same bridge (set by the caller).
sleep 3   # give the host tracer time to attach to this PID

# LNX-002 analog: a cron.d entry holding only a comment
mkdir -p /etc/cron.d
echo '# lab placeholder, no command' > /etc/cron.d/lab-job

# LNX-005 analog: read the container's own shadow file
cat /etc/shadow > /dev/null

# LNX-006 analog: a sudoers.d drop-in holding only a comment (sudo is not installed)
mkdir -p /etc/sudoers.d
echo '# lab placeholder' > /etc/sudoers.d/90-lab

# LNX-007 analog: setuid bit on a copy of /bin/true inside /tmp
cp /bin/true /tmp/lab-copy
chmod 4755 /tmp/lab-copy

# LNX-009 analog: truncate a log file the script just created
mkdir -p /var/log
echo x > /var/log/lab.log
: > /var/log/lab.log

# LNX-004 NEGATIVE control: an executable in /tmp connects to a PRIVATE address.
# The rule is about PUBLIC destinations, so this must stay silent.
cp /bin/wget /tmp/wget
/tmp/wget -q -T 2 -O /dev/null "http://$CANARY:9000/" || true

sleep 1
