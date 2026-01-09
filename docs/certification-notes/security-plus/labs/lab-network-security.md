---
Title: "Security+ Lab: Network Security & Segmentation — Firewall + Packet Capture + Mini-IDS (Local Lab)"
Certification: "CompTIA Security+ (SY0-701)"
Exam Objective Focus:
  - "3.x Security Architecture: segmentation, secure network design"
  - "4.4 Security alerting/monitoring: packet capture, logs"
  - "2.x Threats & mitigations: reduce attack surface with allowlisting"
Difficulty: "Beginner → Advanced (Optional Extensions)"
Estimated Time: "3–8 hours (depending on extensions)"
Last Updated: "2026-01-09"
---

# Security+ Lab: Network Security & Segmentation — Firewall + Packet Capture + Mini-IDS (Local Lab)

## What makes this lab impressive
You’ll build a realistic mini-network:
- DMZ segment hosting a web service
- Internal segment hosting a client
- A router/firewall enforcing **deny-by-default**
- Proof via:
  - blocked vs allowed traffic tests (curl/nc/nmap)
  - packet captures (pcap + Wireshark)
- Optional: Suricata IDS running locally to show alerting on suspicious traffic

Everything is contained locally (safe + legal).

---

## Success criteria
You can demonstrate:
1. Segmentation: Internal cannot reach DMZ until routing is allowed
2. Firewall: Only required ports/protocols are permitted
3. Evidence: pcaps prove what happened on the wire
4. Optional IDS: alerts trigger on a scan pattern

---

## Topology
We will create two Docker networks:
- `dmz_net`: hosts `dmz-web` (nginx)
- `internal_net`: hosts `internal-client`
A third container `net-router` connects both and enforces firewall rules.

> This mirrors a common enterprise pattern: **internal → firewall/router → DMZ service**.

---

## Prerequisites
- Docker Desktop
- Wireshark installed on host (recommended)
- Basic CLI tools

---

# Part 1 — Build Segments (Docker Networks)

## 1.1 Create segmented networks
```bash
docker network create dmz_net
docker network create internal_net
````

## 1.2 Start DMZ web server

```bash
docker run -d --name dmz-web --network dmz_net nginx:alpine
```

## 1.3 Start internal client

```bash
docker run -it --name internal-client --network internal_net alpine:3.20 sh
```

Inside the client container:

```sh
apk add --no-cache curl bind-tools iproute2 busybox-extras netcat-openbsd nmap
```

## 1.4 Validate segmentation (should fail)

Inside `internal-client`:

```sh
curl -i http://dmz-web 2>/dev/null || echo "DENIED (expected): internal cannot resolve/reach DMZ service"
```

**Expected**

* No reachability yet (segmentation is working)

---

# Part 2 — Introduce a Router/Firewall Node

## 2.1 Create router container and attach to both networks

On host:

```bash
docker run -d --name net-router --network dmz_net alpine:3.20 sleep infinity
docker network connect internal_net net-router
```

## 2.2 Enable IP forwarding and install iptables/tcpdump

```bash
docker exec -it net-router sh -lc "apk add --no-cache iptables tcpdump iproute2 && sysctl -w net.ipv4.ip_forward=1"
```

## 2.3 Discover IPs

On host:

```bash
DMZ_WEB_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{if eq .NetworkID (index $.NetworkSettings.Networks \"dmz_net\").NetworkID}}{{.IPAddress}}{{end}}{{end}}' dmz-web 2>/dev/null || true)"
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' dmz-web
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' net-router
```

Simpler (works fine):

```bash
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' dmz-web
```

Copy the DMZ web IP. You’ll use it throughout:

* `<DMZ_WEB_IP>`

---

# Part 3 — Firewall Policy (Deny-by-Default + Allowlist)

## 3.1 Set deny-by-default forwarding on router

On host:

```bash
docker exec -it net-router sh -lc '
iptables -P FORWARD DROP
iptables -F FORWARD

# Allow established/related flows back
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow internal -> DMZ web on tcp/80 only
iptables -A FORWARD -p tcp --dport 80 -j ACCEPT

echo "FORWARD chain:"
iptables -S FORWARD
'
```

> Note: Docker itself manipulates iptables on the host; this lab keeps firewalling inside the router container for clarity.

---

## 3.2 Validate allowed traffic

Inside `internal-client`:

```sh
curl -I http://<DMZ_WEB_IP>/ && echo "ALLOWED (expected): HTTP to DMZ works"
```

## 3.3 Validate blocked traffic (attack surface reduction)

Inside `internal-client`:

```sh
# Try SSH port (not allowed)
nc -vz <DMZ_WEB_IP> 22 && echo "UNEXPECTED" || echo "DENIED (expected): TCP/22 blocked"

# Try HTTPS port (not allowed)
nc -vz <DMZ_WEB_IP> 443 && echo "UNEXPECTED" || echo "DENIED (expected): TCP/443 blocked"
```

## 3.4 Prove with a scan (contained, safe)

Inside `internal-client`:

```sh
nmap -Pn -p 1-1000 <DMZ_WEB_IP>
```

**Expected**

* Port 80 open
* Most others filtered/closed

**Evidence:** screenshot or save output.

---

# Part 4 — Packet Capture Evidence (tcpdump + Wireshark)

## 4.1 Live capture of HTTP traffic on router

On host (terminal A):

```bash
docker exec -it net-router sh -lc "tcpdump -i any -nn tcp port 80"
```

In `internal-client` (terminal B):

```sh
curl -I http://<DMZ_WEB_IP>/
```

You should see SYN/SYN-ACK/ACK and HTTP traffic in tcpdump.

## 4.2 Save a PCAP and open in Wireshark

On host:

```bash
docker exec -it net-router sh -lc "tcpdump -i any -w /tmp/netlab.pcap -nn"
```

Generate traffic (curl + scan), then stop tcpdump (Ctrl+C). Copy PCAP out:

```bash
docker cp net-router:/tmp/netlab.pcap ./netlab.pcap
```

Open `netlab.pcap` in Wireshark and document:

* TCP handshake (SYN/SYN-ACK/ACK)
* HTTP request/response
* Any scan patterns (SYNs without completing sessions)

---

# Part 5 — Host Firewall Variant (UFW on a VM) (Optional but great)

If you also have a VM web server, show the same concept at host level:

On VM:

```bash
sudo apt update
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw enable
sudo ufw status verbose
```

Validate from another machine:

```bash
curl -I http://<vm-ip>/
nc -vz <vm-ip> 22
nc -vz <vm-ip> 443
```

---

# Part 6 (Optional Advanced) — Mini IDS with Suricata (Very Impressive)

This adds “monitoring + alerting” realism.

## 6.1 Run Suricata on the host (easy mode)

If you can install Suricata on your host/VM:

* Start it on the interface that sees traffic (e.g., docker bridge or VM interface)
* Run the nmap scan again
* Check for alerts in `fast.log` / `eve.json`

## 6.2 Alternative: Suricata container (advanced)

You can run Suricata in a privileged container attached to the same networks or sniffing the docker bridge.
Document:

* What interface you captured
* Which rule triggered
* The alert metadata

> Even if you don’t fully operationalize it, describing the design and constraints is useful.

---

# Evidence Pack (What to commit)

Create:
`docs/certification-notes/security-plus/labs/evidence/network-security/`

Include:

* `01-segmentation-deny.txt` (initial failed curl)
* `02-firewall-rules.txt` (iptables FORWARD chain)
* `03-allowed-http.txt` (curl success)
* `04-blocked-ports.txt` (nc failures)
* `05-nmap-results.txt` (scan results)
* `06-packet-capture.md` (Wireshark screenshots + explanation)
* Optional: `07-ids-alerts.txt` / `eve.json` snippets (if you do Suricata)

**Redaction tip:** remove IPs if you want, but it’s fine to keep lab IPs.

---

# Reflection Questions (write short answers)

1. What security benefit did segmentation provide before routing was enabled?
2. Why is “deny-by-default + allowlist” safer than “allow all + block some”?
3. What did the packet capture prove that logs alone could not?
4. If port 80 is allowed, what app-layer controls should also exist (TLS, auth, input validation)?

---

# Troubleshooting

## Internal client can’t reach DMZ even on port 80

* Confirm `net-router` has IP forwarding enabled:

  ```bash
  docker exec -it net-router sh -lc "sysctl net.ipv4.ip_forward"
  ```
* Confirm iptables rules exist:

  ```bash
  docker exec -it net-router sh -lc "iptables -S FORWARD"
  ```
* Confirm you’re curling the DMZ IP, not the container name.

## Docker networking surprises

Docker manipulates iptables and forwarding behavior on the host; that’s normal. If host policies are too restrictive, container traffic can be impacted. Document what you observed and why it matters.

---

# Cleanup

```bash
docker rm -f internal-client dmz-web net-router || true
docker network rm dmz_net internal_net || true
rm -f ./netlab.pcap || true
```

---

# Security+ Mapping Notes (quick)

* Segmentation / DMZ concepts
* Firewall allowlisting and reduced attack surface
* Monitoring/validation via packet capture
* Optional IDS thinking and alerting
---

[1]: https://docs.docker.com/engine/network/firewall-iptables/?utm_source=chatgpt.com "Docker with iptables"
[2]: https://serverfault.com/questions/130482/how-to-check-sshd-log?utm_source=chatgpt.com "ssh - How to check sshd log?"
