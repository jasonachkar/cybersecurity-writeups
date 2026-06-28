---
title: "Kubernetes Multi-Tenancy: Hardening RBAC, NetworkPolicies, and Workload Isolation Boundaries"
type: cloud-security
tags: [Kubernetes, Multi-Tenancy, OPA Gatekeeper, NetworkPolicy, Container Security]
date: 2026-06
readingTime: 22
---

# Kubernetes Multi-Tenancy: Hardening RBAC, NetworkPolicies, and Workload Isolation Boundaries

## Executive Summary

Kubernetes has become the operating system of the cloud, hosting diverse workloads across namespaces and business units. However, Kubernetes was not designed with hard multi-tenancy in mind. The container runtime shares the host operating system's kernel, making container escapes a constant risk. By default, namespaces in Kubernetes are logical divisions, not secure security boundaries. Without deliberate security engineering, any pod in a cluster can communicate with any other pod, query the cluster's internal DNS, and potentially extract secrets from the local Kubernetes API.

At scale, the failure to implement network segmentation, secure RBAC configurations, and strict admission control policies turns a single microservice compromise into a cluster-wide take-over. Attackers exploit weak Pod Security Standards to schedule privileged workloads, mount host directories, and capture service account tokens to escalate privileges. This whitepaper analyzes the attack paths from pod compromise to control plane takeover. It provides defensive architecture patterns using Kubernetes NetworkPolicies, OPA Gatekeeper, and sandboxed runtimes to achieve secure multi-tenancy.

---

## Threat Model and Attack Surface

In a multi-tenant Kubernetes cluster, the threat model assumes that one of the tenants (or a pod running a tenant's code) is either malicious or compromised.

```
                  [ Compromised Pod / Container ]
                                 │
                        ( HostPath Escape )
                                 │
                                 ▼
                   [ Access Host File System ]
                                 │
               ┌─────────────────┴─────────────────┐
               ▼                                   ▼
      [ Steal Kubelet Config ]           [ Steal Cloud Credentials ]
               │                                   │
               ▼                                   ▼
      [ Control Plane Takeover ]         [ Cloud Platform Takeover ]
```

### Threat Vectors and Kill-Chains

1. **Pod Escape via HostPath Mounts**:
   - *Adversary Goal*: Gain root access to the underlying worker node.
   - *Attack Vector*: An attacker compromises a pod running in a namespace with lax security policies. The pod is configured to mount `/var/log` or the root directory `/` of the worker node using `hostPath`. The attacker writes a malicious cron job or modifies a system binary in the mounted host directory, executing arbitrary commands with root privileges on the node.
2. **Identity Theft via Service Account Token Harvesting**:
   - *Adversary Goal*: Acquire administrative tokens to query the Kubernetes API.
   - *Attack Vector*: Every pod by default mounts a Service Account token at `/var/run/secrets/kubernetes.io/serviceaccount/token`. An attacker compromises a pod, extracts this JWT token, and uses it to authenticate to the Kubernetes API server from their workstation. If RBAC bindings are overly permissive (e.g. wildcard verbs or secrets-access on default service accounts), the attacker escalates permissions across the cluster.
3. **Cross-Tenant Network Probing and Lateral Movement**:
   - *Adversary Goal*: Intercept or alter traffic belonging to another tenant in the same cluster.
   - *Attack Vector*: A database service runs in namespace `finance` without network segmentation. An attacker compromises an application pod in namespace `marketing`. Because NetworkPolicies are not configured, the attacker port-scans the internal network, identifies the database in `finance`, and logs in using brute-forced credentials or exploits unpatched service vulnerabilities.

---

## Deep Technical Body

### The Mechanics of Node Compromise (Container Escape)

Container isolation relies on Linux kernel namespaces (cgroups, pid, mount, network, ipc, uts). If a container runs in `privileged` mode or mounts sensitive host systems, these namespaces are bypassed.

#### The hostPath Mount Attack Path
Consider a pod YAML configuration where a developer mounted `/var/run/docker.sock` or the node's root filesystem:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: admin-helper-pod
spec:
  containers:
  - name: helper
    image: alpine
    command: ["sleep", "3600"]
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
```

If an attacker compromises this pod:
1. They navigate to `/host/etc/shadow` to dump node user passwords.
2. They access `/host/etc/kubernetes/kubelet.conf` which contains the worker node's client certificate and credentials.
3. Using the kubelet credentials, they send API requests directly to the control plane, masquerading as the worker node. Since nodes have permissions to read secrets and write statuses for pods assigned to them (via the Node Authorization mode), the attacker can pull secrets across the cluster.

### Network Isolation Failures and Default Trust
In Kubernetes, the network is flat. Pods receive unique IPs and can communicate with any other pod in the cluster, even across namespaces.
* **DNS Reconnaissance**: Any pod can query the internal DNS provider (`coredns.kube-system.svc.cluster.local`) to map out all services across all namespaces.
* **Cloud Metadata Service Exfiltration**: If a pod runs on a cloud provider (e.g., AWS or GCP) and the node's IMDS is not restricted, the pod can query `http://169.254.169.254/latest/meta-data/` to retrieve the worker node's IAM instance profile credentials, potentially compromising the parent cloud account.

---

## Defensive Architecture

A secure multi-tenant architecture must implement network micro-segmentation, lock down pod capabilities, and enforce compliance using admission controllers.

### Hardened NetworkPolicy: Namespace Isolation
By default, block all ingress and egress traffic, then explicitly allow traffic only between designated services and system components like CoreDNS.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: tenant-a
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-internal-namespace-traffic-only
  namespace: tenant-a
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {} # Allow ingress only from pods in the same namespace
```

### OPA Gatekeeper Policy: Block Privileged Containers and HostPath Mounts
Deploy Gatekeeper to validate configurations. The following ConstraintTemplate blocks any pod that attempts to run as privileged or uses hostPath mounts.

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sblockhostpath
spec:
  crd:
    spec:
      names:
        kind: K8sBlockHostPath
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sblockhostpath

        violation[{"msg": msg}] {
          volume := input.review.object.spec.volumes[_]
          has_field(volume, "hostPath")
          msg := sprintf("HostPath volume mount is forbidden: %v", [volume.name])
        }

        has_field(obj, field) {
          _ := obj[field]
        }
```

To instantiate this policy, create the Constraint resource:
```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockHostPath
metadata:
  name: block-hostpath-mounts
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

---

## Tooling and Implementation

Secure multi-tenancy requires active runtime inspection and policy enforcement tools:

1. **OPA Gatekeeper / Kyverno**: Enforce Pod Security Standards (PSS) dynamically. They replace legacy Pod Security Policies (PSPs) and reject pods that attempt to run with root group IDs, host namespaces (`hostPID`, `hostNetwork`, `hostIPC`), or insecure capabilities.
2. **Cilium Network Engine**: Replace default CNI plugins with Cilium. Cilium uses eBPF (Extended Berkeley Packet Filter) to apply NetworkPolicies at the Linux kernel level, providing high-performance, L7-aware application routing security.
3. **Kata Containers / gVisor**: For hard tenancy (running untrusted or third-party code), isolate workloads using sandboxed container runtimes. gVisor intercepts system calls and runs them in a user-space kernel, preventing container breakout attacks from compromising the host OS.

---

## Kubernetes Security Audit Checklist

| Item | Focus Area | Verification Step / Command | Target State |
| :--- | :--- | :--- | :--- |
| 1 | Pod Security Standards | Check if namespaces enforce the `restricted` pod security profile. | `kubectl get ns -o jsonpath='{.items[*].metadata.labels}'` contains `pod-security.kubernetes.io/enforce: restricted`. |
| 2 | Auto-mounting Tokens | Inspect if pods auto-mount API tokens when not required. | Pod specifications define `automountServiceAccountToken: false`. |
| 3 | Network Segmentation | Confirm if NetworkPolicies exist in every tenant namespace. | `kubectl get netpol -n <namespace>` returns at least one active policy. |
| 4 | Host Access | Verify that pods are blocked from running with `hostNetwork` or `hostPID`. | Admission controller rules block these configurations. |
| 5 | Metadata Protection | Ensure access to `169.254.169.254` is blocked at the network level. | Network policies or node-level iptables rules block pod access to the cloud metadata service. |
| 6 | Namespace RBAC | Audit Roles and RoleBindings to check for tenant administrative isolation. | No tenant has permissions to modify resources in sister namespaces or write cluster-level resources. |

---

## References

* *Kubernetes Pod Security Standards*: [Kubernetes Documentation](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
* *OPA Gatekeeper Constraints and Templates*: [Gatekeeper Library](https://open-policy-agent.github.io/gatekeeper/website/docs/howto)
* *Securing GKE Multi-Tenancy (Shopify SSRF case study)*: [Google Cloud Security Blog](https://cloud.google.com/blog/products/containers-kubernetes/gke-security-metadata-concealment/)
* *NIST Special Publication 800-190 (Application Container Security Guide)*: [NIST SP 800-190](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
