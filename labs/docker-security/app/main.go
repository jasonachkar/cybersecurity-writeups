// Command posture is the workload for labs/docker-security.
//
// It is a deliberately tiny HTTP service plus a set of bounded, benign
// "can I do X?" probes. The probes exist so the lab can OBSERVE container
// runtime posture from inside a running container instead of inferring it from
// configuration files. Every probe either succeeds or reports the errno the
// kernel returned; none of them tries to escape the container, modify the host
// outside an explicitly mounted lab canary directory, or persist anything.
//
// Subcommands:
//
//	serve (default)  HTTP server on :8080 with /healthz and a passive /posture
//	probe            print passive posture plus active probe results as JSON
//	healthcheck      GET /healthz on loopback; exit 0 on 200, 1 otherwise
//	sleep <seconds>  sleep, then exit (child process for forktest)
//	forktest <n>     start up to n sleeping children; report where the kernel said no
//	memtest <MiB>    touch MiB of memory in 1 MiB steps (OOM-kill target)
//	k8sprobe         in-cluster identity and authorization probe (labs/kubernetes-security)
//	tcpcheck host:port  one TCP connect attempt, reported as JSON (labs/kubernetes-security)
//
// Only the Go standard library is used so the image has no module download step.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// capNames maps capability bit numbers to names (capabilities(7)).
var capNames = []string{
	"CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL",
	"SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE", "NET_BIND_SERVICE",
	"NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK", "IPC_OWNER",
	"SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT",
	"SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME",
	"SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL",
	"SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG", "WAKE_ALARM",
	"BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF", "CHECKPOINT_RESTORE",
}

// Posture is the passive view: values read from procfs and cgroupfs only.
type Posture struct {
	UID            int      `json:"uid"`
	GID            int      `json:"gid"`
	CapEffHex      string   `json:"cap_eff_hex"`
	CapEff         []string `json:"cap_eff"`
	CapBndHex      string   `json:"cap_bnd_hex"`
	NoNewPrivs     string   `json:"no_new_privs"`
	SeccompMode    string   `json:"seccomp_mode"`
	SeccompFilters string   `json:"seccomp_filters"`
	RootReadOnly   bool     `json:"root_fs_mounted_read_only"`
	MemoryLimit    string   `json:"memory_limit"`
	PidsLimit      string   `json:"pids_limit"`
	CPUQuota       string   `json:"cpu_quota"`
	PID1Comm       string   `json:"pid1_comm"`
	VisibleProcs   int      `json:"visible_process_count"`
	GoVersion      string   `json:"go_version"`
}

// ProbeResult is one active probe outcome.
type ProbeResult struct {
	Name    string `json:"name"`
	Allowed bool   `json:"allowed"`
	Errno   string `json:"errno,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Report is the full `probe` output.
type Report struct {
	Posture Posture       `json:"posture"`
	Probes  []ProbeResult `json:"probes"`
}

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		os.Exit(serve())
	case "probe":
		os.Exit(probe())
	case "healthcheck":
		os.Exit(healthcheck())
	case "sleep":
		secs, _ := strconv.Atoi(arg(2, "1"))
		time.Sleep(time.Duration(secs) * time.Second)
	case "forktest":
		n, _ := strconv.Atoi(arg(2, "10"))
		os.Exit(forktest(n))
	case "memtest":
		mib, _ := strconv.Atoi(arg(2, "16"))
		os.Exit(memtest(mib))
	case "k8sprobe":
		os.Exit(k8sprobe())
	case "tcpcheck":
		os.Exit(tcpcheck(arg(2, "")))
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", cmd)
		os.Exit(2)
	}
}

func arg(i int, def string) string {
	if len(os.Args) > i {
		return os.Args[i]
	}
	return def
}

// listenAddr lets the lab run the service on a different port when 8080 is taken
// (for example while tracing on the host). Default matches the image's EXPOSE.
func listenAddr() string {
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		return v
	}
	return ":8080"
}

func serve() int {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/posture", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(passivePosture())
	})
	srv := &http.Server{
		Addr:              listenAddr(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		fmt.Fprintln(os.Stderr, "server error:", err)
		return 1
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		return 0
	}
}

func healthcheck() int {
	client := &http.Client{Timeout: 2 * time.Second}
	_, port, err := net.SplitHostPort(listenAddr())
	if err != nil {
		return 1
	}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// statusFields parses "Key:\tvalue" lines of /proc/self/status.
func statusFields() map[string]string {
	fields := map[string]string{}
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return fields
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if ok {
			fields[k] = strings.TrimSpace(v)
		}
	}
	return fields
}

func decodeCaps(hex string) []string {
	v, err := strconv.ParseUint(hex, 16, 64)
	if err != nil {
		return []string{"<unparsable>"}
	}
	names := []string{}
	for bit := 0; bit < 64; bit++ {
		if v&(1<<uint(bit)) == 0 {
			continue
		}
		if bit < len(capNames) {
			names = append(names, capNames[bit])
		} else {
			names = append(names, "CAP_"+strconv.Itoa(bit))
		}
	}
	return names
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unavailable"
	}
	return strings.TrimSpace(string(b))
}

// firstReadable returns the first readable file's trimmed content so the same
// binary reports cgroup v1 and v2 hosts. The first matching path is included
// so a reader can tell which hierarchy answered.
func firstReadable(paths ...string) string {
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(b)) + " (" + p + ")"
		}
	}
	return "unavailable"
}

func rootReadOnly() bool {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		// mountinfo: id parent major:minor root mountpoint options ...
		if len(parts) > 5 && parts[4] == "/" {
			for _, opt := range strings.Split(parts[5], ",") {
				if opt == "ro" {
					return true
				}
			}
			return false
		}
	}
	return false
}

func visibleProcs() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return -1
	}
	n := 0
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err == nil {
			n++
		}
	}
	return n
}

func passivePosture() Posture {
	st := statusFields()
	capEff := strings.TrimSpace(st["CapEff"])
	return Posture{
		UID:            os.Getuid(),
		GID:            os.Getgid(),
		CapEffHex:      capEff,
		CapEff:         decodeCaps(capEff),
		CapBndHex:      strings.TrimSpace(st["CapBnd"]),
		NoNewPrivs:     st["NoNewPrivs"],
		SeccompMode:    st["Seccomp"],
		SeccompFilters: st["Seccomp_filters"],
		RootReadOnly:   rootReadOnly(),
		MemoryLimit: firstReadable(
			"/sys/fs/cgroup/memory.max",
			"/sys/fs/cgroup/memory/memory.limit_in_bytes"),
		PidsLimit: firstReadable(
			"/sys/fs/cgroup/pids.max",
			"/sys/fs/cgroup/pids/pids.max"),
		CPUQuota: firstReadable(
			"/sys/fs/cgroup/cpu.max",
			"/sys/fs/cgroup/cpu/cpu.cfs_quota_us"),
		PID1Comm:     readTrim("/proc/1/comm"),
		VisibleProcs: visibleProcs(),
		GoVersion:    runtime.Version(),
	}
}

func errnoName(err error) string {
	var e syscall.Errno
	if errors.As(err, &e) {
		switch e {
		case syscall.EPERM:
			return "EPERM"
		case syscall.EACCES:
			return "EACCES"
		case syscall.EROFS:
			return "EROFS"
		case syscall.ENOENT:
			return "ENOENT"
		case syscall.EAGAIN:
			return "EAGAIN"
		case syscall.EINVAL:
			return "EINVAL"
		case syscall.ECONNREFUSED:
			return "ECONNREFUSED"
		}
		return "errno_" + strconv.Itoa(int(e))
	}
	return "error"
}

func result(name string, err error, detail string) ProbeResult {
	if err == nil {
		return ProbeResult{Name: name, Allowed: true, Detail: detail}
	}
	return ProbeResult{Name: name, Allowed: false, Errno: errnoName(err), Detail: detail}
}

func runProbes() []ProbeResult {
	var out []ProbeResult

	// 1. Can the process write to the image filesystem?
	{
		path := "/probe-rootfs"
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err == nil {
			f.Close()
			_ = os.Remove(path)
		}
		out = append(out, result("write_root_filesystem", err, ""))
	}

	// 2. Is there a writable scratch area at all (a hardened image must still work)?
	tmp := "/tmp/probe-tmp"
	{
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err == nil {
			f.Close()
		}
		out = append(out, result("write_tmp_scratch", err, ""))
	}

	// 3. CAP_CHOWN: hand a file to an unrelated uid.
	out = append(out, result("chown_to_other_uid (CAP_CHOWN)", os.Chown(tmp, 12345, 12345), ""))
	_ = os.Remove(tmp)

	// 4. CAP_MKNOD: create a character device node (1,3 is the /dev/null number).
	{
		path := "/tmp/probe-null"
		err := syscall.Mknod(path, syscall.S_IFCHR|0o600, 1<<8|3)
		if err == nil {
			_ = os.Remove(path)
		}
		out = append(out, result("mknod_char_device (CAP_MKNOD)", err, ""))
	}

	// 5. CAP_NET_RAW: open a raw ICMP socket.
	{
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
		if err == nil {
			_ = syscall.Close(fd)
		}
		out = append(out, result("raw_socket (CAP_NET_RAW)", err, ""))
	}

	// 6. CAP_SYS_ADMIN: mount a tmpfs inside the container's mount namespace.
	{
		dir := "/tmp/probe-mnt"
		_ = os.MkdirAll(dir, 0o700)
		err := syscall.Mount("tmpfs", dir, "tmpfs", 0, "size=1m")
		if err == nil {
			_ = syscall.Unmount(dir, 0)
		}
		_ = os.Remove(dir)
		out = append(out, result("mount_tmpfs (CAP_SYS_ADMIN)", err, ""))
	}

	// 7. Seccomp-attributable: creating a user namespace needs no capability on
	// most kernels, so a denial here points at the seccomp filter. unshare(2)
	// cannot be used because it returns EINVAL for any multithreaded process
	// (every Go program); clone(2) with CLONE_NEWUSER via os/exec can.
	{
		self, _ := os.Executable()
		c := exec.Command(self, "sleep", "0")
		c.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}
		// errnoName unwraps *os.PathError to the underlying syscall.Errno.
		err := c.Run()
		out = append(out, result("clone_new_user_namespace (seccomp-attributable)", err, ""))
	}

	// 8. Is a container-runtime socket mounted, and does it answer a read-only ping?
	{
		const sock = "/var/run/docker.sock"
		if _, err := os.Stat(sock); err != nil {
			out = append(out, ProbeResult{Name: "docker_socket_present", Allowed: false, Errno: errnoName(err)})
		} else {
			conn, err := net.DialTimeout("unix", sock, 2*time.Second)
			if err != nil {
				out = append(out, result("docker_socket_reachable", err, "socket path exists"))
			} else {
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = io.WriteString(conn, "GET /_ping HTTP/1.0\r\n\r\n")
				buf := make([]byte, 256)
				n, _ := conn.Read(buf)
				conn.Close()
				line, _, _ := strings.Cut(string(buf[:n]), "\r\n")
				out = append(out, ProbeResult{Name: "docker_socket_reachable", Allowed: true,
					Detail: "GET /_ping only; status line: " + line})
			}
		}
	}

	// 9. Is a host-side lab canary directory mounted, and is it writable?
	{
		const dir = "/mnt/host-canary"
		if _, err := os.Stat(dir); err != nil {
			out = append(out, ProbeResult{Name: "host_canary_mounted", Allowed: false, Errno: errnoName(err)})
		} else {
			_, readErr := os.ReadFile(dir + "/canary.txt")
			out = append(out, result("host_canary_read", readErr, "content not printed"))
			w := dir + "/written-by-container.txt"
			f, werr := os.OpenFile(w, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if werr == nil {
				f.Close()
			}
			out = append(out, result("host_canary_write", werr, ""))
		}
	}

	// 10. Network reachability of a lab canary service (topology, not firewalling).
	if target := os.Getenv("PROBE_TCP_TARGET"); target != "" {
		conn, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err == nil {
			conn.Close()
		}
		detail := "target=" + target
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			detail += " (name resolution failed)"
		}
		out = append(out, result("tcp_connect_canary", err, detail))
	}

	return out
}

func probe() int {
	rep := Report{Posture: passivePosture(), Probes: runProbes()}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return 1
	}
	return 0
}

func forktest(n int) int {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot locate self:", err)
		return 1
	}
	started := 0
	firstErr := ""
	var kids []*exec.Cmd
	for i := 0; i < n; i++ {
		c := exec.Command(self, "sleep", "3")
		if err := c.Start(); err != nil {
			firstErr = errnoName(errors.Unwrap(err))
			if firstErr == "error" {
				firstErr = err.Error()
			}
			break
		}
		kids = append(kids, c)
		started++
	}
	for _, c := range kids {
		_ = c.Wait()
	}
	out := map[string]any{"requested": n, "started": started, "first_error": firstErr}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	return 0
}

func memtest(mib int) int {
	chunks := make([][]byte, 0, mib)
	for i := 1; i <= mib; i++ {
		b := make([]byte, 1<<20)
		for j := 0; j < len(b); j += 4096 {
			b[j] = 1
		}
		chunks = append(chunks, b)
		if i%16 == 0 || i == mib {
			fmt.Printf("{\"touched_mib\":%d}\n", i)
		}
	}
	runtime.KeepAlive(chunks)
	return 0
}

// ---- Kubernetes workload-identity probe ---------------------------------------

// K8sCall is one API request outcome. Only the HTTP status and, for a list, the
// number of items are recorded: never object names or contents, so running the
// probe against an over-privileged identity does not print secret material.
type K8sCall struct {
	Name   string `json:"name"`
	Status int    `json:"status"`
	Items  *int   `json:"items,omitempty"`
	Error  string `json:"error,omitempty"`
}

// K8sReport is the full `k8sprobe` output.
type K8sReport struct {
	TokenMounted bool                   `json:"token_mounted"`
	Namespace    string                 `json:"namespace,omitempty"`
	Claims       map[string]interface{} `json:"token_claims,omitempty"`
	Calls        []K8sCall              `json:"api_calls,omitempty"`
	Access       map[string]bool        `json:"self_subject_access_review,omitempty"`
	Note         string                 `json:"note,omitempty"`
}

// jwtClaims decodes the payload of a service-account JWT WITHOUT verifying it.
// It is informational (what the pod was handed); the API server is the verifier.
func jwtClaims(token string) map[string]interface{} {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var all map[string]interface{}
	if json.Unmarshal(raw, &all) != nil {
		return nil
	}
	out := map[string]interface{}{"sub": all["sub"], "aud": all["aud"], "iss": all["iss"]}
	if exp, ok := all["exp"].(float64); ok {
		out["seconds_until_expiry"] = int64(exp) - time.Now().Unix()
	}
	if iat, ok := all["iat"].(float64); ok {
		out["token_age_seconds"] = time.Now().Unix() - int64(iat)
	}
	// A bound token carries the pod it was issued to; a legacy secret-based token does not.
	if kube, ok := all["kubernetes.io"].(map[string]interface{}); ok {
		_, bound := kube["pod"]
		out["bound_to_pod"] = bound
	} else {
		out["bound_to_pod"] = false
	}
	return out
}

func k8sprobe() int {
	const dir = "/var/run/secrets/kubernetes.io/serviceaccount"
	rep := K8sReport{}
	emit := func() int {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return 0
	}
	tokenBytes, err := os.ReadFile(dir + "/token")
	if err != nil {
		rep.Note = "no service-account token mounted at " + dir
		return emit()
	}
	rep.TokenMounted = true
	token := strings.TrimSpace(string(tokenBytes))
	rep.Namespace = readTrim(dir + "/namespace")
	rep.Claims = jwtClaims(token)

	caPEM, err := os.ReadFile(dir + "/ca.crt")
	pool := x509.NewCertPool()
	if err != nil || !pool.AppendCertsFromPEM(caPEM) {
		rep.Note = "cannot load cluster CA"
		return emit()
	}
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		rep.Note = "KUBERNETES_SERVICE_HOST/PORT not set"
		return emit()
	}
	base := "https://" + net.JoinHostPort(host, port)
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	do := func(method, path string, body []byte) (int, []byte, error) {
		req, _ := http.NewRequest(method, base+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return resp.StatusCode, data, nil
	}

	ns := rep.Namespace
	reads := []struct{ name, path string }{
		{"get_configmap_app_config_own_ns", "/api/v1/namespaces/" + ns + "/configmaps/app-config"},
		{"list_configmaps_own_ns", "/api/v1/namespaces/" + ns + "/configmaps"},
		{"list_secrets_own_ns", "/api/v1/namespaces/" + ns + "/secrets"},
		{"list_secrets_kube_system", "/api/v1/namespaces/kube-system/secrets"},
		{"list_pods_all_namespaces", "/api/v1/pods"},
		{"list_nodes", "/api/v1/nodes"},
	}
	for _, r := range reads {
		status, data, err := do(http.MethodGet, r.path, nil)
		call := K8sCall{Name: r.name, Status: status}
		if err != nil {
			call.Error = errnoName(errors.Unwrap(err))
			if call.Error == "error" {
				call.Error = "request failed (network or TLS)"
			}
		} else if status == http.StatusOK {
			var list struct {
				Items []json.RawMessage `json:"items"`
			}
			if json.Unmarshal(data, &list) == nil && list.Items != nil {
				n := len(list.Items)
				call.Items = &n
			}
		}
		rep.Calls = append(rep.Calls, call)
	}

	// Write permissions are checked with SelfSubjectAccessReview: asks the API
	// server whether the action WOULD be allowed, and creates nothing.
	rep.Access = map[string]bool{}
	reviews := []struct{ name, verb, group, resource, sub, namespace string }{
		{"create_pods_own_ns", "create", "", "pods", "", ns},
		{"create_pods_exec_own_ns", "create", "", "pods", "exec", ns},
		{"get_secrets_any_namespace", "get", "", "secrets", "", ""},
		{"create_rolebindings_own_ns", "create", "rbac.authorization.k8s.io", "rolebindings", "", ns},
		{"escalate_clusterroles", "escalate", "rbac.authorization.k8s.io", "clusterroles", "", ""},
		{"impersonate_users", "impersonate", "", "users", "", ""},
	}
	for _, rv := range reviews {
		attrs := map[string]string{"verb": rv.verb, "group": rv.group, "resource": rv.resource}
		if rv.sub != "" {
			attrs["subresource"] = rv.sub
		}
		if rv.namespace != "" {
			attrs["namespace"] = rv.namespace
		}
		body, _ := json.Marshal(map[string]interface{}{
			"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
			"spec": map[string]interface{}{"resourceAttributes": attrs},
		})
		status, data, err := do(http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", body)
		allowed := false
		if err == nil && status == http.StatusCreated {
			var out struct {
				Status struct {
					Allowed bool `json:"allowed"`
				} `json:"status"`
			}
			if json.Unmarshal(data, &out) == nil {
				allowed = out.Status.Allowed
			}
		}
		rep.Access[rv.name] = allowed
	}
	return emit()
}

// tcpcheck makes one TCP connection attempt and reports it. The distroless image
// has no shell, nc or curl, so reachability tests need to live in the binary.
func tcpcheck(target string) int {
	out := map[string]interface{}{"target": target, "connected": false}
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err == nil {
		conn.Close()
		out["connected"] = true
	} else {
		var dnsErr *net.DNSError
		var netErr net.Error
		switch {
		case errors.As(err, &dnsErr):
			out["error"] = "name resolution failed"
		case errors.As(err, &netErr) && netErr.Timeout():
			out["error"] = "timeout"
		default:
			out["error"] = errnoName(errors.Unwrap(errors.Unwrap(err)))
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	return 0
}
