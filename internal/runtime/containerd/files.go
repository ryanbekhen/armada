package containerd

import (
	"bufio"
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Every app container gets its own /etc/resolv.conf, /etc/hosts, and
// /etc/hostname, bind-mounted read-only from <data-dir>/containers/<id>/.

// fallbackDNS is used when the host has no usable nameserver.
var fallbackDNS = []string{"8.8.8.8", "8.8.4.4"}

// hostResolvConf returns the host's resolver configuration. A
// systemd-resolved stub (127.0.0.53) is unreachable from a container's
// network namespace, so the upstream list is used instead.
func hostResolvConf() []byte {
	b, _ := os.ReadFile("/etc/resolv.conf")
	if len(nameservers(b)) == 0 {
		if up, err := os.ReadFile("/run/systemd/resolve/resolv.conf"); err == nil {
			return up
		}
	}
	return b
}

// nameservers returns the non-loopback nameservers in a resolv.conf.
func nameservers(conf []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(conf))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		if a, err := netip.ParseAddr(f[1]); err == nil && !a.IsLoopback() {
			out = append(out, f[1])
		}
	}
	return out
}

// resolvConf builds a container's resolv.conf: dns (or the host's
// non-loopback nameservers, or fallbackDNS) plus the host's search and
// options lines.
func resolvConf(host []byte, dns []string) []byte {
	servers := dns
	if len(servers) == 0 {
		servers = nameservers(host)
	}
	if len(servers) == 0 {
		servers = fallbackDNS
	}
	var b bytes.Buffer
	for _, s := range servers {
		b.WriteString("nameserver " + s + "\n")
	}
	sc := bufio.NewScanner(bytes.NewReader(host))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && (f[0] == "search" || f[0] == "options") {
			b.WriteString(strings.Join(f, " ") + "\n")
		}
	}
	return b.Bytes()
}

func hostsFile(ip, hostname string) []byte {
	s := "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n"
	if ip != "" {
		s += ip + "\t" + hostname + "\n"
	}
	return []byte(s)
}

// hostname returns a valid hostname for container id.
func hostname(id string) string {
	if len(id) > 63 {
		id = id[:63]
	}
	return strings.Trim(strings.ReplaceAll(id, "_", "-"), ".-")
}

type containerFiles struct{ resolv, hosts, hostname string }

// writeFiles creates the per-container files under dir/<id>; the hostname
// is the container's name.
func writeFiles(dir, id, name, ip string, dns []string) (containerFiles, error) {
	d := filepath.Join(dir, id)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return containerFiles{}, err
	}
	f := containerFiles{
		resolv:   filepath.Join(d, "resolv.conf"),
		hosts:    filepath.Join(d, "hosts"),
		hostname: filepath.Join(d, "hostname"),
	}
	// World-readable: processes in the container may run as any user. The
	// 0700 parent keeps them private on the host.
	for path, data := range map[string][]byte{
		f.resolv:   resolvConf(hostResolvConf(), dns),
		f.hosts:    hostsFile(ip, hostname(name)),
		f.hostname: []byte(hostname(name) + "\n"),
	} {
		if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // read by any user in the container; parent dir is 0700
			return containerFiles{}, err
		}
	}
	return f, nil
}
