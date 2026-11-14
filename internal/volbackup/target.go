// Package volbackup keeps deduplicated, encrypted backups of volumes in an
// S3-compatible bucket (ADR 0041).
package volbackup

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

// Target is where a volume's backups go, read from the URL in the app's
// secret. It never prints its credentials.
type Target struct {
	// Endpoint is host[:port]; Secure is false only for http://.
	Endpoint string
	Secure   bool
	Bucket   string
	// Prefix is "" or ends with "/".
	Prefix    string
	Region    string
	AccessKey string
	SecretKey string
	// loopback lets tests reach a server on 127.0.0.1.
	loopback bool
}

// String names the bucket without credentials.
func (t Target) String() string { return t.Bucket + "/" + t.Prefix }

// LogValue keeps credentials out of logs.
func (t Target) LogValue() string { return t.String() }

var (
	bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	prefixRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	regionRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
)

// errTarget never carries the URL: it holds credentials.
func errTarget(msg string) error { return errors.New("backup URL: " + msg) }

// ParseTarget reads https://KEY:SECRET@host[:port]/bucket[/prefix][?region=R].
// http:// is accepted only for a private IP address. The node's own
// services are never a bucket: loopback, link-local, unspecified, and
// multicast addresses are refused (and refused again when a name resolves
// to one, see S3).
func ParseTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) > 2048 {
		return Target{}, errTarget("too long")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, errTarget("not a URL")
	}
	var t Target
	switch u.Scheme {
	case "https":
		t.Secure = true
	case "http":
	default:
		return Target{}, errTarget("must start with https://")
	}
	if u.Host == "" || u.Opaque != "" || u.Fragment != "" {
		return Target{}, errTarget("must be https://KEY:SECRET@host/bucket")
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil && nodeOnly(ip) {
		return Target{}, errTarget("a loopback, link-local, or multicast address cannot hold a bucket")
	}
	if !t.Secure {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.IsPrivate() {
			return Target{}, errTarget("http:// is only allowed for a private IP address; use https://")
		}
	}
	if port := u.Port(); port != "" {
		t.Endpoint = net.JoinHostPort(host, port)
	} else {
		t.Endpoint = host
		if strings.Contains(host, ":") {
			t.Endpoint = "[" + host + "]"
		}
	}
	if u.User == nil {
		return Target{}, errTarget("needs the access key and secret key as KEY:SECRET@")
	}
	t.AccessKey = u.User.Username()
	t.SecretKey, _ = u.User.Password()
	if t.AccessKey == "" || t.SecretKey == "" {
		return Target{}, errTarget("needs the access key and secret key as KEY:SECRET@")
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segs) == 0 || segs[0] == "" {
		return Target{}, errTarget("needs a bucket: https://KEY:SECRET@host/bucket")
	}
	if !bucketRe.MatchString(segs[0]) || strings.Contains(segs[0], "..") {
		return Target{}, errTarget("invalid bucket name")
	}
	t.Bucket = segs[0]
	for _, s := range segs[1:] {
		if !prefixRe.MatchString(s) || s == "." || s == ".." {
			return Target{}, errTarget("the prefix may only hold letters, digits, '.', '_', and '-' between slashes")
		}
		t.Prefix += s + "/"
	}
	if len(t.Prefix) > 256 {
		return Target{}, errTarget("prefix too long")
	}
	q := u.Query()
	for k := range q {
		if k != "region" {
			return Target{}, errTarget("unknown parameter " + strings.ToValidUTF8(k[:min(len(k), 32)], "?") + "; only region is known")
		}
	}
	if r := q.Get("region"); r != "" {
		if !regionRe.MatchString(r) {
			return Target{}, errTarget("invalid region")
		}
		t.Region = r
	}
	return t, nil
}

// nodeOnly reports addresses that reach the node itself or its link rather
// than a bucket: loopback, link-local (cloud metadata), unspecified, and
// multicast.
func nodeOnly(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast()
}

// PrivateIP returns the bucket's host when it is a private IP address:
// such a bucket is reached from the node's own address, inside the private
// network, so only cluster-admins may choose one (ADR 0041).
func (t Target) PrivateIP() (netip.Addr, bool) {
	host := strings.TrimSuffix(strings.TrimPrefix(t.Endpoint, "["), "]")
	if h, _, err := net.SplitHostPort(t.Endpoint); err == nil {
		host = h
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Unmap().IsPrivate() {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}
