package certs

// TestArmadaACME checks armada-server's ACME manager (server/src/acme,
// ADR 0055) against this package's certmagic manager on one etcd member
// and one Pebble: each obtains certificates over HTTP-01 while the other
// answers the challenge from storage, renews the other's certificates,
// waits for the other's issuance lock, and fails a name with the same
// message; the Rust manager also obtains a wildcard and an app's custom
// domain over DNS-01 through a stand-in of Cloudflare's API. It needs
// Pebble (ARMADA_PEBBLE_BIN, e.g. `GOBIN=DIR go install
// github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.3`) and
// armada-acme-parity (ARMADA_ACME_BIN, `make server-parity`); it never
// reaches Let's Encrypt or Cloudflare.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"github.com/miekg/dns"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/etcd/etcdtest"
	"github.com/ryanbekhen/armada/internal/pki"
)

const (
	labEmail     = "ops@example.test"
	labRootToken = "root-token"
	labAppToken  = "app-token"
	labPrefix    = "/armada-acme/"
)

// acmeEvent is a certificate obtained (err "") or a failed attempt.
type acmeEvent struct {
	name, err string
	renewal   bool
}

// eventLog keeps the events not waited for yet.
type eventLog struct {
	ch      chan acmeEvent
	pending []acmeEvent
}

func newEventLog() *eventLog { return &eventLog{ch: make(chan acmeEvent, 64)} }

// next waits for name's next event.
func (l *eventLog) next(t *testing.T, name string) acmeEvent {
	t.Helper()
	for i, e := range l.pending {
		if e.name == name {
			l.pending = slices.Delete(l.pending, i, i+1)
			return e
		}
	}
	timeout := time.After(90 * time.Second)
	for {
		select {
		case e := <-l.ch:
			if e.name == name {
				return e
			}
			l.pending = append(l.pending, e)
		case <-timeout:
			t.Fatalf("no event for %s", name)
		}
	}
}

// none fails when name has an event within d.
func (l *eventLog) none(t *testing.T, name string, d time.Duration) {
	t.Helper()
	timeout := time.After(d)
	for {
		select {
		case e := <-l.ch:
			if e.name == name {
				t.Fatalf("event for %s while its lock was held: %+v", name, e)
			}
			l.pending = append(l.pending, e)
		case <-timeout:
			return
		}
	}
}

func TestArmadaACME(t *testing.T) {
	pebbleBin, rustBin := os.Getenv("ARMADA_PEBBLE_BIN"), os.Getenv("ARMADA_ACME_BIN")
	if pebbleBin == "" || rustBin == "" {
		t.Skip("set ARMADA_PEBBLE_BIN (Pebble) and ARMADA_ACME_BIN (armada-acme-parity) to run")
	}
	lab := newACMELab(t, pebbleBin)
	goM := lab.startGo(t)
	rust := lab.startRust(t, rustBin)

	var goNames []string
	goManage := func(names ...string) {
		t.Helper()
		goNames = append(goNames, names...)
		if err := goM.acme.Manage(lab.ctx, goNames, "", nil); err != nil {
			t.Fatal(err)
		}
	}
	rustNames := []string{}
	rustDNS := map[string]any{}
	rustManage := func(names ...string) {
		t.Helper()
		rustNames = append(rustNames, names...)
		if e := rust.call(t, map[string]any{"op": "manage", "names": rustNames, "root": "apps.example.test", "dns": rustDNS})["error"]; e != "" {
			t.Fatalf("manage: %v", e)
		}
	}

	t.Run("rust obtains, Go answers its challenge", func(t *testing.T) {
		lab.forward(goM.responder)
		rustManage("r1.example.test")
		rust.want(t, "r1.example.test", false)
		lab.checkStored(t, goM.acme, rust, "r1.example.test")
	})
	t.Run("go obtains, Rust answers its challenge", func(t *testing.T) {
		lab.forward(rust.responder)
		goManage("g1.example.test")
		goM.want(t, "g1.example.test")
		lab.checkStored(t, goM.acme, rust, "g1.example.test")
	})
	t.Run("rust renews Go's certificate", func(t *testing.T) {
		lab.forward(goM.responder)
		before := lab.serial(t, "g1.example.test")
		rustManage("g1.example.test")
		rust.want(t, "g1.example.test", true)
		if lab.serial(t, "g1.example.test") == before {
			t.Error("the certificate was not replaced")
		}
		lab.checkStored(t, goM.acme, rust, "g1.example.test")
	})
	t.Run("go renews Rust's certificate", func(t *testing.T) {
		lab.forward(rust.responder)
		before := lab.serial(t, "r1.example.test")
		goManage("r1.example.test")
		goM.want(t, "r1.example.test")
		if lab.serial(t, "r1.example.test") == before {
			t.Error("the certificate was not replaced")
		}
		lab.checkStored(t, goM.acme, rust, "r1.example.test")
	})
	t.Run("a lock Go holds holds Rust", func(t *testing.T) {
		lab.forward(rust.responder)
		other, err := NewEtcdStorage(lab.client, labPrefix)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		if err := other.Lock(lab.ctx, "issue_cert_l1.example.test"); err != nil {
			t.Fatal(err)
		}
		rustManage("l1.example.test")
		rust.none(t, "l1.example.test", 4*time.Second)
		if _, ok := goM.acme.Certificate(lab.ctx, "l1.example.test"); ok {
			t.Fatal("obtained while the lock was held")
		}
		if err := other.Unlock(lab.ctx, "issue_cert_l1.example.test"); err != nil {
			t.Fatal(err)
		}
		rust.want(t, "l1.example.test", false)
	})
	t.Run("a lock Rust holds holds Go", func(t *testing.T) {
		lab.forward(goM.responder)
		if e := rust.call(t, map[string]any{"op": "lock", "name": "issue_cert_l2.example.test"})["error"]; e != "" {
			t.Fatal(e)
		}
		goManage("l2.example.test")
		goM.none(t, "l2.example.test", 4*time.Second)
		if e := rust.call(t, map[string]any{"op": "unlock", "name": "issue_cert_l2.example.test"})["error"]; e != "" {
			t.Fatal(e)
		}
		goM.want(t, "l2.example.test")
	})
	t.Run("rust obtains over DNS-01 through Cloudflare", func(t *testing.T) {
		rustDNS["c1.custom.test"] = map[string]string{"provider": "cloudflare", "token": labAppToken}
		rustManage("*.apps.example.test", "c1.custom.test")
		rust.want(t, "*.apps.example.test", false)
		rust.want(t, "c1.custom.test", false)
		lab.checkStored(t, goM.acme, rust, "*.apps.example.test")
		lab.checkStored(t, goM.acme, rust, "c1.custom.test")
		created, deleted, left := lab.cf.counts()
		if created != 2 || deleted != 2 || left != 0 {
			t.Errorf("Cloudflare records: %d created, %d deleted, %d left; want 2, 2, 0", created, deleted, left)
		}
		if k := wildcardKey(lab.issuer); !lab.exists(t, k) {
			t.Errorf("%s is not in storage", k)
		}
	})
	t.Run("failures read the same", func(t *testing.T) {
		rustManage("bad1.nowhere.test")
		goManage("bad2.nowhere.test")
		r := rust.wantFailure(t, "bad1.nowhere.test")
		g := goM.wantFailure(t, "bad2.nowhere.test")
		// The challenges' tokens are random.
		token := regexp.MustCompile(`acme-challenge/[A-Za-z0-9_-]+`)
		r, g = token.ReplaceAllString(r, "acme-challenge/TOKEN"), token.ReplaceAllString(g, "acme-challenge/TOKEN")
		if r != strings.ReplaceAll(g, "bad2.", "bad1.") {
			t.Errorf("failure messages differ:\n rust: %s\n   go: %s", r, g)
		}
	})
	t.Run("responders answer only challenges", func(t *testing.T) {
		for _, c := range []struct{ method, host, path string }{
			{http.MethodGet, "r1.example.test", "/.well-known/acme-challenge/nothing"},
			{http.MethodGet, "r1.example.test", "/"},
			{http.MethodPost, "r1.example.test", "/.well-known/acme-challenge/nothing"},
		} {
			gs, gb := httpGet(t, c.method, goM.responder, c.host, c.path)
			rs, rb := httpGet(t, c.method, rust.responder, c.host, c.path)
			if gs != rs || gb != rb {
				t.Errorf("%s %s: go %d %q, rust %d %q", c.method, c.path, gs, gb, rs, rb)
			}
		}
	})
	t.Run("one account", func(t *testing.T) {
		users, err := lab.storage.List(lab.ctx, "acme/"+certmagic.StorageKeys.Safe(lab.issuer)+"/users", false)
		if err != nil || len(users) != 1 || !strings.HasSuffix(users[0], "/"+labEmail) {
			t.Errorf("accounts = %v, %v", users, err)
		}
	})
}

func wildcardKey(issuer string) string {
	return certmagic.StorageKeys.SiteCert(issuer, "*.apps.example.test")
}

// acmeLab is Pebble with its stand-ins: a DNS server for the test zones,
// Cloudflare's API, and HAProxy's forwarding of HTTP-01 challenges.
type acmeLab struct {
	ctx      context.Context
	dir      string
	caFile   string
	roots    *x509.CertPool
	ca       string // the directory URL
	issuer   string
	dnsAddr  string
	cf       *cfStandIn
	cfURL    string
	target   atomic.Pointer[string]
	endpoint string
	etcdDir  string
	client   *clientv3.Client
	storage  *EtcdStorage
}

func newACMELab(t *testing.T, pebbleBin string) *acmeLab {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	lab := &acmeLab{ctx: ctx, dir: t.TempDir(), cf: newCFStandIn()}
	lab.makeTLS(t)

	// etcd, as the control plane's.
	pca, err := pki.NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	lab.etcdDir = filepath.Join(lab.dir, "etcd")
	m, err := etcdtest.Start(ctx, etcd.Config{Dir: lab.etcdDir, Name: "cp-1", Addr: netip.MustParseAddr("127.0.0.1"), CA: pca, UnsafeNoFsync: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	lab.client = m.Client()
	lab.endpoint = m.Client().Endpoints()[0]
	if lab.storage, err = NewEtcdStorage(lab.client, labPrefix); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lab.storage.Close() })

	lab.startDNS(t)
	srv := httptest.NewUnstartedServer(lab.cf)
	srv.TLS = lab.serverTLS(t)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	lab.cfURL = srv.URL + "/client/v4"

	// HAProxy: port 80's /.well-known/acme-challenge/ to the leader's
	// responder, Host kept.
	httpPort := lab.startProxy(t)
	lab.startPebble(t, pebbleBin, httpPort)
	return lab
}

func (l *acmeLab) forward(addr string) { l.target.Store(&addr) }

func (l *acmeLab) makeTLS(t *testing.T) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "acme lab CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(der)
	l.caFile = filepath.Join(l.dir, "ca.pem")
	if err := os.WriteFile(l.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	l.roots = x509.NewCertPool()
	l.roots.AddCert(caCert)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	for f, b := range map[string][]byte{
		"server.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		"server.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	} {
		if err := os.WriteFile(filepath.Join(l.dir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func (l *acmeLab) serverTLS(t *testing.T) *tls.Config {
	t.Helper()
	c, err := tls.LoadX509KeyPair(filepath.Join(l.dir, "server.pem"), filepath.Join(l.dir, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12}
}

// labZones are the stand-in DNS server's zones.
var labZones = []string{"example.test.", "custom.test."}

func zoneOf(name string) string {
	for _, z := range labZones {
		if name == z || strings.HasSuffix(name, "."+z) {
			return z
		}
	}
	return ""
}

func (l *acmeLab) startDNS(t *testing.T) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	l.dnsAddr = pc.LocalAddr().String()
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		zone := zoneOf(name)
		hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 1}
		switch {
		case zone == "":
			m.Rcode = dns.RcodeNameError
		case q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.ParseIP("127.0.0.1")})
		case q.Qtype == dns.TypeSOA && name == zone:
			m.Answer = append(m.Answer, &dns.SOA{Hdr: hdr, Ns: "ns1." + zone, Mbox: "admin." + zone, Serial: 1, Refresh: 1, Retry: 1, Expire: 60, Minttl: 1})
		case q.Qtype == dns.TypeNS && name == zone:
			m.Answer = append(m.Answer, &dns.NS{Hdr: hdr, Ns: "ns1." + zone})
		case q.Qtype == dns.TypeTXT:
			for _, v := range l.cf.txt(strings.TrimSuffix(name, ".")) {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{v}})
			}
		}
		_ = w.WriteMsg(m)
	})
	for _, s := range []*dns.Server{{PacketConn: pc, Handler: h}, {Listener: ln, Handler: h}} {
		go func() { _ = s.ActivateAndServe() }()
		t.Cleanup(func() { _ = s.Shutdown() })
	}
}

func (l *acmeLab) startProxy(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := l.target.Load()
		if target == nil || !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			http.NotFound(w, r)
			return
		}
		httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: *target}).ServeHTTP(w, r)
	})}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func (l *acmeLab) startPebble(t *testing.T, bin string, httpPort int) {
	t.Helper()
	port := freePort(t)
	conf := map[string]any{"pebble": map[string]any{
		"listenAddress":                  fmt.Sprintf("127.0.0.1:%d", port),
		"managementListenAddress":        fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"certificate":                    filepath.Join(l.dir, "server.pem"),
		"privateKey":                     filepath.Join(l.dir, "server.key"),
		"httpPort":                       httpPort,
		"tlsPort":                        freePort(t),
		"ocspResponderURL":               "",
		"externalAccountBindingRequired": false,
		"retryAfter":                     map[string]int{"authz": 1, "order": 1},
		"keyAlgorithm":                   "ecdsa",
		// 45 minutes: within five renewal checks of its end from the
		// start, so a certificate one side obtained is due for the other.
		"profiles": map[string]any{"default": map[string]any{"description": "lab", "validityPeriod": 2700}},
	}}
	b, _ := json.Marshal(conf)
	cfgFile := filepath.Join(l.dir, "pebble.json")
	if err := os.WriteFile(cfgFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-config", cfgFile, "-dnsserver", l.dnsAddr)
	cmd.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_AUTHZREUSE=0")
	if os.Getenv("ARMADA_ACME_VERBOSE") != "" {
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	l.ca = fmt.Sprintf("https://127.0.0.1:%d/dir", port)
	l.issuer = (&certmagic.ACMEIssuer{CA: l.ca}).IssuerKey()
	hc := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: l.roots, MinVersion: tls.VersionTLS12}}}
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := hc.Get(l.ca)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pebble did not start: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// goACME is this package's manager with its responder.
type goACME struct {
	acme      *ACME
	responder string
	events    *eventLog
}

func (l *acmeLab) startGo(t *testing.T) *goACME {
	t.Helper()
	// Pebble's TLS certificate is the lab's; certmagic's HTTP-01 solver
	// binds a port of its own besides the responder (here unused).
	oldRoots, oldPort := certmagic.DefaultACME.TrustedRoots, certmagic.HTTPPort
	certmagic.DefaultACME.TrustedRoots, certmagic.HTTPPort = l.roots, freePort(t)
	t.Cleanup(func() { certmagic.DefaultACME.TrustedRoots, certmagic.HTTPPort = oldRoots, oldPort })
	g := &goACME{events: newEventLog()}
	a, err := NewACME(Options{
		Storage: l.storage, CA: l.ca, Email: labEmail,
		OnObtained: func(name string) { g.events.ch <- acmeEvent{name: name} },
		OnFailed: func(name string, renewal bool, err error) {
			g.events.ch <- acmeEvent{name: name, err: fmt.Sprint(err), renewal: renewal}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	g.acme = a
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: a.HTTPHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	g.responder = ln.Addr().String()
	return g
}

func (g *goACME) want(t *testing.T, name string) {
	t.Helper()
	e := g.events.next(t, name)
	if e.err != "" {
		t.Fatalf("go: %s failed: %s", name, e.err)
	}
}

func (g *goACME) wantFailure(t *testing.T, name string) string {
	t.Helper()
	e := g.events.next(t, name)
	if e.err == "" {
		t.Fatalf("go: %s obtained", name)
	}
	return e.err
}

func (g *goACME) none(t *testing.T, name string, d time.Duration) {
	t.Helper()
	g.events.none(t, name, d)
}

// rustACME is armada-acme-parity.
type rustACME struct {
	in        io.WriteCloser
	responder string
	events    *eventLog
	mu        sync.Mutex
	next      int
	waiting   map[int]chan map[string]any
}

func (l *acmeLab) startRust(t *testing.T, bin string) *rustACME {
	t.Helper()
	cmd := exec.Command(bin)
	// The lab's CA is the only root; no proxy.
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+l.caFile, "SSL_CERT_DIR="+l.dir, "HTTPS_PROXY=", "https_proxy=")
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r := &rustACME{in: in, events: newEventLog(), waiting: map[int]chan map[string]any{}}
	ready := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) != nil {
				continue
			}
			switch {
			case m["ready"] != nil:
				rd, _ := m["ready"].(map[string]any)
				addr, _ := rd["responder"].(string)
				ready <- addr
			case m["event"] != nil:
				name, _ := m["name"].(string)
				msg, _ := m["error"].(string)
				renewal, _ := m["renewal"].(bool)
				r.events.ch <- acmeEvent{name: name, err: msg, renewal: renewal}
			default:
				id, _ := m["id"].(float64)
				r.mu.Lock()
				ch := r.waiting[int(id)]
				delete(r.waiting, int(id))
				r.mu.Unlock()
				if ch != nil {
					ch <- m
				}
			}
		}
	}()
	conf := map[string]any{
		"endpoint": l.endpoint, "dir": l.etcdDir, "prefix": labPrefix, "ca": l.ca, "email": labEmail,
		"dnsToken": labRootToken, "cloudflareApi": l.cfURL, "resolvers": []string{l.dnsAddr},
		"responderListen": "127.0.0.1:0", "verbose": os.Getenv("ARMADA_ACME_VERBOSE") != "",
	}
	b, _ := json.Marshal(conf)
	if _, err := in.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
	select {
	case r.responder = <-ready:
	case <-time.After(30 * time.Second):
		t.Fatal("armada-acme-parity did not get ready")
	}
	t.Cleanup(func() {
		r.call(t, map[string]any{"op": "close"})
		_ = in.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
		}
	})
	return r
}

func (r *rustACME) call(t *testing.T, req map[string]any) map[string]any {
	t.Helper()
	ch := make(chan map[string]any, 1)
	r.mu.Lock()
	r.next++
	id := r.next
	r.waiting[id] = ch
	r.mu.Unlock()
	req["id"] = id
	b, _ := json.Marshal(req)
	if _, err := r.in.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-ch:
		if m["error"] == nil {
			m["error"] = ""
		}
		return m
	case <-time.After(60 * time.Second):
		t.Fatalf("no answer to %v", req["op"])
		return nil
	}
}

func (r *rustACME) want(t *testing.T, name string, renewal bool) {
	t.Helper()
	e := r.events.next(t, name)
	if e.err != "" {
		t.Fatalf("rust: %s failed: %s", name, e.err)
	}
	if e.renewal != renewal {
		t.Errorf("rust: %s renewal = %v, want %v", name, e.renewal, renewal)
	}
}

func (r *rustACME) wantFailure(t *testing.T, name string) string {
	t.Helper()
	e := r.events.next(t, name)
	if e.err == "" {
		t.Fatalf("rust: %s obtained", name)
	}
	return e.err
}

func (r *rustACME) none(t *testing.T, name string, d time.Duration) {
	t.Helper()
	r.events.none(t, name, d)
}

// checkStored: both managers serve the same bundle for name, a chain
// for name whose key is the stored key, with metadata certmagic reads.
func (l *acmeLab) checkStored(t *testing.T, g *ACME, r *rustACME, name string) {
	t.Helper()
	gb, ok := g.Certificate(l.ctx, name)
	if !ok {
		t.Fatalf("go: no certificate for %s", name)
	}
	rb, _ := r.call(t, map[string]any{"op": "certificate", "name": name})["pem"].(string)
	if rb != string(gb) {
		t.Fatalf("the bundles of %s differ", name)
	}
	if _, err := tls.X509KeyPair(gb, gb); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	leaf, err := x509.ParseCertificate(firstBlock(t, gb))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(leaf.DNSNames, []string{name}) {
		t.Errorf("%s: names %v", name, leaf.DNSNames)
	}
	meta, err := l.storage.Load(l.ctx, certmagic.StorageKeys.SiteMeta(l.issuer, name))
	if err != nil {
		t.Fatal(err)
	}
	var res certmagic.CertificateResource
	var data acme.Certificate
	if err := json.Unmarshal(meta, &res); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(res.IssuerData, &data); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.SANs, []string{name}) || data.CA != l.ca || data.URL == "" || data.Account == "" ||
		data.RenewalInfo == nil || !data.RenewalInfo.HasWindow() || data.RenewalInfo.SelectedTime.IsZero() {
		t.Errorf("%s: metadata %s", name, meta)
	}
}

func firstBlock(t *testing.T, b []byte) []byte {
	t.Helper()
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatal("no PEM block")
	}
	return blk.Bytes
}

func (l *acmeLab) serial(t *testing.T, name string) string {
	t.Helper()
	b, err := l.storage.Load(l.ctx, certmagic.StorageKeys.SiteCert(l.issuer, name))
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(firstBlock(t, b))
	if err != nil {
		t.Fatal(err)
	}
	return c.SerialNumber.String()
}

func (l *acmeLab) exists(t *testing.T, key string) bool {
	t.Helper()
	return l.storage.Exists(l.ctx, key)
}

func httpGet(t *testing.T, method, addr, host, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+addr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// cfStandIn answers Cloudflare's API for the lab's zones, each with its
// own token: example.test the cluster's, custom.test an app's.
type cfStandIn struct {
	mu               sync.Mutex
	records          map[string]cfRecord
	next             int
	created, deleted int
}

type cfRecord struct{ zone, name, content string }

var cfZones = map[string]struct{ id, token string }{
	"example.test": {"zone-1", labRootToken},
	"custom.test":  {"zone-2", labAppToken},
}

func newCFStandIn() *cfStandIn { return &cfStandIn{records: map[string]cfRecord{}} }

func (c *cfStandIn) counts() (created, deleted, left int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.created, c.deleted, len(c.records)
}

func (c *cfStandIn) txt(name string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, r := range c.records {
		if r.name == name {
			out = append(out, strings.Trim(r.content, `"`))
		}
	}
	return out
}

func cfReply(w http.ResponseWriter, status int, result any, errs ...string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	var es []map[string]any
	for _, e := range errs {
		es = append(es, map[string]any{"code": 9109, "message": e})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": len(errs) == 0, "errors": es, "result": result})
}

func (c *cfStandIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/client/v4")
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	zoneByID := func(id string) (string, bool) {
		for name, z := range cfZones {
			if z.id == id {
				return name, z.token == token
			}
		}
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case path == "/zones" && r.Method == http.MethodGet:
		name := strings.TrimSuffix(r.URL.Query().Get("name"), ".")
		z, ok := cfZones[name]
		if !ok || z.token != token {
			cfReply(w, http.StatusForbidden, nil, "Invalid access token")
			return
		}
		cfReply(w, http.StatusOK, []map[string]any{{"id": z.id, "name": name}})
	case len(parts) >= 3 && parts[0] == "zones" && parts[2] == "dns_records":
		zone, ok := zoneByID(parts[1])
		if !ok {
			cfReply(w, http.StatusForbidden, nil, "Invalid access token")
			return
		}
		switch {
		case len(parts) == 3 && r.Method == http.MethodPost:
			var rec struct{ Type, Name, Content string }
			if err := json.NewDecoder(r.Body).Decode(&rec); err != nil || rec.Type != "TXT" {
				cfReply(w, http.StatusBadRequest, nil, "bad record")
				return
			}
			full := rec.Name + "." + zone
			c.next++
			id := fmt.Sprintf("rec-%d", c.next)
			c.records[id] = cfRecord{zone: zone, name: full, content: rec.Content}
			c.created++
			cfReply(w, http.StatusOK, map[string]any{"id": id, "type": "TXT", "name": full, "content": rec.Content})
		case len(parts) == 3 && r.Method == http.MethodGet:
			q := r.URL.Query()
			var out []map[string]any
			for id, rec := range c.records {
				if rec.zone == zone && rec.name == q.Get("name") && strings.Contains(rec.content, q.Get("content.contains")) {
					out = append(out, map[string]any{"id": id, "type": "TXT", "name": rec.name, "content": rec.content})
				}
			}
			cfReply(w, http.StatusOK, out)
		case len(parts) == 4 && r.Method == http.MethodDelete:
			if _, ok := c.records[parts[3]]; !ok {
				cfReply(w, http.StatusNotFound, nil, "no such record")
				return
			}
			delete(c.records, parts[3])
			c.deleted++
			cfReply(w, http.StatusOK, map[string]any{"id": parts[3]})
		default:
			cfReply(w, http.StatusNotFound, nil, "not found")
		}
	default:
		cfReply(w, http.StatusNotFound, nil, "not found")
	}
}
