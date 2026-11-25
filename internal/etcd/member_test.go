package etcd

import (
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"go.etcd.io/etcd/server/v3/embed"

	"github.com/ryanbekhen/armada/internal/pki"
)

var update = flag.Bool("update", false, "rewrite golden files")

func goldenSpec() memberSpec {
	return memberSpec{
		Name:           "cp-1",
		DataDir:        "/var/lib/armada/etcd/data",
		ClientURL:      memberURL(netip.MustParseAddr("10.0.0.5"), DefaultClientPort),
		PeerURL:        memberURL(netip.MustParseAddr("10.0.0.5"), DefaultPeerPort),
		InitialCluster: "cp-1=https://10.0.0.5:2380",
		ClusterState:   clusterStateNew,
		Token:          clusterToken,
		CertFile:       "/var/lib/armada/etcd/member.crt",
		KeyFile:        "/var/lib/armada/etcd/member.key",
		CAFile:         "/var/lib/armada/etcd/ca.crt",
		AllowedCN:      pki.EtcdMember.String(),
	}
}

func TestFileConfigGolden(t *testing.T) {
	t.Parallel()
	joining := goldenSpec()
	joining.InitialCluster = "cp-0=https://10.0.0.4:2380,cp-1=https://10.0.0.5:2380"
	joining.ClusterState = clusterStateExisting
	for name, s := range map[string]memberSpec{"new": goldenSpec(), "joining": joining} {
		b, err := fileConfig(s)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join("testdata", "etcd-"+name+".yaml")
		if *update {
			if err := os.WriteFile(path, b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != string(want) {
			t.Errorf("%s:\n%s\nwant (go test -update):\n%s", name, b, want)
		}
	}
}

// The file armadad etcd writes, read as the pinned etcd reads it
// (embed.ConfigFromFile, what `etcd --config-file` calls), describes the
// member the embedded path starts.
func TestFileConfigMatchesEmbedded(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("test")
	for name, initial := range map[string]string{"new": "", "joining": "cp-0=https://127.0.0.1:12380,cp-1=https://127.0.0.1:2380"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := Config{Dir: filepath.Join(t.TempDir(), "etcd"), Name: "cp-1", Addr: netip.MustParseAddr("127.0.0.1"), CA: ca, InitialCluster: initial}
			path, err := WriteConfigFile(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 || filepath.Base(path) != FileConfig {
				t.Fatalf("%s: %v %v", path, fi, err)
			}
			got, err := embed.ConfigFromFile(path)
			if err != nil {
				t.Fatal(err)
			}
			_, s, err := prepare(cfg)
			if err != nil {
				t.Fatal(err)
			}
			want := embedConfig(s)
			if initial != "" && want.ClusterState != clusterStateExisting {
				t.Errorf("a first start with an initial cluster is %q", want.ClusterState)
			}
			fields := []string{
				"Name", "Dir", "ListenClientUrls", "AdvertiseClientUrls", "ListenPeerUrls", "AdvertisePeerUrls",
				"ListenClientHttpUrls", "ListenMetricsUrls", "InitialCluster", "InitialClusterToken", "ClusterState",
				"EnableGRPCGateway", "TlsMinVersion", "TlsMaxVersion", "CipherSuites", "MaxTxnOps", "AutoCompactionMode",
				"AutoCompactionRetention", "UnsafeNoFsync", "ClientAutoTLS", "PeerAutoTLS", "EnablePprof", "Metrics",
				"AuthToken", "QuotaBackendBytes", "SnapshotCount", "TickMs", "ElectionMs", "MaxRequestBytes",
			}
			gv, wv := reflect.ValueOf(*got), reflect.ValueOf(*want)
			for _, f := range fields {
				if g, w := gv.FieldByName(f).Interface(), wv.FieldByName(f).Interface(); !reflect.DeepEqual(g, w) {
					t.Errorf("%s: file %v, embedded %v", f, g, w)
				}
			}
			for _, side := range []string{"ClientTLSInfo", "PeerTLSInfo"} {
				g, w := gv.FieldByName(side), wv.FieldByName(side)
				for _, f := range []string{"CertFile", "KeyFile", "TrustedCAFile", "ClientCertFile", "ClientKeyFile", "ClientCertAuth", "AllowedCNs", "AllowedHostnames", "SkipClientSANVerify", "CRLFile"} {
					if gf, wf := g.FieldByName(f).Interface(), w.FieldByName(f).Interface(); !reflect.DeepEqual(gf, wf) {
						t.Errorf("%s.%s: file %v, embedded %v", side, f, gf, wf)
					}
				}
				if !g.FieldByName("ClientCertAuth").Bool() || !reflect.DeepEqual(g.FieldByName("AllowedCNs").Interface(), []string{pki.EtcdMember.String()}) || g.FieldByName("SkipClientSANVerify").Bool() {
					t.Errorf("%s: client certificates are not required from the member identity alone", side)
				}
			}
			if got.TlsMinVersion != "TLS1.3" || got.EnableGRPCGateway || len(got.ListenMetricsUrls) != 0 || got.MaxTxnOps != 4096 ||
				got.AutoCompactionMode != "periodic" || got.AutoCompactionRetention != "1h" {
				t.Errorf("settings: tls %s gateway %v metrics %v txn %d compaction %s/%s", got.TlsMinVersion, got.EnableGRPCGateway, got.ListenMetricsUrls, got.MaxTxnOps, got.AutoCompactionMode, got.AutoCompactionRetention)
			}
		})
	}
}

// A data directory without a write-ahead log never started; armadad etcd
// removes it before the pinned etcd sees it, as Start does.
func TestWriteConfigFileRemovesUnstartedData(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("test")
	cfg := Config{Dir: filepath.Join(t.TempDir(), "etcd"), Name: "cp-1", Addr: netip.MustParseAddr("127.0.0.1"), CA: ca}
	junk := filepath.Join(cfg.Dir, dirData, "member", "snap", "db")
	if err := os.MkdirAll(filepath.Dir(junk), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(junk, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteConfigFile(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Dir, dirData)); !os.IsNotExist(err) {
		t.Errorf("data directory without a write-ahead log kept: %v", err)
	}
	for _, f := range []string{fileCert, fileKey, fileCA} {
		if fi, err := os.Stat(filepath.Join(cfg.Dir, f)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, fi, err)
		}
	}
}

func TestWriteConfigFileRefusesPublicAddress(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA("test")
	if _, err := WriteConfigFile(Config{Dir: t.TempDir(), Name: "x", Addr: netip.MustParseAddr("0.0.0.0"), CA: ca}); err == nil {
		t.Error("a public address was accepted")
	}
}
