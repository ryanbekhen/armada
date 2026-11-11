package spec

import (
	"strings"
	"testing"
)

func TestNFSVolumes(t *testing.T) {
	t.Parallel()
	ok := "name: web\nimage: nginx:1\nscale:\n  min: 3\n  max: 3\nvolumes:\n  - name: uploads\n    path: /uploads\n    nfs:\n      server: 10.0.0.20\n      path: /exports/uploads\n      readOnly: true\n"
	a, err := Parse([]byte(ok))
	if err != nil {
		t.Fatal(err)
	}
	if a.HasLocalVolumes() || !a.HasNFSVolumes() || !a.HasVolumes() || a.Replicas() != 3 {
		t.Errorf("local=%v nfs=%v replicas=%d", a.HasLocalVolumes(), a.HasNFSVolumes(), a.Replicas())
	}
	if n := a.Volumes[0].NFS; n.Server != "10.0.0.20" || n.Path != "/exports/uploads" || !n.ReadOnly {
		t.Errorf("nfs = %+v", n)
	}
	for _, server := range []string{"192.168.1.5", "172.20.0.1", "100.64.3.4", "fd12::5"} {
		if err := CheckNFSServer(server); err != nil {
			t.Errorf("%s: %v", server, err)
		}
	}
	nfs := func(server, path, extra string) string {
		return "name: web\nimage: nginx:1\nvolumes:\n  - name: uploads\n    path: /uploads\n" + extra + "    nfs:\n      server: " + server + "\n      path: " + path + "\n"
	}
	for _, tc := range []struct{ yaml, want string }{
		{nfs("8.8.8.8", "/x", ""), "private address"},
		{nfs("127.0.0.1", "/x", ""), "private address"},
		{nfs("169.254.169.254", "/x", ""), "private address"},
		{nfs("nfs.example.com", "/x", ""), "IP address"},
		{nfs("fe80::1%eth0", "/x", ""), "IP address"},
		{nfs("10.0.0.20", "exports", ""), "absolute"},
		{nfs("10.0.0.20", "/a/../b", ""), "clean"},
		{nfs("10.0.0.20", "/a,addr=1.2.3.4", ""), "letters, digits"},
		{nfs("10.0.0.20", "/x", "    owner: \"1000:1000\"\n"), "on the NFS server"},
		{nfs("10.0.0.20", "/x", "    backup: {every: 1h, keep: 3, urlSecretRef: u, keySecretRef: k}\n"), "backed up by its server"},
	} {
		if _, err := Parse([]byte(tc.yaml)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v, want %q", err, tc.want)
		}
	}
	// A local volume next to it still binds the app to one replica.
	mixed := "name: web\nimage: nginx:1\nscale:\n  min: 2\n  max: 2\nvolumes:\n  - name: uploads\n    path: /uploads\n    nfs: {server: 10.0.0.20, path: /x}\n  - name: data\n    path: /data\n"
	if _, err := Parse([]byte(mixed)); err == nil || !strings.Contains(err.Error(), "exactly one replica") {
		t.Errorf("mixed: %v", err)
	}
}
