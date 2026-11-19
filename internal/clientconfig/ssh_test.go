package clientconfig

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryanbekhen/armada/internal/clientconfig/sshtest"
)

func TestMain(m *testing.M) {
	sshtest.Main()
	SSHProgram = os.Args[0]
	os.Exit(m.Run())
}

func TestCheckSSH(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"app-01", "devops@139.190.96.130", "ops@bastion.example.com", "ssh://ops@bastion.example.com:2222", "bastion_1.lan", "[2001:db8::1]"} {
		if err := CheckSSH(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-oProxyCommand=touch /tmp/x", "-v", "a b", "host;id", "$(id)", "host\n", "@host", "user@-host", "ssh://-oProxyCommand=x", strings.Repeat("a", 256)} {
		if err := CheckSSH(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// A config whose ssh field is not a destination is refused on load.
func TestLoadRefusesBadSSH(t *testing.T) {
	t.Parallel()
	c := validConfig(t)
	c.SSH = "-oProxyCommand=id"
	path := filepath.Join(t.TempDir(), "config")
	if err := c.SaveFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "ssh destination") {
		t.Errorf("load: %v", err)
	}
	c.SSH = "ops@" + sshtest.Host
	if err := c.SaveFile(path); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(path); err != nil || got.SSH != c.SSH {
		t.Errorf("load: %+v, %v", got, err)
	}
}

// The dialer relays bytes through `ssh -W ADDR DEST`, both ways.
func TestSSHDialerRelays(t *testing.T) {
	t.Parallel()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	go func() {
		c, err := lis.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.Copy(c, c) // echo
	}()
	c, err := sshDialer(sshtest.Host)(context.Background(), lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("hello through ssh")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, len("hello through ssh"))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello through ssh" {
		t.Errorf("read %q, %v", buf, err)
	}
	if c.RemoteAddr().String() != lis.Addr().String() || c.RemoteAddr().Network() != "ssh" {
		t.Errorf("remote addr %v", c.RemoteAddr())
	}
}

// What ssh says when it fails reaches the person.
func TestSSHDialerSaysWhy(t *testing.T) {
	t.Parallel()
	c, err := sshDialer("nowhere.invalid")(context.Background(), "127.0.0.1:7443")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err = c.Read(make([]byte, 1))
	if err == nil || !strings.Contains(err.Error(), "Could not resolve hostname nowhere.invalid") || !strings.Contains(err.Error(), "127.0.0.1:7443") {
		t.Errorf("read: %v", err)
	}
	if _, err := sshDialer(sshtest.Host)(context.Background(), "-oProxyCommand=id"); err == nil {
		t.Error("an address that looks like an option was dialled")
	}
}
