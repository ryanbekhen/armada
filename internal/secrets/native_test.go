package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The parity tests of the Rust port (ADR 0055): armada-secrets-parity,
// built with `cargo build -p armada-secrets --features parity`, opens what
// this package seals and the reverse, reads and writes the same master key
// files, and refuses what this package refuses with the same texts.

type rustAnswer map[string]any

func (a rustAnswer) str(k string) string { s, _ := a[k].(string); return s }

func rust(t *testing.T, cmd string, req map[string]any) rustAnswer {
	t.Helper()
	bin := os.Getenv("ARMADA_SECRETS_BIN")
	if bin == "" {
		t.Skip("ARMADA_SECRETS_BIN is not set (cargo build -p armada-secrets --features parity)")
	}
	in, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	c := exec.Command(bin, cmd)
	c.Stdin = bytes.NewReader(in)
	c.Stderr = os.Stderr
	out, err := c.Output()
	if err != nil {
		t.Fatalf("armada-secrets-parity %s: %v", cmd, err)
	}
	var a rustAnswer
	if err := json.Unmarshal(out, &a); err != nil {
		t.Fatalf("armada-secrets-parity %s answered %q: %v", cmd, out, err)
	}
	return a
}

func randomKey(t *testing.T) ([]byte, *Keyring) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	k, err := NewKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, k
}

// privateDir is a directory only its owner may open.
func privateDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func sealedReq(key []byte, s Sealed, scope, name string, version int) map[string]any {
	return map[string]any{"key": hex.EncodeToString(key), "keyId": s.KeyID, "wrappedKey": hex.EncodeToString(s.WrappedKey),
		"ciphertext": hex.EncodeToString(s.Ciphertext), "scope": scope, "name": name, "version": version}
}

func TestArmadaSecretsOpenWhatGoSeals(t *testing.T) {
	key, k := randomKey(t)
	big := make([]byte, MaxSize)
	_, _ = rand.Read(big)
	for _, tc := range []struct {
		scope, name string
		version     int
		value       []byte
	}{
		{"web", "DB_URL", 1, []byte("postgres://u:p@db/app")},
		{"cluster", "dns-token", 7, []byte("token\n")},
		{"api.space-1", "db/url", 0, nil},
		{"x\x00y", "a\x00b", -3, []byte{0, 1, 2, 255}},
		{"π", "ключ", 1 << 40, big},
	} {
		// Go seals, Rust opens.
		s, err := k.Seal(tc.scope, tc.name, tc.version, NewValue(tc.value))
		if err != nil {
			t.Fatal(err)
		}
		a := rust(t, "open", sealedReq(key, s, tc.scope, tc.name, tc.version))
		if a.str("error") != "" || a.str("value") != hex.EncodeToString(tc.value) {
			t.Errorf("%s/%s: Rust opened %v", tc.scope, tc.name, a.str("error"))
		}
		if strings.Contains(a.str("shown"), hex.EncodeToString(tc.value)) && len(tc.value) > 0 || a.str("shown") != "[REDACTED] [REDACTED]" {
			t.Errorf("Rust prints a value: %q", a.str("shown"))
		}
		// Rust seals, Go opens.
		r := rust(t, "seal", map[string]any{"key": hex.EncodeToString(key), "scope": tc.scope, "name": tc.name, "version": tc.version, "value": hex.EncodeToString(tc.value)})
		if r.str("error") != "" {
			t.Fatal(r.str("error"))
		}
		wrapped, _ := hex.DecodeString(r.str("wrappedKey"))
		ct, _ := hex.DecodeString(r.str("ciphertext"))
		rs := Sealed{KeyID: r.str("keyId"), WrappedKey: wrapped, Ciphertext: ct}
		if rs.KeyID != k.ID() || len(wrapped) != len(s.WrappedKey) || len(ct) != len(s.Ciphertext) {
			t.Errorf("Rust's sealed form differs: id %q, %d/%d bytes", rs.KeyID, len(wrapped), len(ct))
		}
		v, err := k.Open(rs, tc.scope, tc.name, tc.version)
		if err != nil || !bytes.Equal(v.Bytes(), tc.value) {
			t.Errorf("%s/%s: Go opens Rust's: %v", tc.scope, tc.name, err)
		}
	}
}

func TestArmadaSecretsRefuseWhatGoRefuses(t *testing.T) {
	key, k := randomKey(t)
	otherKey, _ := randomKey(t)
	s, _ := k.Seal("web", "K", 1, NewValue([]byte("v")))
	flip := func(b []byte) []byte {
		b = append([]byte(nil), b...)
		b[len(b)-1] ^= 1
		return b
	}
	cases := map[string]struct {
		key         []byte
		s           Sealed
		scope, name string
		version     int
	}{
		"other scope":   {key, s, "api", "K", 1},
		"other name":    {key, s, "web", "L", 1},
		"other version": {key, s, "web", "K", 2},
		"ciphertext":    {key, Sealed{s.KeyID, s.WrappedKey, flip(s.Ciphertext)}, "web", "K", 1},
		"nonce":         {key, Sealed{s.KeyID, s.WrappedKey, append([]byte{s.Ciphertext[0] ^ 1}, s.Ciphertext[1:]...)}, "web", "K", 1},
		"wrapped key":   {key, Sealed{s.KeyID, flip(s.WrappedKey), s.Ciphertext}, "web", "K", 1},
		"short":         {key, Sealed{s.KeyID, s.WrappedKey, []byte{1, 2, 3}}, "web", "K", 1},
		"short wrapped": {key, Sealed{s.KeyID, s.WrappedKey[:27], s.Ciphertext}, "web", "K", 1},
		"empty":         {key, Sealed{s.KeyID, nil, nil}, "web", "K", 1},
		"swapped":       {key, Sealed{s.KeyID, s.Ciphertext, s.WrappedKey}, "web", "K", 1},
		"other key":     {otherKey, s, "web", "K", 1},
		"other key id":  {key, Sealed{"0011223344556677", s.WrappedKey, s.Ciphertext}, "web", "K", 1},
	}
	for name, tc := range cases {
		gk, _ := NewKeyring(tc.key)
		_, goErr := gk.Open(tc.s, tc.scope, tc.name, tc.version)
		a := rust(t, "open", sealedReq(tc.key, tc.s, tc.scope, tc.name, tc.version))
		if goErr == nil || a.str("error") != goErr.Error() || a["wrongKey"] != errors.Is(goErr, ErrWrongKey) {
			t.Errorf("%s: Go %v, Rust %v", name, goErr, a)
		}
	}
	tooBig := hex.EncodeToString(make([]byte, MaxSize+1))
	_, goErr := k.Seal("s", "n", 1, NewValue(make([]byte, MaxSize+1)))
	if a := rust(t, "seal", map[string]any{"key": hex.EncodeToString(key), "scope": "s", "name": "n", "version": 1, "value": tooBig}); goErr == nil || a.str("error") != goErr.Error() {
		t.Errorf("too large: Go %v, Rust %v", goErr, a)
	}
	for _, n := range []int{0, 16, 31, 33} {
		_, goErr := NewKeyring(make([]byte, n))
		if a := rust(t, "seal", map[string]any{"key": hex.EncodeToString(make([]byte, n))}); goErr == nil || a.str("error") != goErr.Error() {
			t.Errorf("%d-byte key: Go %v, Rust %v", n, goErr, a)
		}
	}
}

func TestArmadaSecretsKeyFiles(t *testing.T) {
	dir := t.TempDir()
	// Go writes, Rust reads; Rust writes, Go reads.
	goPath := filepath.Join(dir, "go.key")
	if err := GenerateKeyFile(goPath); err != nil {
		t.Fatal(err)
	}
	gk, _ := LoadKeyFile(goPath)
	a := rust(t, "load-key-file", map[string]any{"path": goPath})
	export, _ := hex.DecodeString(a.str("export"))
	if a.str("id") != gk.ID() || !bytes.Equal(export, gk.Export().Bytes()) {
		t.Errorf("Rust reads Go's key file as %v", a)
	}
	if shown := a.str("shown"); shown != gk.String()+" "+gk.String() {
		t.Errorf("Rust shows the keyring as %q", shown)
	}
	rustPath := filepath.Join(dir, "rust.key")
	if a := rust(t, "generate-key-file", map[string]any{"path": rustPath}); a.str("error") != "" {
		t.Fatal(a.str("error"))
	}
	fi, err := os.Stat(rustPath)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("Rust's key file: %v %v", fi.Mode(), err)
	}
	b, _ := os.ReadFile(rustPath)
	if len(b) != 65 || b[64] != '\n' {
		t.Errorf("Rust's key file is %q", b)
	}
	rk, err := LoadKeyFile(rustPath)
	if err != nil {
		t.Fatal(err)
	}
	if a := rust(t, "load-key-file", map[string]any{"path": rustPath}); a.str("id") != rk.ID() {
		t.Errorf("ids differ: %q, %q", a.str("id"), rk.ID())
	}
	// A secret sealed by Rust with its key file opens in Go.
	r := rust(t, "seal", map[string]any{"keyFile": rustPath, "scope": "s", "name": "n", "version": 2, "value": hex.EncodeToString([]byte("v"))})
	w, _ := hex.DecodeString(r.str("wrappedKey"))
	c, _ := hex.DecodeString(r.str("ciphertext"))
	if v, err := rk.Open(Sealed{r.str("keyId"), w, c}, "s", "n", 2); err != nil || string(v.Bytes()) != "v" {
		t.Errorf("Go opens Rust's: %v", err)
	}

	// Export and WriteKeyFile, both ways.
	exported := filepath.Join(dir, "exported.key")
	if a := rust(t, "write-key-file", map[string]any{"path": exported, "value": hex.EncodeToString(gk.Export().Bytes())}); a.str("error") != "" {
		t.Fatal(a.str("error"))
	}
	if k, err := LoadKeyFile(exported); err != nil || k.ID() != gk.ID() {
		t.Errorf("Go reads Rust's written key: %v", err)
	}

	// Refusals with Go's texts.
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	valid := hex.EncodeToString(make([]byte, 32)) + "\n"
	for name, path := range map[string]string{
		"loose mode":   write("loose.key", valid, 0o644),
		"group read":   write("group.key", valid, 0o640),
		"not hex":      write("nothex.key", "zz\n", 0o600),
		"odd hex":      write("odd.key", "abc\n", 0o600),
		"short":        write("short.key", "abcd\n", 0o600),
		"upper case":   write("upper.key", strings.ToUpper(valid), 0o600),
		"white space":  write("space.key", "  \t"+valid+"\r\n\n", 0o600),
		"missing":      filepath.Join(dir, "missing.key"),
		"a directory":  privateDir(t),
		"empty":        write("empty.key", "", 0o600),
		"inner spaces": write("inner.key", valid[:10]+" "+valid[10:], 0o600),
	} {
		gk, goErr := LoadKeyFile(path)
		a := rust(t, "load-key-file", map[string]any{"path": path})
		switch {
		case goErr != nil && a.str("error") != goErr.Error():
			t.Errorf("%s: Go %q, Rust %q", name, goErr, a.str("error"))
		case goErr == nil && a.str("id") != gk.ID():
			t.Errorf("%s: Go read %s, Rust %v", name, gk.ID(), a)
		}
	}
	for name, tc := range map[string]struct{ path, value string }{
		"exists":  {goPath, hex.EncodeToString(gk.Export().Bytes())},
		"not hex": {filepath.Join(dir, "w1"), hex.EncodeToString([]byte("nothex"))},
		"short":   {filepath.Join(dir, "w2"), hex.EncodeToString([]byte("abcd\n"))},
	} {
		v, _ := hex.DecodeString(tc.value)
		goErr := WriteKeyFile(tc.path+".go", NewValue(v))
		if name == "exists" {
			goErr = WriteKeyFile(tc.path, NewValue(v))
		}
		a := rust(t, "write-key-file", map[string]any{"path": tc.path, "value": tc.value})
		if goErr == nil || a.str("error") != goErr.Error() {
			t.Errorf("%s: Go %v, Rust %q", name, goErr, a.str("error"))
		}
	}
	if a := rust(t, "generate-key-file", map[string]any{"path": goPath}); a.str("error") != GenerateKeyFile(goPath).Error() {
		t.Errorf("generate over an existing file: Rust %q", a.str("error"))
	}
}
