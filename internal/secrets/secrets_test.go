package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/fsutil"
)

const marker = "hunter2-plaintext"

func keyring(t *testing.T, b byte) *Keyring {
	t.Helper()
	k, err := NewKeyring(bytes.Repeat([]byte{b}, keySize))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestValueNeverPrints(t *testing.T) {
	t.Parallel()
	v := NewValue([]byte(marker))
	type wrapper struct {
		V Value
		P *Value
	}
	w := wrapper{V: v, P: &v}
	var out []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		out = append(out, fmt.Sprintf(verb, v), fmt.Sprintf(verb, w))
	}
	j, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, string(j))
	var logs bytes.Buffer
	for _, h := range []slog.Handler{slog.NewTextHandler(&logs, nil), slog.NewJSONHandler(&logs, nil)} {
		slog.New(h).Info("msg", "secret", v, "ptr", &v)
	}
	out = append(out, logs.String())
	for _, s := range out {
		if strings.Contains(s, marker) || strings.Contains(s, fmt.Sprintf("%x", marker)) {
			t.Errorf("plaintext leaked: %s", s)
		}
	}
	if string(v.Bytes()) != marker || v.Len() != len(marker) {
		t.Error("Bytes/Len do not return the value")
	}
	// Bytes returns a copy.
	b := v.Bytes()
	b[0] = 'X'
	if string(v.Bytes()) != marker {
		t.Error("Bytes exposes internal storage")
	}
}

func TestSealOpen(t *testing.T) {
	t.Parallel()
	k := keyring(t, 1)
	s, err := k.Seal("web", "db", 3, NewValue([]byte(marker)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(s.Ciphertext, []byte(marker)) || bytes.Contains(s.WrappedKey, bytes.Repeat([]byte{1}, keySize)) {
		t.Fatal("sealed output contains plaintext or the master key")
	}
	v, err := k.Open(s, "web", "db", 3)
	if err != nil || string(v.Bytes()) != marker {
		t.Fatalf("Open = %v", err)
	}
	// Same input, fresh data key and nonces.
	s2, _ := k.Seal("web", "db", 3, NewValue([]byte(marker)))
	if bytes.Equal(s.Ciphertext, s2.Ciphertext) || bytes.Equal(s.WrappedKey, s2.WrappedKey) {
		t.Error("sealing is deterministic")
	}
	empty, err := k.Seal("web", "e", 1, NewValue(nil))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := k.Open(empty, "web", "e", 1); err != nil || v.Len() != 0 {
		t.Errorf("empty secret = %v", err)
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	t.Parallel()
	k := keyring(t, 1)
	s, _ := k.Seal("web", "db", 3, NewValue([]byte(marker)))
	other, _ := k.Seal("web", "api", 1, NewValue([]byte("other")))
	flip := func(b []byte, i int) []byte {
		c := bytes.Clone(b)
		c[i] ^= 1
		return c
	}
	cases := map[string]struct {
		s                 Sealed
		scope, name       string
		version           int
		wantWrongKeyError bool
	}{
		"other app":             {s, "api", "db", 3, false},
		"other name":            {s, "web", "api", 3, false},
		"other version":         {s, "web", "db", 2, false},
		"flipped ciphertext":    {Sealed{s.KeyID, s.WrappedKey, flip(s.Ciphertext, len(s.Ciphertext)-1)}, "web", "db", 3, false},
		"flipped nonce":         {Sealed{s.KeyID, s.WrappedKey, flip(s.Ciphertext, 0)}, "web", "db", 3, false},
		"flipped wrapped key":   {Sealed{s.KeyID, flip(s.WrappedKey, 20), s.Ciphertext}, "web", "db", 3, false},
		"swapped wrapped key":   {Sealed{s.KeyID, other.WrappedKey, s.Ciphertext}, "web", "db", 3, false},
		"swapped ciphertext":    {Sealed{s.KeyID, s.WrappedKey, other.Ciphertext}, "web", "db", 3, false},
		"truncated":             {Sealed{s.KeyID, s.WrappedKey, s.Ciphertext[:10]}, "web", "db", 3, false},
		"empty":                 {Sealed{KeyID: s.KeyID}, "web", "db", 3, false},
		"other master key":      {s, "web", "db", 3, true},
		"spoofed key id":        {Sealed{keyring(t, 2).ID(), s.WrappedKey, s.Ciphertext}, "web", "db", 3, true},
		"name/version boundary": {s, "web", "db\x003", 0, false},
	}
	for name, tc := range cases {
		opener := k
		if name == "other master key" {
			opener = keyring(t, 2)
		}
		v, err := opener.Open(tc.s, tc.scope, tc.name, tc.version)
		if err == nil {
			t.Errorf("%s: Open succeeded", name)
			continue
		}
		if errors.Is(err, ErrWrongKey) != tc.wantWrongKeyError {
			t.Errorf("%s: err = %v", name, err)
		}
		if v.Len() != 0 || strings.Contains(err.Error(), marker) {
			t.Errorf("%s: leaked data: %v", name, err)
		}
	}
	// A key with a spoofed ID still cannot decrypt.
	k2 := keyring(t, 2)
	k2.id = k.id
	if _, err := k2.Open(s, "web", "db", 3); err == nil || errors.Is(err, ErrWrongKey) {
		t.Errorf("spoofed keyring = %v, want authentication failure", err)
	}
}

func TestSealLimits(t *testing.T) {
	t.Parallel()
	k := keyring(t, 1)
	if _, err := k.Seal("a", "b", 1, NewValue(make([]byte, MaxSize+1))); err == nil {
		t.Error("oversized secret accepted")
	}
	if _, err := k.Seal("a", "b", 1, NewValue(make([]byte, MaxSize))); err != nil {
		t.Errorf("max-size secret rejected: %v", err)
	}
	if _, err := NewKeyring(make([]byte, 16)); err == nil {
		t.Error("short master key accepted")
	}
	if s := fmt.Sprint(k); strings.Contains(s, "0101") || !strings.Contains(s, k.ID()) {
		t.Errorf("keyring prints as %q", s)
	}
}

func TestKeyFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	if err := GenerateKeyFile(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, %v", fi.Mode(), err)
	}
	before, _ := os.ReadFile(path)
	if err := GenerateKeyFile(path); err == nil {
		t.Error("existing master key overwritten")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("existing master key modified")
	}
	k, err := LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := k.Seal("a", "b", 1, NewValue([]byte("x")))
	k2, _ := LoadKeyFile(path)
	if _, err := k2.Open(s, "a", "b", 1); err != nil {
		t.Errorf("reloaded key cannot open: %v", err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(path); !errors.Is(err, fsutil.ErrInsecurePermissions) {
		t.Errorf("world-readable key = %v", err)
	}
	for name, content := range map[string]string{"bad-hex": "zz\n", "short": "abcd\n", "empty": ""} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKeyFile(p); err == nil {
			t.Errorf("%s key accepted", name)
		}
	}
	if _, err := LoadKeyFile(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing key = %v", err)
	}
}

func TestExportWriteKeyFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := filepath.Join(dir, "master.key")
	if err := GenerateKeyFile(src); err != nil {
		t.Fatal(err)
	}
	k, _ := LoadKeyFile(src)
	exp := k.Export()
	if fmt.Sprint(exp) != redacted {
		t.Error("exported key prints")
	}
	dst := filepath.Join(dir, "copy.key")
	if err := WriteKeyFile(dst, exp); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dst); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", fi.Mode().Perm())
	}
	if k2, err := LoadKeyFile(dst); err != nil || k2.ID() != k.ID() {
		t.Errorf("copied key: %v", err)
	}
	if err := WriteKeyFile(dst, exp); err == nil {
		t.Error("existing key overwritten")
	}
	for _, bad := range []string{"zz", "abcd", ""} {
		if err := WriteKeyFile(filepath.Join(dir, "bad"+bad), NewValue([]byte(bad))); err == nil {
			t.Errorf("invalid key %q written", bad)
		}
	}
}
