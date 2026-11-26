package secrets

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The parity cases of native_test.go recorded once from Go (ADR 0055,
// item 20): -record-fixtures writes what Go sealed, refused, and wrote as
// secrets/tests/testdata/parity.json, which the crate's tests
// (secrets/tests/parity.rs) replay with no Go:
//
//	go test ./internal/secrets -run TestRecordSecretsFixtures -record-fixtures
var recordFixtures = flag.Bool("record-fixtures", false, "write secrets/tests/testdata/parity.json from Go's answers")

const fixturePath = "../../secrets/tests/testdata/parity.json"

func goError(err error) map[string]any {
	if err == nil {
		return nil
	}
	return map[string]any{"error": err.Error(), "wrongKey": errors.Is(err, ErrWrongKey)}
}

func sealedJSON(s Sealed) map[string]any {
	return map[string]any{"keyId": s.KeyID, "wrappedKey": hex.EncodeToString(s.WrappedKey), "ciphertext": hex.EncodeToString(s.Ciphertext)}
}

func TestRecordSecretsFixtures(t *testing.T) {
	if !*recordFixtures {
		t.Skip("-record-fixtures is not set")
	}
	key, k := randomKey(t)
	out := map[string]any{"key": hex.EncodeToString(key), "keyId": k.ID(), "shown": k.String()}

	// Go seals; Rust opens each and seals the same values.
	big := make([]byte, MaxSize)
	_, _ = rand.Read(big)
	var sealed []any
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
		s, err := k.Seal(tc.scope, tc.name, tc.version, NewValue(tc.value))
		if err != nil {
			t.Fatal(err)
		}
		v, err := k.Open(s, tc.scope, tc.name, tc.version)
		if err != nil {
			t.Fatal(err)
		}
		sealed = append(sealed, map[string]any{"scope": tc.scope, "name": tc.name, "version": tc.version,
			"value": hex.EncodeToString(tc.value), "sealed": sealedJSON(s), "shown": v.String() + " " + v.GoString()})
	}
	out["sealed"] = sealed

	// Refusals.
	otherKey, _ := randomKey(t)
	s, _ := k.Seal("web", "K", 1, NewValue([]byte("v")))
	flip := func(b []byte) []byte {
		b = append([]byte(nil), b...)
		b[len(b)-1] ^= 1
		return b
	}
	var refused []any
	for name, tc := range map[string]struct {
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
	} {
		gk, _ := NewKeyring(tc.key)
		_, goErr := gk.Open(tc.s, tc.scope, tc.name, tc.version)
		if goErr == nil {
			t.Fatalf("%s: Go opened it", name)
		}
		refused = append(refused, map[string]any{"case": name, "key": hex.EncodeToString(tc.key), "sealed": sealedJSON(tc.s),
			"scope": tc.scope, "name": tc.name, "version": tc.version, "want": goError(goErr)})
	}
	sort.Slice(refused, func(i, j int) bool {
		return refused[i].(map[string]any)["case"].(string) < refused[j].(map[string]any)["case"].(string)
	})
	out["refused"] = refused
	_, goErr := k.Seal("s", "n", 1, NewValue(make([]byte, MaxSize+1)))
	out["tooBig"] = goError(goErr)
	var keySizes []any
	for _, n := range []int{0, 16, 31, 33} {
		_, goErr := NewKeyring(make([]byte, n))
		keySizes = append(keySizes, map[string]any{"size": n, "want": goError(goErr)})
	}
	out["keySizes"] = keySizes

	// Key files: Go's file, and the files Go refuses, with the directory
	// as {dir}.
	dir := t.TempDir()
	goPath := filepath.Join(dir, "go.key")
	if err := GenerateKeyFile(goPath); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(goPath)
	gk, _ := LoadKeyFile(goPath)
	out["keyFile"] = map[string]any{"content": string(content), "id": gk.ID(), "export": hex.EncodeToString(gk.Export().Bytes()), "shown": gk.String() + " " + gk.String()}
	placeholder := func(err error) map[string]any {
		m := goError(err)
		if m != nil {
			m["error"] = strings.ReplaceAll(m["error"].(string), dir, "{dir}")
		}
		return m
	}
	valid := hex.EncodeToString(make([]byte, 32)) + "\n"
	var files []any
	for _, tc := range []struct {
		name, file, content string
		mode                os.FileMode
	}{
		{"loose mode", "loose.key", valid, 0o644},
		{"group read", "group.key", valid, 0o640},
		{"not hex", "nothex.key", "zz\n", 0o600},
		{"odd hex", "odd.key", "abc\n", 0o600},
		{"short", "short.key", "abcd\n", 0o600},
		{"upper case", "upper.key", strings.ToUpper(valid), 0o600},
		{"white space", "space.key", "  \t" + valid + "\r\n\n", 0o600},
		{"empty", "empty.key", "", 0o600},
		{"inner spaces", "inner.key", valid[:10] + " " + valid[10:], 0o600},
		{"missing", "missing.key", "", 0},
		{"a directory", "private", "", 0o700 | os.ModeDir},
	} {
		p := filepath.Join(dir, tc.file)
		switch {
		case tc.mode == 0:
		case tc.mode.IsDir():
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		default:
			if err := os.WriteFile(p, []byte(tc.content), tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, tc.mode); err != nil {
				t.Fatal(err)
			}
		}
		gk, goErr := LoadKeyFile(p)
		c := map[string]any{"case": tc.name, "file": tc.file, "content": tc.content, "mode": int(tc.mode.Perm()), "dir": tc.mode.IsDir(), "missing": tc.mode == 0}
		if goErr != nil {
			c["want"] = placeholder(goErr)
		} else {
			c["id"] = gk.ID()
		}
		files = append(files, c)
	}
	out["loadKeyFile"] = files
	var writes []any
	for _, tc := range []struct{ name, file, value string }{
		{"exists", "go.key", hex.EncodeToString(gk.Export().Bytes())},
		{"not hex", "w1", hex.EncodeToString([]byte("nothex"))},
		{"short", "w2", hex.EncodeToString([]byte("abcd\n"))},
	} {
		v, _ := hex.DecodeString(tc.value)
		goErr := WriteKeyFile(filepath.Join(dir, tc.file), NewValue(v))
		if goErr == nil {
			t.Fatalf("%s: Go wrote it", tc.name)
		}
		writes = append(writes, map[string]any{"case": tc.name, "file": tc.file, "value": tc.value, "want": placeholder(goErr)})
	}
	out["writeKeyFile"] = writes
	out["generateExisting"] = placeholder(GenerateKeyFile(goPath))

	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixturePath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
