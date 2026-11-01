// Package secrets encrypts secret values at rest with envelope encryption
// and provides a value type that never prints its contents.
//
// Every secret version is encrypted with its own random data key
// (AES-256-GCM); the data key is encrypted with the cluster master key. Both
// layers bind the secret's scope, name, and version as additional data, so a
// ciphertext cannot be moved to another secret or version.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"github.com/ryanbekhen/armada/internal/fsutil"
)

// MaxSize is the largest secret value accepted.
const MaxSize = 64 << 10

const (
	keySize  = 32
	redacted = "[REDACTED]"
)

// Value is a secret's plaintext. It redacts itself in every fmt verb, in
// slog, and in JSON/text encoding; use Bytes to get the contents.
type Value struct {
	b []byte
}

// NewValue copies b into a Value.
func NewValue(b []byte) Value { return Value{b: append([]byte(nil), b...)} }

// Bytes returns a copy of the plaintext.
func (v Value) Bytes() []byte { return append([]byte(nil), v.b...) }

// Len returns the plaintext length.
func (v Value) Len() int { return len(v.b) }

// String implements fmt.Stringer.
func (Value) String() string { return redacted }

// GoString implements fmt.GoStringer.
func (Value) GoString() string { return redacted }

// Format implements fmt.Formatter so that no verb (%x, %q, ...) reveals the
// contents.
func (Value) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// LogValue implements slog.LogValuer.
func (Value) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText implements encoding.TextMarshaler (and so JSON encoding).
func (Value) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Sealed is an encrypted secret version as stored.
type Sealed struct {
	// KeyID identifies the master key that wrapped the data key.
	KeyID string
	// WrappedKey is nonce || AES-GCM(master key, data key).
	WrappedKey []byte
	// Ciphertext is nonce || AES-GCM(data key, plaintext).
	Ciphertext []byte
}

// ErrWrongKey means a secret was sealed with a different master key.
var ErrWrongKey = errors.New("secret was encrypted with a different master key")

// Keyring holds the cluster master key.
type Keyring struct {
	key []byte
	id  string
}

// NewKeyring wraps a 32-byte master key.
func NewKeyring(key []byte) (*Keyring, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", keySize, len(key))
	}
	sum := sha256.Sum256(key)
	return &Keyring{key: append([]byte(nil), key...), id: hex.EncodeToString(sum[:8])}, nil
}

// GenerateKeyFile writes a new random master key to path (mode 0600). It
// fails if the file exists.
func GenerateKeyFile(path string) error {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	enc := []byte(hex.EncodeToString(key) + "\n")
	return fsutil.WriteFileExclusive(path, enc, 0o600)
}

// Export returns the master key in the key file encoding, for a control
// plane node that joins the cluster.
func (k *Keyring) Export() Value { return NewValue([]byte(hex.EncodeToString(k.key) + "\n")) }

// WriteKeyFile writes a master key exported by Export to path (mode 0600).
// It fails if the file exists or the key is invalid.
func WriteKeyFile(path string, v Value) error {
	key, err := hex.DecodeString(strings.TrimSpace(string(v.Bytes())))
	if err != nil {
		return errors.New("master key is not valid hex")
	}
	if _, err := NewKeyring(key); err != nil {
		return err
	}
	return fsutil.WriteFileExclusive(path, v.Bytes(), 0o600)
}

// LoadKeyFile reads a master key written by GenerateKeyFile, refusing files
// readable by others.
func LoadKeyFile(path string) (*Keyring, error) {
	b, err := fsutil.ReadPrivateFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("master key %s is not valid hex", path)
	}
	return NewKeyring(key)
}

// ID identifies the master key without revealing it.
func (k *Keyring) ID() string { return k.id }

// String implements fmt.Stringer without revealing the key.
func (k *Keyring) String() string { return "keyring(" + k.id + ")" }

// Seal encrypts v as version of secret name in scope.
func (k *Keyring) Seal(scope, name string, version int, v Value) (Sealed, error) {
	if v.Len() > MaxSize {
		return Sealed{}, fmt.Errorf("secret is %d bytes; the limit is %d", v.Len(), MaxSize)
	}
	dataKey := make([]byte, keySize)
	if _, err := rand.Read(dataKey); err != nil {
		return Sealed{}, err
	}
	ad := additionalData(scope, name, version)
	ct, err := seal(dataKey, v.b, ad)
	if err != nil {
		return Sealed{}, err
	}
	wrapped, err := seal(k.key, dataKey, ad)
	if err != nil {
		return Sealed{}, err
	}
	clear(dataKey)
	return Sealed{KeyID: k.id, WrappedKey: wrapped, Ciphertext: ct}, nil
}

// Open decrypts s, which must have been sealed for the same scope, name, and
// version.
func (k *Keyring) Open(s Sealed, scope, name string, version int) (Value, error) {
	if s.KeyID != k.id {
		return Value{}, ErrWrongKey
	}
	ad := additionalData(scope, name, version)
	dataKey, err := open(k.key, s.WrappedKey, ad)
	if err != nil {
		return Value{}, fmt.Errorf("unwrap data key of %s/%s v%d: %w", scope, name, version, err)
	}
	defer clear(dataKey)
	pt, err := open(dataKey, s.Ciphertext, ad)
	if err != nil {
		return Value{}, fmt.Errorf("decrypt %s/%s v%d: %w", scope, name, version, err)
	}
	return Value{b: pt}, nil
}

func additionalData(scope, name string, version int) []byte {
	return []byte("armada-secret-v1\x00" + scope + "\x00" + name + "\x00" + strconv.Itoa(version))
}

func seal(key, plaintext, ad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, ad), nil
}

func open(key, sealed, ad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	n := aead.NonceSize()
	pt, err := aead.Open(nil, sealed[:n], sealed[n:], ad)
	if err != nil {
		return nil, errors.New("authentication failed")
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
