package clusternet

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ryanbekhen/armada/internal/fsutil"
)

// PrivateKey is a node's WireGuard private key. It never prints itself.
type PrivateKey struct{ k wgtypes.Key }

// String redacts the key.
func (PrivateKey) String() string { return "[redacted]" }

// LogValue redacts the key.
func (PrivateKey) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// Public returns the key's public half, which peers know the node by.
func (p PrivateKey) Public() string { return p.k.PublicKey().String() }

// IsZero reports whether the key is unset.
func (p PrivateKey) IsZero() bool { return p.k == wgtypes.Key{} }

// LoadOrCreateKey reads the node's key from path, a private file, or
// generates one there the first time (ADR 0027).
func LoadOrCreateKey(path string) (PrivateKey, error) {
	b, err := fsutil.ReadPrivateFile(path)
	switch {
	case err == nil:
		k, err := wgtypes.ParseKey(strings.TrimSpace(string(b)))
		if err != nil || k == (wgtypes.Key{}) {
			return PrivateKey{}, fmt.Errorf("%s does not hold a valid key", path)
		}
		return PrivateKey{k: k}, nil
	case !errors.Is(err, fs.ErrNotExist):
		return PrivateKey{}, err
	}
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return PrivateKey{}, err
	}
	if err := fsutil.WriteFileExclusive(path, []byte(k.String()+"\n"), 0o600); err != nil {
		return PrivateKey{}, err
	}
	return PrivateKey{k: k}, nil
}
