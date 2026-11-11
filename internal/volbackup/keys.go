package volbackup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// keys are a repository's keys, derived from the key secret and salted
// with the repository's ID.
type keys struct {
	aead  cipher.AEAD
	id    []byte
	gear  [256]uint64
	check string
}

// MinKeyLen is the shortest key secret.
const MinKeyLen = 32

func deriveKeys(secret, repoID []byte) (*keys, error) {
	if len(secret) < MinKeyLen {
		return nil, fmt.Errorf("the backup key must be at least %d bytes", MinKeyLen)
	}
	derive := func(info string, n int) ([]byte, error) {
		return hkdf.Key(sha256.New, secret, repoID, "armada volume backup "+info, n)
	}
	seal, err := derive("seal", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(seal)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	k := &keys{aead: aead}
	if k.id, err = derive("chunk id", 32); err != nil {
		return nil, err
	}
	g, err := derive("gear", 256*8)
	if err != nil {
		return nil, err
	}
	for i := range k.gear {
		k.gear[i] = binary.LittleEndian.Uint64(g[i*8:])
	}
	c, err := derive("check", 32)
	if err != nil {
		return nil, err
	}
	k.check = hex.EncodeToString(c)
	return k, nil
}

// chunkID names a chunk by its plaintext; without the key it says nothing
// about the content.
func (k *keys) chunkID(plain []byte) string {
	m := hmac.New(sha256.New, k.id)
	m.Write(plain)
	return hex.EncodeToString(m.Sum(nil))
}

// seal encrypts plain for the object name, which binds it: an object moved
// to another name does not open.
func (k *keys) seal(name string, plain []byte) []byte {
	nonce := make([]byte, k.aead.NonceSize(), k.aead.NonceSize()+len(plain)+k.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		panic(err) // crypto/rand never fails on supported systems
	}
	return k.aead.Seal(nonce, nonce, plain, []byte(name))
}

var errSealed = errors.New("an object of the backup repository does not open with the backup key: damaged or replaced")

func (k *keys) open(name string, sealed []byte) ([]byte, error) {
	n := k.aead.NonceSize()
	if len(sealed) < n+k.aead.Overhead() {
		return nil, errSealed
	}
	plain, err := k.aead.Open(nil, sealed[:n], sealed[n:], []byte(name))
	if err != nil {
		return nil, errSealed
	}
	return plain, nil
}
