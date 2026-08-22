package akko

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	keySize  = 32
	saltSize = 16
)

// KDFParams stores Argon2id parameters embedded in the header.
type KDFParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
}

var defaultKDFParams = KDFParams{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
}

var defaultExpiryUnix int64

var HighSecurityKDFParams = KDFParams{
	Memory:      256 * 1024,
	Iterations:  4,
	Parallelism: 2,
}

func deriveKey(password []byte, salt []byte, params KDFParams) ([]byte, error) {
	if len(salt) != saltSize {
		return nil, fmt.Errorf("invalid salt length: %d", len(salt))
	}
	if params.Memory == 0 || params.Iterations == 0 || params.Parallelism == 0 {
		return nil, errors.New("invalid kdf parameters")
	}

	key := argon2.IDKey(password, salt, params.Iterations, params.Memory, params.Parallelism, keySize)
	return key, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// SetDefaultKDFParams overrides the package default KDF parameters.
// This is intended for callers (e.g. CLI) that want to enable
// higher-cost KDF profiles (high-security mode).
func SetDefaultKDFParams(p KDFParams) {
	defaultKDFParams = p
}

// SetDefaultExpiryUnix sets the expiry timestamp embedded into newly encrypted
// files. A value of 0 disables expiry.
func SetDefaultExpiryUnix(expiryUnix int64) {
	defaultExpiryUnix = expiryUnix
}
