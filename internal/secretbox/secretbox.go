// Package secretbox encrypts secret values with local AES-256-GCM behind a
// provider-neutral envelope {provider, key_id}.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// ProviderLocal is the envelope provider name of the local AES-256-GCM provider.
const ProviderLocal = "local-aes-256-gcm"

var (
	// ErrUnavailable reports a missing or unusable data key.
	ErrUnavailable = errors.New("cryptography provider unavailable")
	// ErrDecrypt reports an envelope that does not decrypt for its associated data.
	ErrDecrypt = errors.New("secret version does not decrypt")
)

// AAD is the associated data bound into every encryption.
type AAD struct {
	TeamID   int64
	SecretID int64
	Version  int
}

func (a AAD) bytes() []byte {
	b := make([]byte, 0, len(ProviderLocal)+24)
	b = append(b, ProviderLocal...)
	b = binary.BigEndian.AppendUint64(b, uint64(a.TeamID))
	b = binary.BigEndian.AppendUint64(b, uint64(a.SecretID))
	return binary.BigEndian.AppendUint64(b, uint64(a.Version))
}

// Envelope is one stored encrypted version. Ciphertext includes the tag.
type Envelope struct {
	Provider   string
	KeyID      int64
	Nonce      []byte
	Ciphertext []byte
}

// Provider encrypts and decrypts secret values.
type Provider interface {
	Encrypt(aad AAD, plaintext []byte) (Envelope, error)
	Decrypt(aad AAD, env Envelope) ([]byte, error)
}

// Key is one configured data key.
type Key struct {
	ID       int64
	Material []byte
}

// Local is the AES-256-GCM provider.
type Local struct {
	active int64
	aeads  map[int64]cipher.AEAD
}

// NewLocal builds the provider from the configured keys; activeID encrypts.
func NewLocal(keys []Key, activeID int64) (*Local, error) {
	l := &Local{active: activeID, aeads: map[int64]cipher.AEAD{}}
	for _, k := range keys {
		if k.ID < 1 || len(k.Material) != 32 {
			return nil, fmt.Errorf("data key %d: want a positive id and 32 bytes", k.ID)
		}
		if _, dup := l.aeads[k.ID]; dup {
			return nil, fmt.Errorf("data key %d configured twice", k.ID)
		}
		block, err := aes.NewCipher(k.Material)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		l.aeads[k.ID] = aead
	}
	if _, ok := l.aeads[activeID]; !ok {
		return nil, fmt.Errorf("active data key %d is not configured", activeID)
	}
	return l, nil
}

// Encrypt implements Provider.
func (l *Local) Encrypt(aad AAD, plaintext []byte) (Envelope, error) {
	aead := l.aeads[l.active]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, ErrUnavailable
	}
	return Envelope{Provider: ProviderLocal, KeyID: l.active, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plaintext, aad.bytes())}, nil
}

// Decrypt implements Provider.
func (l *Local) Decrypt(aad AAD, env Envelope) ([]byte, error) {
	if env.Provider != ProviderLocal {
		return nil, ErrDecrypt
	}
	aead, ok := l.aeads[env.KeyID]
	if !ok {
		return nil, ErrUnavailable
	}
	if len(env.Nonce) != aead.NonceSize() {
		return nil, ErrDecrypt
	}
	out, err := aead.Open(nil, env.Nonce, env.Ciphertext, aad.bytes())
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}
