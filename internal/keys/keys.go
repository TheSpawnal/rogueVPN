// Package keys defines the Curve25519 key types shared by the transport,
// the NAT-traversal (disco) layer and the control protocol.
package keys

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// Size is the byte length of a Curve25519 key.
const Size = 32

// Public is a Curve25519 public key. It marshals as standard base64.
type Public [Size]byte

// Private is a Curve25519 private key. It deliberately implements no
// marshaler and prints as a redaction marker so it cannot leak through
// fmt, slog or encoding/json by accident. Use Encode to serialize.
type Private [Size]byte

var errKeyLen = errors.New("keys: wrong key length")

// NewPrivate generates a private key from the system CSPRNG.
func NewPrivate() (Private, error) {
	var p Private
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return p, err
	}
	copy(p[:], k.Bytes())
	return p, nil
}

// Public derives the public key.
func (k Private) Public() Public {
	var p Public
	sk, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		// Unreachable: any 32-byte string is a valid X25519 scalar.
		panic("keys: " + err.Error())
	}
	copy(p[:], sk.PublicKey().Bytes())
	return p
}

// String never reveals key material.
func (k Private) String() string { return "(private key)" }

// GoString never reveals key material.
func (k Private) GoString() string { return "(private key)" }

// Encode returns the base64 form for storage in a 0600 state file.
func (k Private) Encode() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Hex returns the hex form required by the WireGuard UAPI.
func (k Private) Hex() string { return hex.EncodeToString(k[:]) }

// IsZero reports whether the key is unset.
func (k Private) IsZero() bool { return k == Private{} }

// ParsePrivate decodes the output of Encode.
func ParsePrivate(s string) (Private, error) {
	var p Private
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return p, err
	}
	if len(b) != Size {
		return p, errKeyLen
	}
	copy(p[:], b)
	return p, nil
}

// String returns the base64 form.
func (p Public) String() string { return base64.StdEncoding.EncodeToString(p[:]) }

// Hex returns the hex form required by the WireGuard UAPI.
func (p Public) Hex() string { return hex.EncodeToString(p[:]) }

// Short returns an abbreviated form for logs and tables.
func (p Public) Short() string { return p.String()[:8] }

// IsZero reports whether the key is unset.
func (p Public) IsZero() bool { return p == Public{} }

// MarshalText implements encoding.TextMarshaler.
func (p Public) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (p *Public) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*p = Public{}
		return nil
	}
	q, err := ParsePublic(string(b))
	if err != nil {
		return err
	}
	*p = q
	return nil
}

// ParsePublic decodes a base64 public key.
func ParsePublic(s string) (Public, error) {
	var p Public
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return p, err
	}
	if len(b) != Size {
		return p, errKeyLen
	}
	copy(p[:], b)
	return p, nil
}

// ParsePublicHex decodes a hex public key (WireGuard UAPI form).
func ParsePublicHex(s string) (Public, error) {
	var p Public
	b, err := hex.DecodeString(s)
	if err != nil {
		return p, err
	}
	if len(b) != Size {
		return p, errKeyLen
	}
	copy(p[:], b)
	return p, nil
}
