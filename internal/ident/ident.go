// Package ident implements the control-plane identities. Every party (the
// coordination server and each node) owns an Ed25519 key wrapped in a
// self-signed certificate. Trust never comes from a certificate chain:
// nodes pin the server's public key, and the server recognises nodes by the
// public key they prove possession of in the TLS 1.3 handshake.
package ident

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"time"
)

// Identity is an Ed25519 key and a certificate carrying its public half.
type Identity struct {
	priv ed25519.PrivateKey
	Cert tls.Certificate
	leaf *x509.Certificate
}

// New generates a fresh identity.
func New() (*Identity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return fromKey(priv)
}

// FromSeed rebuilds an identity from the output of Seed.
func FromSeed(seed []byte) (*Identity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("ident: bad seed length")
	}
	return fromKey(ed25519.NewKeyFromSeed(seed))
}

func fromKey(priv ed25519.PrivateKey) (*Identity, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "wyrm"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(20 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Identity{
		priv: priv,
		Cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf},
		leaf: leaf,
	}, nil
}

// Seed returns the 32-byte secret from which the identity is rebuilt.
func (i *Identity) Seed() []byte { return i.priv.Seed() }

// Public returns the Ed25519 public key.
func (i *Identity) Public() ed25519.PublicKey { return i.priv.Public().(ed25519.PublicKey) }

// Pin returns the pin string peers use to recognise this identity.
func (i *Identity) Pin() string { return Pin(i.leaf) }

// Pin computes "sha256:<base64>" over the certificate's SubjectPublicKeyInfo.
func Pin(c *x509.Certificate) string {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return "sha256:" + base64.StdEncoding.EncodeToString(h[:])
}

// ParsePin validates a pin string and returns the raw digest.
func ParsePin(s string) ([]byte, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "sha256:")
	if !ok {
		return nil, errors.New("ident: pin must start with sha256:")
	}
	b, err := base64.StdEncoding.DecodeString(rest)
	if err != nil || len(b) != sha256.Size {
		return nil, errors.New("ident: malformed pin")
	}
	return b, nil
}

// MatchPin reports, in constant time, whether c carries the pinned key.
func MatchPin(c *x509.Certificate, digest []byte) bool {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return subtle.ConstantTimeCompare(h[:], digest) == 1
}

// NodeID derives the short display handle of a node identity. It is not a
// security boundary: the server keys its tables by the full public key.
func NodeID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "n" + hex.EncodeToString(h[:8])
}
