// Package coord is the coordination server: the control plane of the mesh.
// It authenticates nodes, assigns mesh addresses and distributes public
// keys and candidate endpoints. It never sees a private key and never
// carries tunnel traffic.
package coord

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"wyrm/internal/fsutil"
	"wyrm/internal/ident"
	"wyrm/internal/keys"
)

const (
	stateFile = "state.json"
	keyFile   = "coord.key"
	// AdminSocket is the admin API socket name inside the data directory.
	AdminSocket = "admin.sock"

	authKeyPrefix = "wyrm-auth-"
	maxNodes      = 10000
	maxAuthKeys   = 1000
)

type nodeRec struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Identity []byte      `json:"identity"` // Ed25519 public key
	WGPub    keys.Public `json:"wg_pub"`
	IP       netip.Addr  `json:"ip"`
	Created  time.Time   `json:"created"`
}

type authKeyRec struct {
	ID       string    `json:"id"`
	Hash     string    `json:"hash"` // hex SHA-256 of the secret; the secret is never stored
	Reusable bool      `json:"reusable"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
	Used     int       `json:"used"`
}

type state struct {
	CIDR     netip.Prefix  `json:"cidr"`
	Nodes    []*nodeRec    `json:"nodes"`
	AuthKeys []*authKeyRec `json:"auth_keys"`
}

func loadState(dir string) (*state, error) {
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil {
		return nil, err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	if !st.CIDR.IsValid() {
		return nil, errors.New("coord: state has no mesh CIDR")
	}
	return &st, nil
}

func (st *state) save(dir string) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, stateFile), b, 0o600)
}

// Init creates the data directory, the server identity and an empty state.
// It is idempotent: existing files are kept. It returns the server pin.
func Init(dir string, cidr netip.Prefix) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	id, err := loadOrCreateIdentity(dir)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(dir, stateFile)); errors.Is(err, os.ErrNotExist) {
		cidr = cidr.Masked()
		if !cidr.Addr().Is4() || cidr.Bits() < 8 || cidr.Bits() > 29 {
			return "", errors.New("coord: mesh CIDR must be IPv4 between /8 and /29")
		}
		if err := (&state{CIDR: cidr}).save(dir); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	return id.Pin(), nil
}

func loadOrCreateIdentity(dir string) (*ident.Identity, error) {
	path := filepath.Join(dir, keyFile)
	b, err := os.ReadFile(path)
	if err == nil {
		seed, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil {
			return nil, errors.New("coord: corrupt identity key file")
		}
		return ident.FromSeed(seed)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	id, err := ident.New()
	if err != nil {
		return nil, err
	}
	enc := base64.StdEncoding.EncodeToString(id.Seed()) + "\n"
	if err := fsutil.WriteFileAtomic(path, []byte(enc), 0o600); err != nil {
		return nil, err
	}
	return id, nil
}

func newAuthKey() (secret string, rec *authKeyRec, err error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", nil, err
	}
	secret = authKeyPrefix + base64.RawURLEncoding.EncodeToString(raw[:])
	h := hashAuthKey(secret)
	return secret, &authKeyRec{ID: h[:12], Hash: h, Created: time.Now().UTC()}, nil
}

func hashAuthKey(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// cleanName reduces an arbitrary string to a DNS label. Names are shown in
// other users' terminals, so nothing outside [a-z0-9-] may survive.
func cleanName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.' || r == ' ':
			b.WriteByte('-')
		}
		if b.Len() >= 63 {
			break
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "node"
	}
	return out
}

// ReadPin returns the pin of an initialized data directory without
// starting the server.
func ReadPin(dir string) (string, error) {
	if _, err := os.Stat(filepath.Join(dir, keyFile)); err != nil {
		return "", errors.New("coord: data directory not initialized; run 'wyrm coord serve' once")
	}
	id, err := loadOrCreateIdentity(dir)
	if err != nil {
		return "", err
	}
	return id.Pin(), nil
}
