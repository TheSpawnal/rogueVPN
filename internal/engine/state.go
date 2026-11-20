// Package engine is the node daemon core. It wires the control client, the
// tunnel transport, NAT traversal and the flow inspector together and
// exposes their combined state to the local API.
package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"wyrm/internal/control"
	"wyrm/internal/flow"
	"wyrm/internal/fsutil"
	"wyrm/internal/ident"
	"wyrm/internal/keys"
	"wyrm/internal/proto"
)

const (
	nodeFile   = "node.json"
	policyFile = "policy.json"
)

// State is the node's persistent identity and enrollment.
type State struct {
	CoordURL string
	CoordPin string
	NodeID   string
	Name     string
	IP       netip.Addr
	CIDR     netip.Prefix

	id    *ident.Identity
	wgKey keys.Private
}

type stateFile struct {
	CoordURL string       `json:"coord_url"`
	CoordPin string       `json:"coord_pin"`
	NodeID   string       `json:"node_id"`
	Name     string       `json:"name"`
	IP       netip.Addr   `json:"ip"`
	CIDR     netip.Prefix `json:"cidr"`
	Identity string       `json:"identity_seed"`
	WGKey    string       `json:"wg_private_key"`
}

// EnrollParams are needed once, on a node's first start.
type EnrollParams struct {
	CoordURL string
	CoordPin string
	AuthKey  string
	Name     string
}

// LoadState reads an existing enrollment. It returns os.ErrNotExist if the
// node has never enrolled.
func LoadState(dir string) (*State, error) {
	b, err := os.ReadFile(filepath.Join(dir, nodeFile))
	if err != nil {
		return nil, err
	}
	var f stateFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	seed, err := base64.StdEncoding.DecodeString(f.Identity)
	if err != nil {
		return nil, errors.New("state: corrupt identity")
	}
	id, err := ident.FromSeed(seed)
	if err != nil {
		return nil, err
	}
	wk, err := keys.ParsePrivate(f.WGKey)
	if err != nil {
		return nil, errors.New("state: corrupt tunnel key")
	}
	if !f.IP.IsValid() || !f.CIDR.Contains(f.IP) {
		return nil, errors.New("state: invalid mesh address")
	}
	return &State{
		CoordURL: f.CoordURL, CoordPin: f.CoordPin, NodeID: f.NodeID, Name: f.Name,
		IP: f.IP, CIDR: f.CIDR, id: id, wgKey: wk,
	}, nil
}

// Enroll generates fresh keys, registers them with the coordination server
// and persists the result. Private keys never leave this host.
func Enroll(ctx context.Context, dir string, p EnrollParams) (*State, error) {
	if p.CoordURL == "" || p.CoordPin == "" || p.AuthKey == "" {
		return nil, errors.New("first start needs --coord, --pin and an auth key")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	id, err := ident.New()
	if err != nil {
		return nil, err
	}
	wk, err := keys.NewPrivate()
	if err != nil {
		return nil, err
	}
	ctl, err := control.New(p.CoordURL, p.CoordPin, id)
	if err != nil {
		return nil, err
	}
	resp, err := ctl.Enroll(ctx, proto.EnrollRequest{AuthKey: p.AuthKey, Name: p.Name, WGPub: wk.Public()})
	if err != nil {
		if errors.Is(err, control.ErrUnauthorized) {
			return nil, errors.New("enrollment refused: auth key invalid, expired or already used")
		}
		return nil, err
	}
	if !resp.IP.Is4() || !resp.CIDR.Contains(resp.IP) {
		return nil, errors.New("enrollment: server returned an invalid mesh address")
	}
	st := &State{
		CoordURL: p.CoordURL, CoordPin: p.CoordPin, NodeID: resp.NodeID, Name: resp.Name,
		IP: resp.IP, CIDR: resp.CIDR.Masked(), id: id, wgKey: wk,
	}
	b, err := json.MarshalIndent(stateFile{
		CoordURL: st.CoordURL, CoordPin: st.CoordPin, NodeID: st.NodeID, Name: st.Name,
		IP: st.IP, CIDR: st.CIDR,
		Identity: base64.StdEncoding.EncodeToString(id.Seed()),
		WGKey:    wk.Encode(),
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, nodeFile), b, 0o600); err != nil {
		return nil, err
	}
	return st, nil
}

func loadPolicy(dir string, t *flow.Table) error {
	b, err := os.ReadFile(filepath.Join(dir, policyFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var p flow.Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	return t.LoadPolicy(p)
}

func savePolicy(dir string, p flow.Policy) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, policyFile), b, 0o600)
}
