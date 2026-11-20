package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"wyrm/internal/flow"
)

// Client talks to a node daemon over its local socket.
type Client struct {
	hc *http.Client
}

// NewClient returns a client for the daemon listening on sock.
func NewClient(sock string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "unix", sock)
		},
		MaxIdleConns: 2,
	}
	return &Client{hc: &http.Client{Transport: tr}}
}

const base = "http://wyrmd"

func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("daemon not reachable: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e Error
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", Printable(e.Error))
		}
		return fmt.Errorf("daemon returned %d", resp.StatusCode)
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Status fetches the node status.
func (c *Client) Status(ctx context.Context) (s Status, err error) {
	return s, c.call(ctx, http.MethodGet, PathStatus, nil, &s)
}

// Peers lists remote nodes.
func (c *Client) Peers(ctx context.Context) (p []Peer, err error) {
	return p, c.call(ctx, http.MethodGet, PathPeers, nil, &p)
}

// Flows lists active flows.
func (c *Client) Flows(ctx context.Context) (f []flow.FlowInfo, err error) {
	return f, c.call(ctx, http.MethodGet, PathFlows, nil, &f)
}

// Packets returns recent packets with a sequence number above after.
func (c *Client) Packets(ctx context.Context, after uint64) (p []flow.PacketInfo, err error) {
	return p, c.call(ctx, http.MethodGet, PathPackets+"?after="+strconv.FormatUint(after, 10), nil, &p)
}

// Rules lists filter rules.
func (c *Client) Rules(ctx context.Context) (r []flow.Rule, err error) {
	return r, c.call(ctx, http.MethodGet, PathRules, nil, &r)
}

// AddRule appends a filter rule.
func (c *Client) AddRule(ctx context.Context, r flow.Rule) (out flow.Rule, err error) {
	return out, c.call(ctx, http.MethodPost, PathRules, r, &out)
}

// DelRule removes a filter rule.
func (c *Client) DelRule(ctx context.Context, id uint32) error {
	return c.call(ctx, http.MethodDelete, PathRules+"/"+strconv.FormatUint(uint64(id), 10), nil, nil)
}

// SetShields switches shields mode.
func (c *Client) SetShields(ctx context.Context, on bool) error {
	return c.call(ctx, http.MethodPut, PathShields, ShieldsRequest{On: on}, nil)
}

// Snapshot fetches status, peers, flows and rules together.
func (c *Client) Snapshot(ctx context.Context) (s Snapshot, err error) {
	return s, c.call(ctx, http.MethodGet, PathSnapshot, nil, &s)
}

// Capture streams a pcap capture of tunnel traffic into w until ctx ends.
func (c *Client) Capture(ctx context.Context, snaplen int, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+PathCapture+"?snaplen="+strconv.Itoa(snaplen), nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("daemon not reachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var e Error
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", Printable(e.Error))
		}
		return fmt.Errorf("daemon returned %d", resp.StatusCode)
	}
	_, err = io.Copy(w, resp.Body)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// Printable makes a string safe to write to a terminal. Names and messages
// can originate on other machines, so anything outside printable ASCII is
// replaced; escape sequences cannot survive.
func Printable(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	return string(b)
}
