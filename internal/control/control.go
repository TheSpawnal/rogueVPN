// Package control is the node side of the coordination protocol.
package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"wyrm/internal/ident"
	"wyrm/internal/proto"
)

// ErrUnauthorized means the server does not know this node (never enrolled
// or removed by an administrator).
var ErrUnauthorized = errors.New("control: node not authorized by coordination server")

const maxResponse = 8 << 20

// Client talks to one coordination server.
type Client struct {
	base string
	host string
	hc   *http.Client
}

// New builds a client that only trusts a server presenting the pinned key
// and that authenticates itself with id.
func New(coordURL, pin string, id *ident.Identity) (*Client, error) {
	u, err := url.Parse(coordURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("control: coordination URL must be https://host[:port]")
	}
	digest, err := ident.ParsePin(pin)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{id.Cert},
		// Chain validation is replaced, not removed: the server must prove
		// possession of the pinned key. VerifyConnection also runs on
		// resumed sessions.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || !ident.MatchPin(cs.PeerCertificates[0], digest) {
				return errors.New("control: server key does not match pin")
			}
			return nil
		},
	}
	tr := &http.Transport{
		Proxy:                 nil, // never route control traffic through an ambient proxy
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       tc,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 45 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
	}
	return &Client{
		base: "https://" + u.Host,
		host: u.Hostname(),
		hc:   &http.Client{Transport: tr},
	}, nil
}

// Host returns the server host name, used to locate its STUN service.
func (c *Client) Host() string { return c.host }

func (c *Client) do(ctx context.Context, method, path string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return 0, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return resp.StatusCode, err
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return resp.StatusCode, ErrUnauthorized
	case resp.StatusCode == http.StatusNoContent:
		return resp.StatusCode, nil
	case resp.StatusCode != http.StatusOK:
		var e proto.Error
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return resp.StatusCode, fmt.Errorf("control: server: %s", e.Error)
		}
		return resp.StatusCode, fmt.Errorf("control: server returned %d", resp.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("control: bad response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// Enroll registers this node. A rejected auth key surfaces as ErrUnauthorized.
func (c *Client) Enroll(ctx context.Context, req proto.EnrollRequest) (*proto.EnrollResponse, error) {
	var out proto.EnrollResponse
	if _, err := c.do(ctx, http.MethodPost, proto.PathEnroll, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Update publishes the node's discovery key and endpoints.
func (c *Client) Update(ctx context.Context, req proto.UpdateRequest) error {
	_, err := c.do(ctx, http.MethodPost, proto.PathUpdate, req, nil)
	return err
}

// NetMap long-polls for a network map whose version differs from since. It
// returns nil when the poll timed out without a change.
func (c *Client) NetMap(ctx context.Context, since uint64) (*proto.NetMap, error) {
	var out proto.NetMap
	code, err := c.do(ctx, http.MethodGet, proto.PathNetMap+"?since="+strconv.FormatUint(since, 10), nil, &out)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNoContent {
		return nil, nil
	}
	return &out, nil
}
