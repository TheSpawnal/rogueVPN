package coord

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wyrm/internal/control"
	"wyrm/internal/ident"
	"wyrm/internal/keys"
	"wyrm/internal/proto"
	"wyrm/internal/stun"
)

type lab struct {
	t   *testing.T
	dir string
	url string
	pin string
	srv *Server
}

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func startLab(t *testing.T) *lab {
	// Unix socket paths are limited to about 100 bytes; t.TempDir can exceed that.
	dir, err := os.MkdirTemp("/tmp", "wc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	pin, err := Init(dir, netip.MustParsePrefix("10.88.0.0/29"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Open(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	addr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, addr, "127.0.0.1:0") }()
	t.Cleanup(func() { cancel(); <-done })
	l := &lab{t: t, dir: dir, url: "https://" + addr, pin: pin, srv: srv}
	for i := 0; ; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			if _, err := os.Stat(filepath.Join(dir, AdminSocket)); err == nil {
				break
			}
		}
		if i > 200 {
			t.Fatal("server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return l
}

func (l *lab) admin(method, path string, in any, out any) error {
	hc, base := AdminClient(l.dir)
	var body io.Reader
	if in != nil {
		body = strings.NewReader(in.(string))
	}
	req, _ := http.NewRequest(method, base+path, body)
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return errors.New(string(b))
	}
	if s, ok := out.(*string); ok {
		*s = string(b)
	}
	return nil
}

func (l *lab) authKey(reusable bool) string {
	l.t.Helper()
	var raw string
	body := `{"reusable":false,"ttl_seconds":60}`
	if reusable {
		body = `{"reusable":true,"ttl_seconds":60}`
	}
	if err := l.admin("POST", "/authkeys", body, &raw); err != nil {
		l.t.Fatal(err)
	}
	i := strings.Index(raw, authKeyPrefix)
	return raw[i : i+strings.IndexByte(raw[i:], '"')]
}

type node struct {
	id  *ident.Identity
	wg  keys.Private
	ctl *control.Client
}

func (l *lab) node() *node {
	l.t.Helper()
	id, _ := ident.New()
	wg, _ := keys.NewPrivate()
	ctl, err := control.New(l.url, l.pin, id)
	if err != nil {
		l.t.Fatal(err)
	}
	return &node{id, wg, ctl}
}

func TestEnrollAndNetMap(t *testing.T) {
	l := startLab(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	a, b := l.node(), l.node()
	key := l.authKey(false)
	ra, err := a.ctl.Enroll(ctx, proto.EnrollRequest{AuthKey: key, Name: "Alpha \x1b[31m!!", WGPub: a.wg.Public()})
	if err != nil {
		t.Fatal(err)
	}
	if ra.IP != netip.MustParseAddr("10.88.0.1") || ra.Name != "alpha-31m" {
		t.Fatalf("enroll: %+v", ra)
	}
	// A single-use key is spent.
	if _, err := b.ctl.Enroll(ctx, proto.EnrollRequest{AuthKey: key, Name: "beta", WGPub: b.wg.Public()}); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("spent key accepted: %v", err)
	}
	// An unenrolled identity gets nothing.
	if _, err := b.ctl.NetMap(ctx, 0); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("unenrolled node read the map: %v", err)
	}
	if err := b.ctl.Update(ctx, proto.UpdateRequest{}); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("unenrolled node updated: %v", err)
	}
	multi := l.authKey(true)
	// A node cannot claim another node's tunnel key.
	if _, err := b.ctl.Enroll(ctx, proto.EnrollRequest{AuthKey: multi, Name: "beta", WGPub: a.wg.Public()}); err == nil {
		t.Fatal("duplicate tunnel key accepted")
	}
	rb, err := b.ctl.Enroll(ctx, proto.EnrollRequest{AuthKey: multi, Name: "alpha-31m", WGPub: b.wg.Public()})
	if err != nil {
		t.Fatal(err)
	}
	if rb.IP != netip.MustParseAddr("10.88.0.2") || rb.Name != "alpha-31m-2" {
		t.Fatalf("second enroll: %+v", rb)
	}

	da, _ := keys.NewPrivate()
	epA := netip.MustParseAddrPort("192.0.2.10:51820")
	if err := a.ctl.Update(ctx, proto.UpdateRequest{DiscoPub: da.Public(), Endpoints: []netip.AddrPort{epA, epA}}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:1"), netip.MustParseAddrPort("0.0.0.0:1"),
		netip.MustParseAddrPort("192.0.2.1:0"), netip.MustParseAddrPort("224.0.0.1:5"),
	} {
		if err := a.ctl.Update(ctx, proto.UpdateRequest{DiscoPub: da.Public(), Endpoints: []netip.AddrPort{bad}}); err == nil {
			t.Fatalf("endpoint %v accepted", bad)
		}
	}
	nm, err := b.ctl.NetMap(ctx, 0)
	if err != nil || nm == nil {
		t.Fatal(err)
	}
	if len(nm.Peers) != 1 || nm.Peers[0].WGPub != a.wg.Public() || nm.Peers[0].DiscoPub != da.Public() ||
		len(nm.Peers[0].Endpoints) != 1 || nm.Peers[0].Endpoints[0] != epA || !nm.Peers[0].Online || nm.Self.IP != rb.IP {
		t.Fatalf("netmap: %+v", nm)
	}

	// Long-poll wakes on change.
	got := make(chan *proto.NetMap, 1)
	go func() {
		m, _ := b.ctl.NetMap(ctx, nm.Version)
		got <- m
	}()
	select {
	case <-got:
		t.Fatal("long-poll returned without a change")
	case <-time.After(300 * time.Millisecond):
	}
	epA2 := netip.MustParseAddrPort("192.0.2.11:51820")
	if err := a.ctl.Update(ctx, proto.UpdateRequest{DiscoPub: da.Public(), Endpoints: []netip.AddrPort{epA2}}); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-got:
		if m == nil || m.Version == nm.Version || m.Peers[0].Endpoints[0] != epA2 {
			t.Fatalf("stale map after change: %+v", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long-poll did not wake")
	}

	// Removal cuts the node off at once.
	if err := l.admin("DELETE", "/nodes/"+ra.NodeID, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ctl.NetMap(ctx, 0); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("removed node still served: %v", err)
	}
	nm, _ = b.ctl.NetMap(ctx, 0)
	if len(nm.Peers) != 0 {
		t.Fatalf("removed node still in map")
	}

	// State survives a restart; secrets are not world-readable.
	for _, f := range []string{stateFile, keyFile} {
		fi, err := os.Stat(filepath.Join(l.dir, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, fi.Mode(), err)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(l.dir, stateFile))
	if strings.Contains(string(raw), key) || strings.Contains(string(raw), multi) {
		t.Fatal("auth key secret stored in clear")
	}
	re, err := Open(l.dir, l.srv.log)
	if err != nil || len(re.st.Nodes) != 1 || re.st.Nodes[0].IP != rb.IP || re.Pin() != l.pin {
		t.Fatalf("reload: %v", err)
	}
}

func TestPinAndIdentityEnforced(t *testing.T) {
	l := startLab(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n := l.node()

	// A client pinned to a different key must refuse the server.
	other, _ := ident.New()
	wrong, err := control.New(l.url, other.Pin(), n.id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Enroll(ctx, proto.EnrollRequest{AuthKey: l.authKey(false), WGPub: n.wg.Public()}); err == nil ||
		!strings.Contains(err.Error(), "does not match pin") {
		t.Fatalf("wrong pin accepted: %v", err)
	}
	for _, bad := range []string{"http://x:1", "https://", "https://user:pw@x:1"} {
		if _, err := control.New(bad, l.pin, n.id); err == nil {
			t.Errorf("url %q accepted", bad)
		}
	}
	if _, err := control.New(l.url, "sha256:AAAA", n.id); err == nil {
		t.Error("malformed pin accepted")
	}

	// Enrollment brute force is throttled per client address.
	var last error
	for i := 0; i < enrollFailMax+2; i++ {
		_, last = n.ctl.Enroll(ctx, proto.EnrollRequest{AuthKey: "wyrm-auth-guess", WGPub: n.wg.Public()})
	}
	if last == nil || !strings.Contains(last.Error(), "too many") {
		t.Fatalf("no throttling: %v", last)
	}

	// Address exhaustion (/29 has six hosts) is reported, not wrapped around.
	l.srv.mu.Lock()
	l.srv.fails = map[netip.Addr]*failRec{}
	l.srv.mu.Unlock()
	multi := l.authKey(true)
	for i := 0; i < 7; i++ {
		x := l.node()
		_, err := x.ctl.Enroll(ctx, proto.EnrollRequest{AuthKey: multi, WGPub: x.wg.Public()})
		if (i < 6) != (err == nil) {
			t.Fatalf("node %d: %v", i, err)
		}
	}
}

func TestLimits(t *testing.T) {
	l := startLab(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	n := l.node()
	if _, err := n.ctl.Enroll(ctx, proto.EnrollRequest{AuthKey: l.authKey(false), WGPub: n.wg.Public()}); err != nil {
		t.Fatal(err)
	}
	// Endpoint updates: a burst is fine, a flood is throttled.
	d, _ := keys.NewPrivate()
	limited := 0
	for i := 0; i < 30; i++ {
		ep := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(1000+i))
		if err := n.ctl.Update(ctx, proto.UpdateRequest{DiscoPub: d.Public(), Endpoints: []netip.AddrPort{ep}}); err != nil {
			if !strings.Contains(err.Error(), "too many updates") {
				t.Fatal(err)
			}
			limited++
		}
	}
	if limited < 15 || limited > 22 {
		t.Fatalf("%d of 30 rapid updates throttled, want about 22", limited)
	}

	// Connections per client address are capped.
	addr := strings.TrimPrefix(l.url, "https://")
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < maxConnsPerIP+8; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	time.Sleep(300 * time.Millisecond)
	open := 0
	for _, c := range conns {
		c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "reset") {
			open++ // read timed out: the server is still holding this one
		}
	}
	if open > maxConnsPerIP || open < maxConnsPerIP-2 {
		t.Fatalf("%d connections held open, want %d", open, maxConnsPerIP)
	}
	// Releasing them frees the slots again.
	for _, c := range conns {
		c.Close()
	}
	conns = nil
	time.Sleep(200 * time.Millisecond)
	if _, err := n.ctl.NetMap(ctx, 0); err != nil {
		t.Fatalf("server unusable after connection flood: %v", err)
	}
}

func TestSTUN(t *testing.T) {
	l := startLab(t)
	l.srv.mu.Lock()
	port := l.srv.stunPort
	l.srv.mu.Unlock()
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tx, req, _ := stun.NewRequest()
	c.Write([]byte("garbage that must be ignored"))
	c.Write(req)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	rtx, addr, err := stun.ParseResponse(buf[:n])
	if err != nil || rtx != tx || addr.String() != c.LocalAddr().String() {
		t.Fatalf("stun: %v %v want %v", addr, err, c.LocalAddr())
	}
}

func TestCleanName(t *testing.T) {
	for in, want := range map[string]string{
		"":                      "node",
		"Lap Top_01.lan":        "lap-top-01-lan",
		"\x1b]0;evil\x07":       "0evil",
		"---":                   "node",
		strings.Repeat("a", 90): strings.Repeat("a", 63),
		"naïve":                 "nave",
	} {
		if got := cleanName(in); got != want {
			t.Errorf("cleanName(%q) = %q, want %q", in, got, want)
		}
	}
}

// The control channel must negotiate TLS 1.3 with the hybrid post-quantum
// key exchange, so that recorded control traffic stays private even against
// a future quantum adversary.
func TestControlChannelIsHybridPQ(t *testing.T) {
	l := startLab(t)
	id, _ := ident.New()
	c, err := tls.Dial("tcp", strings.TrimPrefix(l.url, "https://"), &tls.Config{
		Certificates:       []tls.Certificate{id.Cert},
		InsecureSkipVerify: true, // test only: inspecting handshake parameters
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cs := c.ConnectionState()
	if cs.Version != tls.VersionTLS13 || cs.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("negotiated version %#x, key exchange %v", cs.Version, cs.CurveID)
	}
	// TLS 1.2 clients are refused outright.
	if _, err := tls.Dial("tcp", strings.TrimPrefix(l.url, "https://"), &tls.Config{
		Certificates: []tls.Certificate{id.Cert}, InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12,
	}); err == nil {
		t.Fatal("TLS 1.2 accepted")
	}
}
