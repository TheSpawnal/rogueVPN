package coord

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/netutil"

	"wyrm/internal/ident"
	"wyrm/internal/keys"
	"wyrm/internal/proto"
	"wyrm/internal/stun"
)

const (
	pollTimeout    = 25 * time.Second
	onlineWindow   = 60 * time.Second
	maxConns       = 4096
	maxConnsPerIP  = 64
	updateBurst    = 8.0 // endpoint updates a node may send at once
	updateRate     = 2.0 // and per second after that
	enrollFailMax  = 10
	enrollFailSpan = time.Minute
)

type liveNode struct {
	discoPub  keys.Public
	endpoints []netip.AddrPort
	lastSeen  time.Time
	online    bool
	tokens    float64 // update rate limit
	refilled  time.Time
}

// allowUpdate is a token bucket. Every accepted update wakes all other
// nodes, so one node must not be able to do that without bound.
func (l *liveNode) allowUpdate(now time.Time) bool {
	if l.refilled.IsZero() {
		l.tokens = updateBurst
	} else {
		l.tokens = min(updateBurst, l.tokens+now.Sub(l.refilled).Seconds()*updateRate)
	}
	l.refilled = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

type failRec struct {
	n     int
	since time.Time
}

// Server is a running coordination server.
type Server struct {
	log *slog.Logger
	dir string
	id  *ident.Identity

	mu       sync.Mutex
	st       *state
	byIdent  map[string]*nodeRec
	byID     map[string]*nodeRec
	live     map[string]*liveNode
	version  uint64
	notify   chan struct{}
	fails    map[netip.Addr]*failRec
	stunPort uint16
}

// Open loads a data directory prepared by Init.
func Open(dir string, log *slog.Logger) (*Server, error) {
	id, err := loadOrCreateIdentity(dir)
	if err != nil {
		return nil, err
	}
	st, err := loadState(dir)
	if err != nil {
		return nil, err
	}
	s := &Server{
		log: log, dir: dir, id: id, st: st,
		byIdent: make(map[string]*nodeRec),
		byID:    make(map[string]*nodeRec),
		live:    make(map[string]*liveNode),
		fails:   make(map[netip.Addr]*failRec),
		notify:  make(chan struct{}),
		// Versions only need to differ across changes and restarts.
		version: uint64(time.Now().UnixMicro()),
	}
	for _, n := range st.Nodes {
		s.byIdent[string(n.Identity)] = n
		s.byID[n.ID] = n
	}
	return s, nil
}

// Pin returns the key pin nodes must be configured with.
func (s *Server) Pin() string { return s.id.Pin() }

// bumpLocked publishes a new map version and wakes all long-polls.
func (s *Server) bumpLocked() {
	s.version++
	close(s.notify)
	s.notify = make(chan struct{})
}

// Serve runs the control API, the STUN responder and the admin socket until
// ctx is cancelled.
func (s *Server) Serve(ctx context.Context, listen, stunListen string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer ln.Close()

	uaddr, err := net.ResolveUDPAddr("udp", stunListen)
	if err != nil {
		return err
	}
	uc, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return err
	}
	defer uc.Close()
	s.mu.Lock()
	s.stunPort = uint16(uc.LocalAddr().(*net.UDPAddr).Port)
	s.mu.Unlock()

	sock := filepath.Join(s.dir, AdminSocket)
	os.Remove(sock)
	aln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	defer aln.Close()
	defer os.Remove(sock)
	if err := os.Chmod(sock, 0o600); err != nil {
		return err
	}

	tc := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{s.id.Cert},
		// Any self-signed client certificate completes the handshake; the
		// handshake proves possession of its key, and handlers then look
		// that key up in the node table.
		ClientAuth: tls.RequireAnyClientCert,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+proto.PathEnroll, s.handleEnroll)
	mux.HandleFunc("POST "+proto.PathUpdate, s.handleUpdate)
	mux.HandleFunc("GET "+proto.PathNetMap, s.handleNetMap)
	srv := &http.Server{
		Handler:           mux,
		TLSConfig:         tc,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      pollTimeout + 20*time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
		// HTTP/1.1 only: a smaller parser surface than HTTP/2.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	admin := &http.Server{
		Handler:           s.adminMux(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	errc := make(chan error, 3)
	limited := &ipLimitListener{Listener: netutil.LimitListener(ln, maxConns), max: maxConnsPerIP, n: make(map[netip.Addr]int)}
	go func() { errc <- srv.ServeTLS(limited, "", "") }()
	go func() { errc <- admin.Serve(aln) }()
	go func() { errc <- s.serveSTUN(uc) }()
	go s.janitor(ctx)

	s.log.Info("coordination server up", "listen", ln.Addr().String(),
		"stun", uc.LocalAddr().String(), "pin", s.Pin())

	select {
	case <-ctx.Done():
		err = nil
	case err = <-errc:
	}
	// Close immediately: long-polls would otherwise hold a graceful shutdown.
	srv.Close()
	admin.Close()
	return err
}

func (s *Server) serveSTUN(uc *net.UDPConn) error {
	buf := make([]byte, 1500)
	for {
		n, from, err := uc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		tx, ok := stun.ParseRequest(buf[:n])
		if !ok {
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		uc.WriteToUDPAddrPort(stun.Response(tx, from), from)
	}
}

// janitor flips nodes offline when their long-poll stops.
func (s *Server) janitor(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			changed := false
			for _, l := range s.live {
				on := now.Sub(l.lastSeen) < onlineWindow
				if on != l.online {
					l.online = on
					changed = true
				}
			}
			for ip, f := range s.fails {
				if now.Sub(f.since) > enrollFailSpan {
					delete(s.fails, ip)
				}
			}
			if changed {
				s.bumpLocked()
			}
			s.mu.Unlock()
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, proto.Error{Error: msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, proto.MaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return false
	}
	if _, err := dec.Token(); err != io.EOF {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return false
	}
	return true
}

// clientKey returns the Ed25519 key the TLS client proved possession of.
func clientKey(r *http.Request) (ed25519.PublicKey, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, false
	}
	pub, ok := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	return pub, ok && len(pub) == ed25519.PublicKeySize
}

// ipLimitListener caps concurrent connections per client address, so one
// host cannot occupy every connection slot with idle TLS sessions.
type ipLimitListener struct {
	net.Listener
	max int
	mu  sync.Mutex
	n   map[netip.Addr]int
}

type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

func (l *ipLimitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		key := addrKey(c.RemoteAddr().String())
		l.mu.Lock()
		if l.n[key] >= l.max {
			l.mu.Unlock()
			c.Close()
			continue
		}
		l.n[key]++
		l.mu.Unlock()
		return &countedConn{Conn: c, release: func() {
			l.mu.Lock()
			if l.n[key] <= 1 {
				delete(l.n, key)
			} else {
				l.n[key]--
			}
			l.mu.Unlock()
		}}, nil
	}
}

// remoteKey is the rate-limiting key of a client: its IPv4 address or its
// IPv6 /64.
func remoteKey(r *http.Request) netip.Addr { return addrKey(r.RemoteAddr) }

func addrKey(hostport string) netip.Addr {
	ap, err := netip.ParseAddrPort(hostport)
	if err != nil {
		return netip.Addr{}
	}
	a := ap.Addr().Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	pub, ok := clientKey(r)
	if !ok {
		writeErr(w, http.StatusForbidden, "an Ed25519 client identity is required")
		return
	}
	rk := remoteKey(r)
	s.mu.Lock()
	if f := s.fails[rk]; f != nil && f.n >= enrollFailMax && time.Since(f.since) < enrollFailSpan {
		s.mu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "too many failed enrollments")
		return
	}
	s.mu.Unlock()

	var req proto.EnrollRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.WGPub.IsZero() {
		writeErr(w, http.StatusBadRequest, "missing tunnel key")
		return
	}
	hash := hashAuthKey(req.AuthKey)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()

	var ak *authKeyRec
	for _, k := range s.st.AuthKeys {
		if k.Hash == hash {
			ak = k
			break
		}
	}
	if ak == nil || now.After(ak.Expires) || (!ak.Reusable && ak.Used > 0) {
		f := s.fails[rk]
		if f == nil || now.Sub(f.since) > enrollFailSpan {
			f = &failRec{since: now}
			if len(s.fails) < 100000 {
				s.fails[rk] = f
			}
		}
		f.n++
		s.log.Warn("enrollment rejected", "remote", r.RemoteAddr)
		writeErr(w, http.StatusForbidden, "auth key invalid, expired or already used")
		return
	}
	for _, n := range s.st.Nodes {
		if n.WGPub == req.WGPub && !bytes.Equal(n.Identity, pub) {
			writeErr(w, http.StatusConflict, "tunnel key already registered to another node")
			return
		}
	}

	n := s.byIdent[string(pub)]
	if n == nil {
		id := ident.NodeID(pub)
		if s.byID[id] != nil || len(s.st.Nodes) >= maxNodes {
			writeErr(w, http.StatusConflict, "cannot register node")
			return
		}
		ip, ok := s.allocIPLocked()
		if !ok {
			writeErr(w, http.StatusConflict, "mesh address space exhausted")
			return
		}
		n = &nodeRec{ID: id, Identity: append([]byte(nil), pub...), IP: ip, Created: now}
		n.Name = s.uniqueNameLocked(cleanName(req.Name), n)
		s.st.Nodes = append(s.st.Nodes, n)
		s.byIdent[string(pub)] = n
		s.byID[id] = n
	} else if req.Name != "" {
		n.Name = s.uniqueNameLocked(cleanName(req.Name), n)
	}
	n.WGPub = req.WGPub
	ak.Used++
	if err := s.st.save(s.dir); err != nil {
		s.log.Error("state save failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "state save failed")
		return
	}
	s.bumpLocked()
	s.log.Info("node enrolled", "id", n.ID, "name", n.Name, "ip", n.IP.String())
	writeJSON(w, http.StatusOK, proto.EnrollResponse{NodeID: n.ID, Name: n.Name, IP: n.IP, CIDR: s.st.CIDR})
}

func (s *Server) uniqueNameLocked(name string, self *nodeRec) string {
	taken := func(c string) bool {
		for _, n := range s.st.Nodes {
			if n != self && n.Name == c {
				return true
			}
		}
		return false
	}
	if !taken(name) {
		return name
	}
	for i := 2; ; i++ {
		suffix := "-" + strconv.Itoa(i)
		c := name
		if len(c)+len(suffix) > proto.MaxNameLen {
			c = c[:proto.MaxNameLen-len(suffix)]
		}
		if c += suffix; !taken(c) {
			return c
		}
	}
}

// allocIPLocked returns the lowest free host address of the mesh CIDR.
func (s *Server) allocIPLocked() (netip.Addr, bool) {
	used := make(map[netip.Addr]bool, len(s.st.Nodes))
	for _, n := range s.st.Nodes {
		used[n.IP] = true
	}
	hosts := 1<<(32-s.st.CIDR.Bits()) - 2
	ip := s.st.CIDR.Addr()
	for i := 0; i < hosts; i++ {
		ip = ip.Next()
		if !used[ip] {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// authed resolves the TLS client to an enrolled node and marks it seen.
func (s *Server) authed(w http.ResponseWriter, r *http.Request) *nodeRec {
	pub, ok := clientKey(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unknown node")
		return nil
	}
	s.mu.Lock()
	n := s.byIdent[string(pub)]
	if n != nil {
		s.touchLocked(n.ID)
	}
	s.mu.Unlock()
	if n == nil {
		writeErr(w, http.StatusUnauthorized, "unknown node")
	}
	return n
}

func (s *Server) touchLocked(id string) {
	l := s.live[id]
	if l == nil {
		l = &liveNode{}
		s.live[id] = l
	}
	l.lastSeen = time.Now()
	if !l.online {
		l.online = true
		s.bumpLocked()
	}
}

func validEndpoint(ap netip.AddrPort) bool {
	a := ap.Addr()
	return ap.IsValid() && ap.Port() != 0 && !a.IsUnspecified() && !a.IsMulticast() &&
		!a.IsLoopback() && !a.IsLinkLocalUnicast() && a.Zone() == ""
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	n := s.authed(w, r)
	if n == nil {
		return
	}
	var req proto.UpdateRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.DiscoPub.IsZero() || len(req.Endpoints) > proto.MaxEndpoints {
		writeErr(w, http.StatusBadRequest, "invalid update")
		return
	}
	eps := make([]netip.AddrPort, 0, len(req.Endpoints))
	for _, ep := range req.Endpoints {
		ep = netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port())
		if !validEndpoint(ep) {
			writeErr(w, http.StatusBadRequest, "invalid endpoint")
			return
		}
		if !slices.Contains(eps, ep) {
			eps = append(eps, ep)
		}
	}
	s.mu.Lock()
	limited := false
	// The node may have been removed between authentication and here.
	if s.byID[n.ID] == n {
		l := s.live[n.ID]
		if l == nil {
			l = &liveNode{lastSeen: time.Now(), online: true}
			s.live[n.ID] = l
		}
		if l.discoPub != req.DiscoPub || !slices.Equal(l.endpoints, eps) {
			if l.allowUpdate(time.Now()) {
				l.discoPub, l.endpoints = req.DiscoPub, eps
				s.bumpLocked()
			} else {
				limited = true
			}
		}
	}
	s.mu.Unlock()
	if limited {
		writeErr(w, http.StatusTooManyRequests, "too many updates")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleNetMap(w http.ResponseWriter, r *http.Request) {
	n := s.authed(w, r)
	if n == nil {
		return
	}
	since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	deadline := time.NewTimer(pollTimeout)
	defer deadline.Stop()
	for {
		s.mu.Lock()
		if s.byID[n.ID] != n {
			s.mu.Unlock()
			writeErr(w, http.StatusUnauthorized, "unknown node")
			return
		}
		if s.version != since {
			nm := s.netMapLocked(n)
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, nm)
			return
		}
		wait := s.notify
		s.mu.Unlock()
		select {
		case <-wait:
		case <-deadline.C:
			s.mu.Lock()
			if s.byID[n.ID] == n {
				s.touchLocked(n.ID)
			}
			s.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) nodeViewLocked(n *nodeRec) proto.Node {
	v := proto.Node{ID: n.ID, Name: n.Name, WGPub: n.WGPub, IP: n.IP}
	if l := s.live[n.ID]; l != nil {
		v.DiscoPub = l.discoPub
		v.Endpoints = slices.Clone(l.endpoints)
		v.Online = l.online
		v.LastSeen = l.lastSeen.UTC()
	}
	return v
}

func (s *Server) netMapLocked(self *nodeRec) *proto.NetMap {
	nm := &proto.NetMap{
		Version:  s.version,
		CIDR:     s.st.CIDR,
		STUNPort: s.stunPort,
		Self:     s.nodeViewLocked(self),
		Peers:    make([]proto.Node, 0, len(s.st.Nodes)),
	}
	for _, n := range s.st.Nodes {
		if n != self {
			nm.Peers = append(nm.Peers, s.nodeViewLocked(n))
		}
	}
	slices.SortFunc(nm.Peers, func(a, b proto.Node) int { return a.IP.Compare(b.IP) })
	return nm
}

// ---- admin API (unix socket, owner only) ----

// AuthKeyRequest asks for a new enrollment key.
type AuthKeyRequest struct {
	Reusable   bool `json:"reusable"`
	TTLSeconds int  `json:"ttl_seconds"`
}

// AuthKeyResponse carries the secret, which is shown exactly once.
type AuthKeyResponse struct {
	Key     string    `json:"key"`
	ID      string    `json:"id"`
	Expires time.Time `json:"expires"`
}

// AuthKeyInfo describes an existing key without its secret.
type AuthKeyInfo struct {
	ID       string    `json:"id"`
	Reusable bool      `json:"reusable"`
	Expires  time.Time `json:"expires"`
	Used     int       `json:"used"`
}

// Info summarises the server for the admin CLI.
type Info struct {
	Pin  string       `json:"pin"`
	CIDR netip.Prefix `json:"cidr"`
}

func (s *Server) adminMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /info", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		writeJSON(w, http.StatusOK, Info{Pin: s.Pin(), CIDR: s.st.CIDR})
	})
	mux.HandleFunc("POST /authkeys", func(w http.ResponseWriter, r *http.Request) {
		var req AuthKeyRequest
		if !readJSON(w, r, &req) {
			return
		}
		if req.TTLSeconds <= 0 || req.TTLSeconds > 90*24*3600 {
			writeErr(w, http.StatusBadRequest, "ttl must be between 1s and 90 days")
			return
		}
		secret, rec, err := newAuthKey()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "entropy failure")
			return
		}
		rec.Reusable = req.Reusable
		rec.Expires = rec.Created.Add(time.Duration(req.TTLSeconds) * time.Second)
		s.mu.Lock()
		defer s.mu.Unlock()
		// Drop expired and spent keys while we are here.
		s.st.AuthKeys = slices.DeleteFunc(s.st.AuthKeys, func(k *authKeyRec) bool {
			return rec.Created.After(k.Expires) || (!k.Reusable && k.Used > 0)
		})
		if len(s.st.AuthKeys) >= maxAuthKeys {
			writeErr(w, http.StatusConflict, "too many auth keys")
			return
		}
		s.st.AuthKeys = append(s.st.AuthKeys, rec)
		if err := s.st.save(s.dir); err != nil {
			writeErr(w, http.StatusInternalServerError, "state save failed")
			return
		}
		writeJSON(w, http.StatusOK, AuthKeyResponse{Key: secret, ID: rec.ID, Expires: rec.Expires})
	})
	mux.HandleFunc("GET /authkeys", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		out := make([]AuthKeyInfo, 0, len(s.st.AuthKeys))
		for _, k := range s.st.AuthKeys {
			out = append(out, AuthKeyInfo{ID: k.ID, Reusable: k.Reusable, Expires: k.Expires, Used: k.Used})
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("DELETE /authkeys/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		s.mu.Lock()
		defer s.mu.Unlock()
		before := len(s.st.AuthKeys)
		s.st.AuthKeys = slices.DeleteFunc(s.st.AuthKeys, func(k *authKeyRec) bool { return k.ID == id })
		if len(s.st.AuthKeys) == before {
			writeErr(w, http.StatusNotFound, "no such auth key")
			return
		}
		if err := s.st.save(s.dir); err != nil {
			writeErr(w, http.StatusInternalServerError, "state save failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /nodes", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		out := make([]proto.Node, 0, len(s.st.Nodes))
		for _, n := range s.st.Nodes {
			out = append(out, s.nodeViewLocked(n))
		}
		slices.SortFunc(out, func(a, b proto.Node) int { return a.IP.Compare(b.IP) })
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("DELETE /nodes/{id}", func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("id")
		s.mu.Lock()
		defer s.mu.Unlock()
		idx := slices.IndexFunc(s.st.Nodes, func(n *nodeRec) bool { return n.ID == key || n.Name == key })
		if idx < 0 {
			writeErr(w, http.StatusNotFound, "no such node")
			return
		}
		n := s.st.Nodes[idx]
		s.st.Nodes = slices.Delete(s.st.Nodes, idx, idx+1)
		delete(s.byID, n.ID)
		delete(s.byIdent, string(n.Identity))
		delete(s.live, n.ID)
		if err := s.st.save(s.dir); err != nil {
			writeErr(w, http.StatusInternalServerError, "state save failed")
			return
		}
		s.bumpLocked()
		s.log.Info("node removed", "id", n.ID, "name", n.Name)
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// AdminClient returns an HTTP client and base URL for the admin socket of
// the server running on dir.
func AdminClient(dir string) (*http.Client, string) {
	sock := filepath.Join(dir, AdminSocket)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}, "http://coord"
}
