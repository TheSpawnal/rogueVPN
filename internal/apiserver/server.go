// Package apiserver exposes a node engine on a local unix socket. Access
// control is the socket's file permission: owner only by default, plus one
// group if the administrator names it.
package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"wyrm/internal/api"
	"wyrm/internal/engine"
	"wyrm/internal/flow"
	"wyrm/internal/platform"
)

const maxFlows = 2000

// Serve runs the local API until ctx is cancelled. gid < 0 restricts the
// socket to its owner; otherwise members of that group may also connect.
// Anyone who can connect can read tunnel traffic and change filter rules.
func Serve(ctx context.Context, eng *engine.Engine, sock string, gid int, log *slog.Logger) error {
	dir := filepath.Dir(sock)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Closed while the socket is created, so it is never reachable with
	// default permissions.
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if c, err := net.DialTimeout("unix", sock, time.Second); err == nil {
		c.Close()
		return fmt.Errorf("another daemon is already serving %s", sock)
	}
	os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	defer os.Remove(sock)
	defer ln.Close()
	mode := os.FileMode(0o600)
	if gid >= 0 {
		mode = 0o660
	}
	if err := platform.RestrictSocket(sock, gid, mode); err != nil {
		return err
	}
	if gid >= 0 {
		if err := platform.RestrictSocket(dir, gid, 0o750); err != nil {
			return err
		}
	}

	t := eng.Table()
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+api.PathStatus, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, eng.Status())
	})
	mux.HandleFunc("GET "+api.PathPeers, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, eng.Peers())
	})
	mux.HandleFunc("GET "+api.PathFlows, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, t.Flows(maxFlows))
	})
	mux.HandleFunc("GET "+api.PathPackets, func(w http.ResponseWriter, r *http.Request) {
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		writeJSON(w, http.StatusOK, t.Packets(after, 0))
	})
	mux.HandleFunc("GET "+api.PathRules, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, t.Policy().Rules)
	})
	mux.HandleFunc("POST "+api.PathRules, func(w http.ResponseWriter, r *http.Request) {
		var rule flow.Rule
		if !readJSON(w, r, &rule) {
			return
		}
		out, err := t.AddRule(rule)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("DELETE "+api.PathRules+"/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
		if err != nil || !t.DelRule(uint32(id)) {
			writeErr(w, http.StatusNotFound, "no such rule")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("PUT "+api.PathShields, func(w http.ResponseWriter, r *http.Request) {
		var req api.ShieldsRequest
		if !readJSON(w, r, &req) {
			return
		}
		t.SetShields(req.On)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET "+api.PathSnapshot, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, api.Snapshot{
			Status: eng.Status(), Peers: eng.Peers(),
			Flows: t.Flows(maxFlows), Rules: t.Policy().Rules,
		})
	})
	mux.HandleFunc("GET "+api.PathCapture, func(w http.ResponseWriter, r *http.Request) {
		capture(w, r, t)
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		srv.Close()
		return nil
	case err := <-errc:
		return err
	}
}

func capture(w http.ResponseWriter, r *http.Request, t *flow.Table) {
	snaplen, _ := strconv.Atoi(r.URL.Query().Get("snaplen"))
	sub, err := t.Subscribe(snaplen, 4096)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	defer t.Unsubscribe(sub)
	if snaplen <= 0 || snaplen > 65535 {
		snaplen = 65535
	}
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{}) // a capture runs until the client leaves
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	if flow.WritePcapHeader(w, snaplen) != nil || rc.Flush() != nil {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case p := <-sub.C:
			if flow.WritePcapRecord(w, p) != nil {
				return
			}
			// Drain whatever else is queued before paying for a flush.
			for more := true; more; {
				select {
				case p = <-sub.C:
					if flow.WritePcapRecord(w, p) != nil {
						return
					}
				default:
					more = false
				}
			}
			if rc.Flush() != nil {
				return
			}
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, api.Error{Error: msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return false
	}
	return true
}
