package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"

	"wyrm/internal/api"
	"wyrm/internal/coord"
	"wyrm/internal/platform"
	"wyrm/internal/proto"
)

func cmdCoord(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: wyrm coord <serve|pin|authkey|keys|revoke|nodes|rm>")
	}
	fs := flag.NewFlagSet("coord "+args[0], flag.ContinueOnError)
	dir := fs.String("dir", platform.DefaultCoordDir, "coordination server data directory")
	switch args[0] {
	case "serve":
		listen := fs.String("listen", ":8443", "control API listen address (TLS 1.3)")
		stunAddr := fs.String("stun", ":3478", "STUN listen address (UDP)")
		cidr := fs.String("cidr", "10.88.0.0/16", "mesh address range, used when the data directory is created")
		level := fs.String("log", "info", "log level: debug, info, warn, error")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		log, err := newLogger(*level)
		if err != nil {
			return err
		}
		pfx, err := netip.ParsePrefix(*cidr)
		if err != nil {
			return fmt.Errorf("bad --cidr: %w", err)
		}
		if _, err := coord.Init(*dir, pfx); err != nil {
			return err
		}
		srv, err := coord.Open(*dir, log)
		if err != nil {
			return err
		}
		return srv.Serve(ctx, *listen, *stunAddr)
	case "pin":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		pin, err := coord.ReadPin(*dir)
		if err != nil {
			return err
		}
		fmt.Println(pin)
		return nil
	case "authkey":
		reusable := fs.Bool("reusable", false, "allow the key to enroll more than one node")
		ttl := fs.Duration("ttl", time.Hour, "key lifetime")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		var out coord.AuthKeyResponse
		req := coord.AuthKeyRequest{Reusable: *reusable, TTLSeconds: int(*ttl / time.Second)}
		if err := admin(ctx, *dir, http.MethodPost, "/authkeys", req, &out); err != nil {
			return err
		}
		// The secret alone goes to stdout so it can be redirected to a file.
		fmt.Fprintf(os.Stderr, "key id %s, expires %s\n", out.ID, out.Expires.Local().Format(time.RFC3339))
		fmt.Println(out.Key)
		return nil
	case "keys":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		var out []coord.AuthKeyInfo
		if err := admin(ctx, *dir, http.MethodGet, "/authkeys", nil, &out); err != nil {
			return err
		}
		w := table()
		fmt.Fprintln(w, "ID\tREUSABLE\tUSED\tEXPIRES")
		for _, k := range out {
			fmt.Fprintf(w, "%s\t%v\t%d\t%s\n", api.Printable(k.ID), k.Reusable, k.Used, k.Expires.Local().Format(time.RFC3339))
		}
		return w.Flush()
	case "revoke":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("usage: wyrm coord revoke <key-id>")
		}
		return admin(ctx, *dir, http.MethodDelete, "/authkeys/"+url.PathEscape(fs.Arg(0)), nil, nil)
	case "nodes":
		asJSON := fs.Bool("json", false, "print JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		var out []proto.Node
		if err := admin(ctx, *dir, http.MethodGet, "/nodes", nil, &out); err != nil {
			return err
		}
		if *asJSON {
			return printJSON(out)
		}
		w := table()
		fmt.Fprintln(w, "ID\tNAME\tMESH-IP\tONLINE\tLAST-SEEN\tENDPOINTS")
		for _, n := range out {
			fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\t%v\n", api.Printable(n.ID), api.Printable(n.Name), n.IP, n.Online, ago(n.LastSeen), n.Endpoints)
		}
		return w.Flush()
	case "rm":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("usage: wyrm coord rm <node-id|name>")
		}
		return admin(ctx, *dir, http.MethodDelete, "/nodes/"+url.PathEscape(fs.Arg(0)), nil, nil)
	}
	return fmt.Errorf("unknown coord command %q", args[0])
}

// admin calls the admin socket of the running coordination server.
func admin(ctx context.Context, dir, method, path string, in, out any) error {
	hc, base := coord.AdminClient(dir)
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
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("coordination server not reachable (is 'wyrm coord serve' running on %s?): %w", dir, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e proto.Error
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}
