// Command wyrm is a WireGuard-based mesh VPN: node daemon, coordination
// server, command-line client and terminal dashboard in one binary.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"wyrm/internal/api"
	"wyrm/internal/apiserver"
	"wyrm/internal/engine"
	"wyrm/internal/flow"
	"wyrm/internal/platform"
	"wyrm/internal/tui"
	"wyrm/internal/version"
)

const usage = `wyrm - WireGuard mesh VPN

Node:
  wyrm up        start the node daemon (enrolls on first start)
  wyrm status    show the local node
  wyrm peers     list peers and their paths
  wyrm flows     list active flows
  wyrm packets   list recently seen packets
  wyrm rules     list filter rules
  wyrm rule add <allow|drop> <in|out|any> <any|tcp|udp|icmp> <cidr|ip|any> <port|any>
  wyrm rule del <id>
  wyrm shields <on|off>   drop unsolicited inbound traffic
  wyrm capture   stream a pcap of tunnel traffic to stdout or a file
  wyrm top       interactive dashboard

Coordination server:
  wyrm coord serve     run the server (initializes its data directory)
  wyrm coord pin       print the key pin nodes must be given
  wyrm coord authkey   create an enrollment key
  wyrm coord keys      list enrollment keys
  wyrm coord revoke <key-id>
  wyrm coord nodes     list nodes
  wyrm coord rm <node-id|name>

  wyrm version

Flags go before positional arguments. Run any command with -h for its flags.
Client commands find the daemon at --sock, $WYRM_SOCK or the system default.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "up":
		err = cmdUp(ctx, args)
	case "coord":
		err = cmdCoord(ctx, args)
	case "status", "peers", "flows", "packets", "rules":
		err = cmdShow(ctx, cmd, args)
	case "rule":
		err = cmdRule(ctx, args)
	case "shields":
		err = cmdShields(ctx, args)
	case "capture":
		err = cmdCapture(ctx, args)
	case "top":
		err = cmdTop(ctx, args)
	case "version", "--version", "-v":
		fmt.Println(version.Version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "wyrm:", api.Printable(err.Error()))
		os.Exit(1)
	}
}

// defaultSock is the daemon socket: $WYRM_SOCK if set, else the system path.
func defaultSock() string {
	if s := os.Getenv("WYRM_SOCK"); s != "" {
		return s
	}
	return filepath.Join(platform.DefaultRunDir, "wyrmd.sock")
}

func newLogger(level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("bad log level %q", level)
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})), nil
}

func cmdUp(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	state := fs.String("state", platform.DefaultStateDir, "state directory (keys, enrollment, policy)")
	iface := fs.String("iface", "wyrm0", "tunnel interface name")
	port := fs.Uint("port", 51820, "UDP listen port (0 = random)")
	mtu := fs.Int("mtu", engine.DefaultMTU, "tunnel MTU (1280-1420)")
	noLAN := fs.Bool("no-lan", false, "do not advertise local interface addresses")
	sock := fs.String("sock", defaultSock(), "local API socket")
	group := fs.String("group", "", "group allowed to use the local API (default: owner only)")
	coordURL := fs.String("coord", "", "coordination server URL, first start only (https://host:port)")
	pin := fs.String("pin", "", "coordination server key pin, first start only (sha256:...)")
	keyFile := fs.String("authkey-file", "", "file holding the enrollment key, first start only (or env WYRM_AUTHKEY)")
	name := fs.String("name", "", "node name, first start only (default: host name)")
	level := fs.String("log", "info", "log level: debug, info, warn, error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *port > 65535 {
		return errors.New("bad port")
	}
	log, err := newLogger(*level)
	if err != nil {
		return err
	}
	gid := -1
	if *group != "" {
		if gid, err = lookupGroup(*group); err != nil {
			return err
		}
	}

	st, err := engine.LoadState(*state)
	if errors.Is(err, os.ErrNotExist) {
		authKey := os.Getenv("WYRM_AUTHKEY")
		if *keyFile != "" {
			b, rerr := os.ReadFile(*keyFile)
			if rerr != nil {
				return rerr
			}
			authKey = string(b)
		}
		n := *name
		if n == "" {
			n, _ = os.Hostname()
		}
		ectx, cancel := context.WithTimeout(ctx, 30*time.Second)
		st, err = engine.Enroll(ectx, *state, engine.EnrollParams{
			CoordURL: *coordURL, CoordPin: *pin, AuthKey: strings.TrimSpace(authKey), Name: n,
		})
		cancel()
		if err != nil {
			return err
		}
		log.Info("enrolled", "node", st.NodeID, "name", st.Name, "ip", st.IP.String())
	} else if err != nil {
		return err
	}

	eng, err := engine.New(engine.Config{
		StateDir: *state, Iface: *iface, ListenPort: uint16(*port), MTU: *mtu, NoLAN: *noLAN, Log: log,
	}, st)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- apiserver.Serve(ctx, eng, *sock, gid, log)
		cancel()
	}()
	eng.Run(ctx)
	return <-errc
}

func lookupGroup(name string) (int, error) {
	if gid, err := strconv.Atoi(name); err == nil && gid >= 0 {
		return gid, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return -1, err
	}
	return strconv.Atoi(g.Gid)
}

func clientFlags(name string) (*flag.FlagSet, *string, *bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	sock := fs.String("sock", defaultSock(), "local API socket")
	asJSON := fs.Bool("json", false, "print JSON")
	return fs, sock, asJSON
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func table() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return time.Since(t).Round(time.Second).String()
}

var protoNames = map[uint8]string{1: "icmp", 6: "tcp", 17: "udp", 58: "icmp6"}

func protoName(p uint8) string {
	if n, ok := protoNames[p]; ok {
		return n
	}
	return strconv.Itoa(int(p))
}

func cmdShow(ctx context.Context, what string, args []string) error {
	fs, sock, asJSON := clientFlags(what)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c := api.NewClient(*sock)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := api.Printable
	switch what {
	case "status":
		s, err := c.Status(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(s)
		}
		eps := make([]string, len(s.Endpoints))
		for i, e := range s.Endpoints {
			eps[i] = e.String()
		}
		t := s.Totals
		w := table()
		fmt.Fprintf(w, "node\t%s (%s)\n", p(s.Name), p(s.NodeID))
		fmt.Fprintf(w, "address\t%s/%d on %s\n", s.IP, s.CIDR.Bits(), p(s.Iface))
		fmt.Fprintf(w, "transport\t%s, udp port %d\n", p(s.Transport), s.ListenPort)
		fmt.Fprintf(w, "coordination\t%s (%s, last sync %s ago)\n", p(s.CoordURL), p(s.CoordState), ago(s.CoordSync))
		fmt.Fprintf(w, "endpoints\t%s\n", strings.Join(eps, " "))
		fmt.Fprintf(w, "shields\t%v\n", s.Shields)
		fmt.Fprintf(w, "traffic\trx %d bytes / %d pkts, tx %d bytes / %d pkts\n", t.RxBytes, t.RxPkts, t.TxBytes, t.TxPkts)
		fmt.Fprintf(w, "dropped\tin %d, out %d, malformed %d\n", t.DropIn, t.DropOut, t.Malformed)
		fmt.Fprintf(w, "non-mesh\tin %d (peer misbehaviour), out %d (host noise)\n", t.ForeignIn, t.ForeignOut)
		fmt.Fprintf(w, "flows\t%d\n", t.Flows)
		fmt.Fprintf(w, "uptime\t%s\n", ago(s.Started))
		fmt.Fprintf(w, "version\t%s\n", p(s.Version))
		return w.Flush()
	case "peers":
		peers, err := c.Peers(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(peers)
		}
		w := table()
		fmt.Fprintln(w, "NAME\tMESH-IP\tPATH\tENDPOINT\tRTT\tHANDSHAKE\tRX\tTX")
		for _, x := range peers {
			ep, rtt := "-", "-"
			if x.Endpoint.IsValid() {
				ep = x.Endpoint.String()
			}
			if x.Path == api.PathDirect {
				rtt = strconv.FormatFloat(x.RTTMillis, 'f', 2, 64) + "ms"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\n", p(x.Name), x.IP, p(x.Path), ep, rtt,
				ago(x.LastHandshake), x.RxBytes, x.TxBytes)
		}
		return w.Flush()
	case "flows":
		flows, err := c.Flows(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(flows)
		}
		w := table()
		fmt.Fprintln(w, "PROTO\tLOCAL\tREMOTE\tINIT\tSTATE\tRX-BYTES\tTX-BYTES\tRX-PKTS\tTX-PKTS\tDROPPED\tIDLE")
		for _, f := range flows {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n", protoName(f.Proto), f.Local, f.Remote,
				p(f.Initiator), p(f.State), f.RxBytes, f.TxBytes, f.RxPkts, f.TxPkts, f.Dropped, ago(f.Last))
		}
		return w.Flush()
	case "packets":
		pkts, err := c.Packets(ctx, 0)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(pkts)
		}
		w := table()
		fmt.Fprintln(w, "SEQ\tTIME\tDIR\tVERDICT\tPROTO\tSOURCE\tDESTINATION\tLEN")
		for _, k := range pkts {
			src, dst := "-", "-"
			if k.Src.IsValid() {
				src, dst = k.Src.String(), k.Dst.String()
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n", k.Seq, k.Time.Format("15:04:05.000"),
				p(k.Dir), p(k.Verdict), protoName(k.Proto), src, dst, k.Len)
		}
		return w.Flush()
	}
	rules, err := c.Rules(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(rules)
	}
	w := table()
	fmt.Fprintln(w, "ID\tACTION\tDIR\tPROTO\tREMOTE\tPORT\tHITS")
	for _, r := range rules {
		remote, port := "any", "any"
		if r.Remote.IsValid() {
			remote = r.Remote.String()
		}
		if r.Port != 0 {
			port = strconv.Itoa(int(r.Port))
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%d\n", r.ID, p(r.Action), p(r.Dir), p(r.Proto), remote, port, r.Hits)
	}
	return w.Flush()
}

func cmdRule(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: wyrm rule add ... | wyrm rule del <id>")
	}
	fs, sock, _ := clientFlags("rule")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	c := api.NewClient(*sock)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	switch args[0] {
	case "add":
		r, err := flow.ParseRule(fs.Args())
		if err != nil {
			return err
		}
		out, err := c.AddRule(ctx, r)
		if err != nil {
			return err
		}
		fmt.Println(out.ID)
		return nil
	case "del":
		if fs.NArg() != 1 {
			return errors.New("usage: wyrm rule del <id>")
		}
		id, err := strconv.ParseUint(fs.Arg(0), 10, 32)
		if err != nil {
			return errors.New("bad rule id")
		}
		return c.DelRule(ctx, uint32(id))
	}
	return errors.New("usage: wyrm rule add ... | wyrm rule del <id>")
}

func cmdShields(ctx context.Context, args []string) error {
	fs, sock, _ := clientFlags("shields")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || (fs.Arg(0) != "on" && fs.Arg(0) != "off") {
		return errors.New("usage: wyrm shields <on|off>")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return api.NewClient(*sock).SetShields(ctx, fs.Arg(0) == "on")
}

func cmdCapture(ctx context.Context, args []string) error {
	fs, sock, _ := clientFlags("capture")
	out := fs.String("o", "-", "output file (- = stdout)")
	snaplen := fs.Int("s", 65535, "bytes to keep per packet")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var w io.Writer = os.Stdout
	if *out != "-" {
		// Tunnel plaintext: never create this file readable by others.
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	return api.NewClient(*sock).Capture(ctx, *snaplen, w)
}

func cmdTop(ctx context.Context, args []string) error {
	fs, sock, _ := clientFlags("top")
	once := fs.Bool("once", false, "print one plain-text frame and exit")
	view := fs.String("view", "peers", "initial view: peers, flows, packets, rules")
	interval := fs.Duration("interval", time.Second, "refresh interval")
	if err := fs.Parse(args); err != nil {
		return err
	}
	v, ok := tui.ViewIndex(*view)
	if !ok {
		return fmt.Errorf("unknown view %q", *view)
	}
	c := api.NewClient(*sock)
	o := tui.Options{Interval: *interval, View: v}
	if *once {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return tui.Once(ctx, c, os.Stdout, o)
	}
	return tui.Run(ctx, c, o)
}
