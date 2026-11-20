package tui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"golang.org/x/term"

	"wyrm/internal/api"
	"wyrm/internal/flow"
)

type update struct {
	snap api.Snapshot
	pkts []flow.PacketInfo
	err  error
	at   time.Time
}

type key int

const (
	keyNone key = iota
	keyUp
	keyDown
	keyPgUp
	keyPgDn
	keyHome
	keyEnd
	keyDelete
	keyTab
	keyQuit
	keyChar // plus the byte value
)

// parseKeys decodes raw terminal input into keys.
func parseKeys(b []byte) []key {
	var out []key
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c == 0x03:
			out = append(out, keyQuit)
		case c == '\t':
			out = append(out, keyTab)
		case c == 0x1b:
			if i+1 >= len(b) || (b[i+1] != '[' && b[i+1] != 'O') {
				continue
			}
			j := i + 2
			for j < len(b) && (b[j] < 0x40 || b[j] > 0x7e) {
				j++
			}
			if j >= len(b) {
				return out
			}
			switch seq := string(b[i+2 : j+1]); seq {
			case "A":
				out = append(out, keyUp)
			case "B":
				out = append(out, keyDown)
			case "5~":
				out = append(out, keyPgUp)
			case "6~":
				out = append(out, keyPgDn)
			case "H", "1~":
				out = append(out, keyHome)
			case "F", "4~":
				out = append(out, keyEnd)
			case "3~":
				out = append(out, keyDelete)
			}
			i = j
		case c >= 0x20 && c < 0x7f:
			out = append(out, keyChar+key(c))
		}
	}
	return out
}

func sgr(st style, color bool) string {
	switch st {
	case stTitle:
		return "\x1b[1m"
	case stHeader, stKeys:
		return "\x1b[7m"
	case stSelected:
		return "\x1b[7;1m"
	case stDim:
		return "\x1b[2m"
	case stWarn:
		if color {
			return "\x1b[33m"
		}
	case stBad:
		if color {
			return "\x1b[31m"
		}
	}
	return ""
}

func paint(buf *bytes.Buffer, lines []line, w int, color bool) {
	buf.WriteString("\x1b[H")
	for i, l := range lines {
		t := l.text
		if len(t) > w {
			t = t[:w]
		}
		code := sgr(l.st, color)
		if code != "" {
			buf.WriteString(code)
			buf.WriteString(t)
			if l.st == stHeader || l.st == stKeys || l.st == stSelected {
				for n := len(t); n < w; n++ {
					buf.WriteByte(' ')
				}
			}
			buf.WriteString("\x1b[0m")
		} else {
			buf.WriteString(t)
		}
		buf.WriteString("\x1b[K")
		if i < len(lines)-1 {
			buf.WriteString("\r\n")
		}
	}
	buf.WriteString("\x1b[J")
}

// Options configure the dashboard.
type Options struct {
	Interval time.Duration
	View     int
}

// Once prints a single plain-text frame of one view, for scripts and tests.
func Once(ctx context.Context, c *api.Client, w io.Writer, o Options) error {
	m := newModel()
	m.view = o.View
	now := time.Now()
	snap, err := c.Snapshot(ctx)
	if err != nil {
		return err
	}
	m.setSnapshot(snap, now)
	if m.view == viewPackets {
		pk, err := c.Packets(ctx, 0)
		if err != nil {
			return err
		}
		m.addPackets(pk)
	}
	width, height := 160, m.rowCount()+8
	for _, l := range m.frame(width, height, now) {
		fmt.Fprintln(w, l.text)
	}
	return nil
}

// Run shows the interactive dashboard until the user quits.
func Run(ctx context.Context, c *api.Client, o Options) error {
	in, out := int(os.Stdin.Fd()), int(os.Stdout.Fd())
	if !term.IsTerminal(in) || !term.IsTerminal(out) {
		return errors.New("top needs a terminal; use --once for plain output")
	}
	if o.Interval < 200*time.Millisecond {
		o.Interval = time.Second
	}
	old, err := term.MakeRaw(in)
	if err != nil {
		return err
	}
	os.Stdout.WriteString("\x1b[?1049h\x1b[?25l")
	defer func() {
		os.Stdout.WriteString("\x1b[?25h\x1b[?1049l")
		term.Restore(in, old)
	}()
	color := os.Getenv("NO_COLOR") == ""

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	keys := make(chan []key, 8)
	go func() {
		buf := make([]byte, 64)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				cancel()
				return
			}
			if ks := parseKeys(buf[:n]); len(ks) > 0 {
				select {
				case keys <- ks:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	m := newModel()
	m.view = o.View
	updates := make(chan update, 1)
	refresh := make(chan struct{}, 1)
	seq := make(chan uint64, 1)
	seq <- 0
	go func() {
		t := time.NewTicker(o.Interval)
		defer t.Stop()
		for {
			after := <-seq
			cctx, ccancel := context.WithTimeout(ctx, 3*time.Second)
			u := update{at: time.Now()}
			u.snap, u.err = c.Snapshot(cctx)
			if u.err == nil {
				u.pkts, u.err = c.Packets(cctx, after)
			}
			ccancel()
			select {
			case updates <- u:
			case <-ctx.Done():
				return
			}
			select {
			case <-t.C:
			case <-refresh:
			case <-ctx.Done():
				return
			}
		}
	}()

	resize := time.NewTicker(250 * time.Millisecond)
	defer resize.Stop()
	var buf bytes.Buffer
	lastW, lastH := 0, 0
	draw := func() {
		w, h, err := term.GetSize(out)
		if err != nil || w < 20 || h < 8 {
			w, h = 80, 24
		}
		lastW, lastH = w, h
		buf.Reset()
		paint(&buf, m.frame(w, h, time.Now()), w, color)
		os.Stdout.Write(buf.Bytes())
	}
	act := func(fn func(context.Context) error, ok string) {
		cctx, ccancel := context.WithTimeout(ctx, 3*time.Second)
		defer ccancel()
		if err := fn(cctx); err != nil {
			m.say("error: %v", err)
		} else {
			m.say("%s", ok)
		}
		select {
		case refresh <- struct{}{}:
		default:
		}
	}

	draw()
	for {
		select {
		case <-ctx.Done():
			return nil
		case u := <-updates:
			if u.err != nil {
				m.err = u.err
			} else if !m.paused {
				m.setSnapshot(u.snap, u.at)
				m.addPackets(u.pkts)
			}
			seq <- m.pktSeq
			draw()
		case <-resize.C:
			if w, h, err := term.GetSize(out); err == nil && (w != lastW || h != lastH) {
				draw()
			}
		case ks := <-keys:
			for _, k := range ks {
				if m.handle(k, c, act, lastH) {
					return nil
				}
			}
			draw()
		}
	}
}

// handle applies one key and reports whether to quit.
func (m *model) handle(k key, c *api.Client, act func(func(context.Context) error, string), h int) bool {
	page := max(1, h-8)
	move := func(d int) {
		m.sel[m.view] += d
		if m.view == viewPackets {
			m.follow = m.sel[m.view] >= len(m.pkts)-1
		}
	}
	switch k {
	case keyQuit, keyChar + 'q':
		return true
	case keyTab:
		m.view = (m.view + 1) % numViews
	case keyUp, keyChar + 'k':
		move(-1)
	case keyDown, keyChar + 'j':
		move(1)
	case keyPgUp:
		move(-page)
	case keyPgDn:
		move(page)
	case keyHome, keyChar + 'g':
		m.sel[m.view] = 0
		m.follow = false
	case keyEnd, keyChar + 'G':
		m.sel[m.view] = 1 << 30
		m.follow = true
	case keyChar + '1', keyChar + '2', keyChar + '3', keyChar + '4':
		m.view = int(k - keyChar - '1')
	case keyChar + 's':
		m.sortMode = (m.sortMode + 1) % len(sortNames)
		m.sortFlows()
	case keyChar + 'p', keyChar + ' ':
		m.paused = !m.paused
	case keyChar + 'S':
		on := !m.snap.Status.Shields
		act(func(ctx context.Context) error { return c.SetShields(ctx, on) }, "shields "+onOff(on))
	case keyChar + 'b':
		if r, ok := m.blockRule(); ok {
			act(func(ctx context.Context) error { _, err := c.AddRule(ctx, r); return err },
				fmt.Sprintf("added: drop %s %s %s port %d", r.Dir, r.Proto, r.Remote, r.Port))
		}
	case keyChar + 'u':
		if m.view == viewPeers && m.sel[viewPeers] < len(m.snap.Peers) {
			if id, ok := m.peerBlocked(m.snap.Peers[m.sel[viewPeers]].IP); ok {
				act(func(ctx context.Context) error { return c.DelRule(ctx, id) }, "peer unblocked")
			}
		}
	case keyDelete, keyChar + 'd':
		if m.view == viewRules && m.sel[viewRules] < len(m.snap.Rules) {
			id := m.snap.Rules[m.sel[viewRules]].ID
			act(func(ctx context.Context) error { return c.DelRule(ctx, id) }, fmt.Sprintf("rule %d deleted", id))
		}
	}
	return false
}

// blockRule builds the drop rule for the selected peer or flow.
func (m *model) blockRule() (flow.Rule, bool) {
	r := flow.Rule{Action: "drop", Dir: "any", Proto: "any"}
	switch m.view {
	case viewPeers:
		if m.sel[viewPeers] >= len(m.snap.Peers) {
			return r, false
		}
		ip := m.snap.Peers[m.sel[viewPeers]].IP
		r.Remote = netip.PrefixFrom(ip, ip.BitLen())
		return r, true
	case viewFlows:
		if m.sel[viewFlows] >= len(m.snap.Flows) {
			return r, false
		}
		f := m.snap.Flows[m.sel[viewFlows]]
		a := f.Remote.Addr()
		r.Remote = netip.PrefixFrom(a, a.BitLen())
		switch f.Proto {
		case flow.ProtoTCP, flow.ProtoUDP:
			r.Proto = protoName(f.Proto)
			// Block the service, not the ephemeral port: the destination
			// port as seen by whoever opened the flow.
			if f.Initiator == "in" {
				r.Dir, r.Port = "in", f.Local.Port()
			} else {
				r.Dir, r.Port = "out", f.Remote.Port()
			}
		case flow.ProtoICMP, flow.ProtoICMPv6:
			r.Proto = "icmp"
		}
		return r, true
	}
	return r, false
}
