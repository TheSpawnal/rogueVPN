package tap

import (
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/tun"

	"wyrm/internal/flow"
)

type fakeTun struct {
	toRead  [][]byte
	written [][]byte
}

func (f *fakeTun) File() *os.File           { return nil }
func (f *fakeTun) MTU() (int, error)        { return 1280, nil }
func (f *fakeTun) Name() (string, error)    { return "fake", nil }
func (f *fakeTun) Events() <-chan tun.Event { return nil }
func (f *fakeTun) Close() error             { return nil }
func (f *fakeTun) BatchSize() int           { return 8 }
func (f *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for i, p := range f.toRead {
		sizes[i] = copy(bufs[i][offset:], p)
	}
	return len(f.toRead), nil
}
func (f *fakeTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		f.written = append(f.written, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}

// udp4 builds a minimal IPv4/UDP packet 10.88.0.a -> 10.88.0.b.
func udp4(a, b byte, dport uint16) []byte {
	p := make([]byte, 28)
	p[0], p[3], p[8], p[9] = 0x45, 28, 64, 17
	copy(p[12:], []byte{10, 88, 0, a})
	copy(p[16:], []byte{10, 88, 0, b})
	p[21], p[22], p[23], p[25] = 99, byte(dport>>8), byte(dport), 8
	return p
}

func TestTapFilters(t *testing.T) {
	tb := flow.NewTable()
	r, _ := flow.ParseRule([]string{"drop", "any", "udp", "any", "53"})
	if _, err := tb.AddRule(r); err != nil {
		t.Fatal(err)
	}
	ft := &fakeTun{toRead: [][]byte{udp4(1, 2, 80), udp4(1, 2, 53), udp4(1, 2, 81)}}
	d := New(ft, tb)

	const off = 16
	bufs := make([][]byte, 8)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	sizes := make([]int, 8)
	n, err := d.Read(bufs, sizes, off)
	if err != nil || n != 3 || sizes[0] != 28 || sizes[1] != 0 || sizes[2] != 28 {
		t.Fatalf("read: n=%d sizes=%v err=%v", n, sizes[:3], err)
	}

	mk := func(p []byte) []byte { return append(make([]byte, off), p...) }
	in := [][]byte{mk(udp4(2, 1, 53)), mk(udp4(2, 1, 80)), mk(udp4(2, 1, 53)), mk(udp4(2, 1, 81)), mk([]byte{0xff})}
	orig := append([][]byte(nil), in...)
	if n, err := d.Write(in, off); err != nil || n != len(in) {
		t.Fatalf("write: %d %v", n, err)
	}
	if len(ft.written) != 2 || ft.written[0][23] != 80 || ft.written[1][23] != 81 {
		t.Fatalf("delivered %d packets", len(ft.written))
	}
	for i := range in {
		if &in[i][0] != &orig[i][0] {
			t.Fatal("caller's batch was reordered")
		}
	}
	// Nothing dropped: the batch is passed through untouched.
	ft.written = nil
	if _, err := d.Write([][]byte{mk(udp4(2, 1, 80))}, off); err != nil || len(ft.written) != 1 {
		t.Fatal("pass-through")
	}
	// Everything dropped: the device is not called at all.
	ft.written = nil
	if n, err := d.Write([][]byte{mk(udp4(2, 1, 53))}, off); err != nil || n != 1 || len(ft.written) != 0 {
		t.Fatal("all-dropped batch reached the device")
	}
	tot := tb.Totals()
	if tot.DropOut != 1 || tot.DropIn != 4 || tot.Malformed != 1 || tot.TxPkts != 2 || tot.RxPkts != 3 {
		t.Fatalf("totals: %+v", tot)
	}
}
