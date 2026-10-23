package controlstdio

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestBlockedOpenDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	h := New(true, a, a, a.Close)
	defer h.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := h.Dial(ctx, 80); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unread open succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled open blocked")
	}
	select {
	case <-h.done:
	default:
		t.Fatal("partial write left transport usable")
	}
}
func TestClosedListenerAndMuxRefuse(t *testing.T) {
	h, g := pair(t)
	l, _ := g.Listen(80)
	l.Close()
	go h.Serve()
	go g.Serve()
	c, err := h.Dial(context.Background(), 80)
	if err != nil {
		return
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err = c.Read(b[:]); err == nil {
		t.Fatal("closed listener accepted data")
	}
	g.Close()
	if _, err = g.Listen(81); !errors.Is(err, net.ErrClosed) {
		t.Fatal("listen after close", err)
	}
}
func TestReuseOpenRefused(t *testing.T) {
	var wire []byte
	for i := 0; i < 2; i++ {
		var f [11]byte
		f[0] = openFrame
		binary.BigEndian.PutUint32(f[1:5], 1)
		binary.BigEndian.PutUint16(f[5:7], 80)
		wire = append(wire, f[:]...)
	}
	r, w := io.Pipe()
	g := New(false, r, io.Discard, r.Close)
	defer g.Close()
	l, _ := g.Listen(80)
	defer l.Close()
	go func() { w.Write(wire); w.Close() }()
	if err := g.Serve(); err == nil {
		t.Fatal("reused stream accepted")
	}
}
func TestUnknownPortClosesOnlyStream(t *testing.T) {
	h, g := pair(t)
	l, _ := g.Listen(80)
	go h.Serve()
	go g.Serve()
	missing, err := h.Dial(context.Background(), 81)
	if err != nil {
		t.Fatal(err)
	}
	defer missing.Close()
	missing.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err = missing.Read(b[:]); err == nil {
		t.Fatal("missing listener usable")
	}
	c, err := h.Dial(context.Background(), 80)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	other, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	go other.Write([]byte("x"))
	if _, err = io.ReadFull(c, b[:]); err != nil || b[0] != 'x' {
		t.Fatal("unrelated stream lost", err)
	}
}
