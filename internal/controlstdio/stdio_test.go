package controlstdio

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func pair(t *testing.T) (*Mux, *Mux) {
	t.Helper()
	a, b := net.Pipe()
	host := New(true, a, a, a.Close)
	guest := New(false, b, b, b.Close)
	t.Cleanup(func() { host.Close(); guest.Close() })
	return host, guest
}
func TestParallelReplyAndCancel(t *testing.T) {
	h, g := pair(t)
	l, err := g.Listen(80)
	if err != nil {
		t.Fatal(err)
	}
	go h.Serve()
	go g.Serve()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			c, e := h.Dial(context.Background(), 80)
			if e != nil {
				done <- e
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(2 * time.Second))
			if _, e = c.Write([]byte("hello")); e != nil {
				done <- e
				return
			}
			b := make([]byte, 5)
			_, e = io.ReadFull(c, b)
			if e == nil && string(b) != "hello" {
				t.Error("wrong stream")
			}
			done <- e
		}()
	}
	for i := 0; i < 8; i++ {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := h.Dial(ctx, 80); e == nil {
		t.Fatal("canceled dial")
	}
	if _, e := g.Dial(context.Background(), 80); e == nil {
		t.Fatal("guest opened stream")
	}
}
func TestRejectInvalidFrames(t *testing.T) {
	for _, tc := range []struct {
		name string
		host bool
		kind byte
		id   uint32
		port uint16
		n    uint32
	}{{"guest-open", true, openFrame, 1, 80, 0}, {"zero-id", false, openFrame, 0, 80, 0}, {"oversize", true, dataFrame, 1, 0, maxFrame + 1}, {"unknown", true, dataFrame, 1, 0, 0}, {"bad-kind", false, 9, 1, 80, 0}, {"port-data", false, dataFrame, 1, 80, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			var f [11]byte
			f[0] = tc.kind
			binary.BigEndian.PutUint32(f[1:5], tc.id)
			binary.BigEndian.PutUint16(f[5:7], tc.port)
			binary.BigEndian.PutUint32(f[7:], tc.n)
			b.Write(f[:])
			m := New(tc.host, &b, io.Discard, nil)
			if err := m.Serve(); err == nil {
				t.Fatal("accepted malformed frame")
			}
		})
	}
}
func TestCloseInterruptsActiveStream(t *testing.T) {
	h, g := pair(t)
	l, _ := g.Listen(8081)
	go h.Serve()
	go g.Serve()
	c, e := h.Dial(context.Background(), 8081)
	if e != nil {
		t.Fatal(e)
	}
	other, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	g.Close()
	select {
	case <-h.done:
	case <-time.After(time.Second):
		t.Fatal("host did not close")
	}
	c.SetDeadline(time.Now().Add(time.Second))
	var data [1]byte
	if _, e = c.Read(data[:]); e == nil {
		t.Fatal("closed transport usable")
	}
	c.Close()
}
