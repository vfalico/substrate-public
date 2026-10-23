// Package controlstdio carries host-initiated byte streams over runtime-owned
// stdio. It never opens sockets or interprets application data as destinations.
package controlstdio

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

const maxFrame = 32768
const maxStreams = 64
const (
	openFrame  byte = 1
	dataFrame  byte = 2
	closeFrame byte = 3
)

// Mux belongs to one exact runtime incarnation. Only the host may open streams.
// The close function must interrupt the reader and writer; it must not retire
// enforcement or delete compute. On any protocol error all streams fail closed.
type Mux struct {
	host      bool
	r         io.Reader
	w         io.Writer
	closeIO   func() error
	writeMu   sync.Mutex
	openMu    sync.Mutex
	mu        sync.Mutex
	next      uint32
	streams   map[uint32]*stream
	listeners map[uint16]*Listener
	done      chan struct{}
	once      sync.Once
}
type stream struct {
	pipe  net.Conn
	queue chan []byte
	done  chan struct{}
	once  sync.Once
}

func New(host bool, r io.Reader, w io.Writer, closeIO func() error) *Mux {
	return &Mux{host: host, r: r, w: w, closeIO: closeIO, streams: make(map[uint32]*stream), listeners: make(map[uint16]*Listener), done: make(chan struct{})}
}

// Serve must be started once, after guest listeners are registered.
func (m *Mux) Serve() error {
	defer m.Close()
	for {
		var h [11]byte
		if _, err := io.ReadFull(m.r, h[:]); err != nil {
			return err
		}
		kind, id, port, n := h[0], binary.BigEndian.Uint32(h[1:5]), binary.BigEndian.Uint16(h[5:7]), binary.BigEndian.Uint32(h[7:])
		if id == 0 || n > maxFrame || kind < openFrame || kind > closeFrame || (kind != dataFrame && n != 0) || (kind != openFrame && port != 0) {
			return errors.New("invalid control frame")
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(m.r, data); err != nil {
			return err
		}
		m.mu.Lock()
		s := m.streams[id]
		if kind == openFrame {
			if m.host || port == 0 || id <= m.next || s != nil || len(m.streams) >= maxStreams {
				m.mu.Unlock()
				return errors.New("unsolicited or reused control stream")
			}
			m.next = id
			l := m.listeners[port]
			if l == nil {
				m.mu.Unlock()
				if err := m.send(closeFrame, id, 0, nil); err != nil {
					return err
				}
				continue
			}
			select {
			case <-l.done:
				m.mu.Unlock()
				if err := m.send(closeFrame, id, 0, nil); err != nil {
					return err
				}
				continue
			default:
			}
			local := m.newStreamLocked(id)
			select {
			case l.pending <- local:
				m.mu.Unlock()
			case <-l.done:
				m.mu.Unlock()
				local.Close()
				m.drop(id)
			case <-m.done:
				m.mu.Unlock()
				local.Close()
				return net.ErrClosed
			default:
				m.mu.Unlock()
				local.Close()
				return errors.New("control listener overflow")
			}
			continue
		}
		if s == nil {
			known := id <= m.next
			m.mu.Unlock()
			if known {
				continue
			}
			return errors.New("unknown control stream")
		}
		if kind == closeFrame {
			data = nil
		}
		select {
		case s.queue <- data:
			m.mu.Unlock()
		case <-s.done:
			m.mu.Unlock()
		default:
			m.mu.Unlock()
			return errors.New("control stream receive overflow")
		}
	}
}
func (m *Mux) send(kind byte, id uint32, port uint16, data []byte) error {
	if len(data) > maxFrame {
		return errors.New("oversize control payload")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	select {
	case <-m.done:
		return net.ErrClosed
	default:
	}
	var h [11]byte
	h[0] = kind
	binary.BigEndian.PutUint32(h[1:5], id)
	binary.BigEndian.PutUint16(h[5:7], port)
	binary.BigEndian.PutUint32(h[7:], uint32(len(data)))
	if err := writeAll(m.w, h[:]); err != nil {
		m.Close()
		return err
	}
	if err := writeAll(m.w, data); err != nil {
		m.Close()
		return err
	}
	return nil
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func (m *Mux) newStreamLocked(id uint32) net.Conn {
	local, remote := net.Pipe()
	s := &stream{pipe: remote, queue: make(chan []byte, 16), done: make(chan struct{})}
	m.streams[id] = s
	go func() {
		defer m.drop(id)
		for {
			select {
			case b := <-s.queue:
				if b == nil {
					return
				}
				if err := writeAll(remote, b); err != nil {
					return
				}
			case <-s.done:
				return
			case <-m.done:
				return
			}
		}
	}()
	go func() {
		defer m.drop(id)
		defer m.send(closeFrame, id, 0, nil)
		b := make([]byte, maxFrame)
		for {
			n, err := remote.Read(b)
			if n > 0 {
				if e := m.send(dataFrame, id, 0, b[:n]); e != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return local
}
func (m *Mux) drop(id uint32) {
	m.mu.Lock()
	s := m.streams[id]
	delete(m.streams, id)
	m.mu.Unlock()
	if s != nil {
		s.once.Do(func() { close(s.done); s.pipe.Close() })
	}
}

// Dial only admits a fixed listener number selected by the runtime's inbound
// route. No guest frame can ask the host to dial an address or execute a tool.
func (m *Mux) Dial(ctx context.Context, port uint16) (net.Conn, error) {
	m.openMu.Lock()
	defer m.openMu.Unlock()
	if !m.host || port == 0 {
		return nil, errors.New("only host may open control streams")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	select {
	case <-m.done:
		m.mu.Unlock()
		return nil, net.ErrClosed
	default:
	}
	if len(m.streams) >= maxStreams || m.next == ^uint32(0) {
		m.mu.Unlock()
		return nil, errors.New("control stream limit")
	}
	m.next++
	id := m.next
	local := m.newStreamLocked(id)
	m.mu.Unlock()
	// A stuck guest must not hold the runtime gate past its caller deadline.
	// Canceling an in-flight frame closes this exact transport: frames cannot be
	// partially replayed on another stream or target. Enforcement remains active.
	sent := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			m.Close()
		case <-sent:
		}
	}()
	err := m.send(openFrame, id, port, nil)
	close(sent)
	<-watchDone
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		local.Close()
		m.drop(id)
		return nil, err
	}
	return local, nil
}
func (m *Mux) Close() error {
	var err error
	m.once.Do(func() {
		close(m.done)
		if m.closeIO != nil {
			err = m.closeIO()
		}
		m.mu.Lock()
		for id, s := range m.streams {
			s.once.Do(func() { close(s.done); s.pipe.Close() })
			delete(m.streams, id)
		}
		for _, l := range m.listeners {
			l.once.Do(func() { close(l.done) })
		}
		m.mu.Unlock()
	})
	return err
}

type Listener struct {
	m       *Mux
	port    uint16
	pending chan net.Conn
	done    chan struct{}
	once    sync.Once
}

func (m *Mux) Listen(port uint16) (net.Listener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.done:
		return nil, net.ErrClosed
	default:
	}
	if m.host || port == 0 || m.listeners[port] != nil {
		return nil, errors.New("invalid guest control listener")
	}
	l := &Listener{m: m, port: port, pending: make(chan net.Conn, 16), done: make(chan struct{})}
	m.listeners[port] = l
	return l, nil
}
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.pending:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	case <-l.m.done:
		return nil, net.ErrClosed
	}
}
func (l *Listener) Close() error {
	l.once.Do(func() { close(l.done) })
	for {
		select {
		case c := <-l.pending:
			c.Close()
		default:
			return nil
		}
	}
}
func (l *Listener) Addr() net.Addr { return address(fmt.Sprintf("runtime-stdio:%d", l.port)) }

type address string

func (a address) Network() string { return "runtime-stdio" }
func (a address) String() string  { return string(a) }
