//go:build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agent-substrate/substrate/cmd/ateom-microvm/internal/kata"
	"github.com/agent-substrate/substrate/internal/controlstdio"
)

// runtimeControl belongs to one exact running VM and container. Its stream
// endpoint is Kata's runtime-owned stdio, not a guest-accessible host proxy.
type runtimeControl struct {
	mux    *controlstdio.Mux
	cancel context.CancelFunc
	once   sync.Once
}

func (c *runtimeControl) Close() { c.once.Do(func() { c.cancel(); c.mux.Close() }) }
func (s *AteomService) prepareControlStdio(ctrs []actorContainer, requirement []byte) (string, error) {
	if len(requirement) == 0 {
		return "", nil
	}
	ec, err := s.executionClient()
	if err != nil {
		return "", err
	}
	name := ec.Config.ControlStdioContainer
	if name == "" {
		return "", nil
	}
	found := false
	for _, c := range ctrs {
		if c.name == name {
			if found || c.spec == nil || c.spec.Process == nil {
				return "", fmt.Errorf("invalid runtime control container")
			}
			found = true
			for _, v := range c.spec.Process.Env {
				if strings.HasPrefix(v, "RUNTIME_CONTROL_STDIO=") {
					return "", fmt.Errorf("workload supplied runtime control selector")
				}
			}
			c.spec.Process.Env = append(c.spec.Process.Env, "RUNTIME_CONTROL_STDIO=1")
		}
	}
	if !found {
		return "", fmt.Errorf("configured runtime control container not prepared")
	}
	return name, nil
}
func (s *AteomService) startControlStdio(id, name string) error {
	if name == "" {
		return nil
	}
	// A separate agent connection permits deterministic cancellation without
	// interrupting lifecycle/retirement calls on the owner connection.
	ctx, cancel := context.WithCancel(context.Background())
	dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialCancel()
	ac, err := kata.DialAgent(dialCtx, kata.VsockSocketPath(id))
	if err != nil {
		cancel()
		return err
	}
	mux := controlstdio.New(true, kata.NewStdioReader(ctx, ac, name, name, false), &kata.StdinWriter{Context: ctx, Agent: ac, Container: name, Exec: name}, ac.Close)
	control := &runtimeControl{mux: mux, cancel: cancel}
	s.actorsMu.Lock()
	h := s.actors[id]
	if h == nil || h.control != nil {
		s.actorsMu.Unlock()
		control.Close()
		return fmt.Errorf("runtime control owner missing or already installed")
	}
	h.control = control
	s.actorsMu.Unlock()
	go func() {
		defer control.Close()
		if err := mux.Serve(); err != nil {
			slog.Info("runtime stdio control closed", "actor_uid", id, "error", err)
		}
	}()
	return nil
}
func (s *AteomService) dialControlStdio(ctx context.Context, id, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("runtime control requires TCP-shaped inbound route")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	// Fixed actor address is a selector only. No packet socket is created.
	if host != "169.254.17.2" {
		return nil, fmt.Errorf("runtime control address outside actor")
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return nil, fmt.Errorf("invalid runtime control listener")
	}
	s.actorsMu.RLock()
	h := s.actors[id]
	var c *runtimeControl
	if h != nil {
		c = h.control
	}
	s.actorsMu.RUnlock()
	if c == nil {
		return nil, fmt.Errorf("runtime control not active")
	}
	return c.mux.Dial(ctx, uint16(value))
}
func (s *AteomService) closeControlStdio(id string) {
	s.actorsMu.Lock()
	h := s.actors[id]
	var c *runtimeControl
	if h != nil {
		c = h.control
		h.control = nil
	}
	s.actorsMu.Unlock()
	if c != nil {
		c.Close()
	}
}
