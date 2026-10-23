//go:build linux

package ateomnet

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/ateomnet/netns"
)

// Feasibility probe of the unmodified backend; not an enforcement acceptance test.
func TestPOCBoundaryBaseline(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("must run privileged; a skip is not evidence")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := SetupSandboxNetwork(ctx, SandboxNetworkConfig{ActorUID: "poc-boundary-20261018-a", Veth: true, EgressPort: 15001})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := CleanupSandboxNetwork(n); err != nil {
			t.Error(err)
		}
	}()
	var tcp net.Listener
	var udp *net.UDPConn
	err = netns.Do(ctx, n.GatewayNetNS, func(context.Context) error {
		var e error
		tcp, e = net.Listen("tcp", net.JoinHostPort(ActorVethGateway, "18271"))
		if e != nil {
			return e
		}
		udp, e = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ActorVethGateway), Port: 53})
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	defer udp.Close()
	tcpSeen := make(chan string, 1)
	udpSeen := make(chan string, 1)
	go func() {
		c, e := tcp.Accept()
		if e != nil {
			tcpSeen <- e.Error()
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 64)
		n, e := c.Read(b)
		if e != nil {
			tcpSeen <- e.Error()
			return
		}
		tcpSeen <- string(b[:n])
	}()
	go func() {
		udp.SetReadDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 64)
		n, _, e := udp.ReadFromUDP(b)
		if e != nil {
			udpSeen <- e.Error()
			return
		}
		udpSeen <- string(b[:n])
	}()
	dial := netns.Dialer(n.RuntimeNetNS)
	c, err := dial(ctx, "tcp", net.JoinHostPort(ActorVethGateway, "18271"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(c, "raw-poc-control")
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	c, err = dial(ctx, "udp", net.JoinHostPort(ActorVethGateway, "53"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(c, "udp-poc-control")
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got := <-tcpSeen; got != "raw-poc-control" {
		t.Fatalf("raw receiver: %q", got)
	}
	if got := <-udpSeen; got != "udp-poc-control" {
		t.Fatalf("udp receiver: %q", got)
	}
	t.Log("INDEPENDENT RECEIVERS: raw TCP and UDP:53 both reached gateway without atunnel; gateway subnet is not a strict egress ceiling")
}
