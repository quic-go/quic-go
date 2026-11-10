package self_test

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

func newSimnetLink(t *testing.T, rtt time.Duration) (client, server *simnet.SimConn, close func(t *testing.T)) {
	t.Helper()

	return newSimnetLinkWithRouter(t, rtt, &simnet.PerfectRouter{})
}

func newSimnetLinkWithRouter(t *testing.T, rtt time.Duration, router simnet.Router) (client, server *simnet.SimConn, close func(t *testing.T)) {
	t.Helper()

	n := &simnet.Simnet{Router: router}
	settings := simnet.NodeBiDiLinkSettings{Latency: rtt / 2}
	clientPacketConn := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}, settings)
	serverPacketConn := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}, settings)

	return clientPacketConn, serverPacketConn, func(t *testing.T) {
		require.NoError(t, clientPacketConn.Close())
		require.NoError(t, serverPacketConn.Close())
		require.NoError(t, n.Close())
	}
}

// testNetwork is a simulated network.
// Every connection gets its own 127.0.0.1 address.
type testNetwork struct {
	simnet   simnet.Simnet
	settings simnet.NodeBiDiLinkSettings

	mx    sync.Mutex
	conns []*simnet.SimConn
}

func newTestNetwork(t *testing.T) *testNetwork {
	return newTestNetworkWithSettings(t, simnet.NodeBiDiLinkSettings{})
}

func newTestNetworkWithSettings(t *testing.T, settings simnet.NodeBiDiLinkSettings) *testNetwork {
	n := &testNetwork{
		simnet:   simnet.Simnet{Router: &simnet.PerfectRouter{}},
		settings: settings,
	}
	t.Cleanup(func() { require.NoError(t, n.Close()) })
	return n
}

func (n *testNetwork) NewConn() *simnet.SimConn {
	n.mx.Lock()
	defer n.mx.Unlock()

	c := n.simnet.NewEndpoint(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000 + len(n.conns)}, n.settings)
	n.conns = append(n.conns, c)
	return c
}

// DialEarly dials from a new connection.
// It can be used as the http3.Transport's Dial callback.
func (n *testNetwork) DialEarly(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	return quic.DialEarly(ctx, n.NewConn(), udpAddr, tlsConf, conf)
}

func (n *testNetwork) Close() error {
	n.mx.Lock()
	defer n.mx.Unlock()

	for _, c := range n.conns {
		c.Close()
	}
	return n.simnet.Close()
}

type droppingRouter struct {
	simnet.PerfectRouter

	Drop func(simnet.Packet) bool
}

func (d *droppingRouter) SendPacket(p simnet.Packet) error {
	if d.Drop(p) {
		return nil
	}
	return d.PerfectRouter.SendPacket(p)
}

type callbackRouter struct {
	simnet.Router

	OnSendPacket func(simnet.Packet)
}

func (c *callbackRouter) SendPacket(p simnet.Packet) error {
	c.OnSendPacket(p)
	return c.Router.SendPacket(p)
}

type direction uint8

const (
	directionUnknown = iota
	directionToClient
	directionToServer
	directionBoth
)

func (d direction) String() string {
	switch d {
	case directionToClient:
		return "to client"
	case directionToServer:
		return "to server"
	case directionBoth:
		return "both"
	}
	return "unknown"
}

var _ simnet.Router = &droppingRouter{}

type directionAwareDroppingRouter struct {
	simnet.PerfectRouter

	ClientAddr, ServerAddr *net.UDPAddr

	Drop func(direction direction, p simnet.Packet) bool
}

func (d *directionAwareDroppingRouter) SendPacket(p simnet.Packet) error {
	var dir direction
	switch p.To.String() {
	case d.ClientAddr.String():
		dir = directionToClient
	case d.ServerAddr.String():
		dir = directionToServer
	default:
		dir = directionUnknown
	}
	if d.Drop(dir, p) {
		return nil
	}
	return d.PerfectRouter.SendPacket(p)
}

// natRouter translates the client's address to an external address, like a NAT.
// Packets sent to a previous external address are dropped.
type natRouter struct {
	simnet.PerfectRouter

	clientAddr net.Addr

	mx           sync.Mutex
	externalAddr net.Addr
}

var _ simnet.Router = &natRouter{}

func newNATRouter(clientAddr, externalAddr net.Addr) *natRouter {
	return &natRouter{clientAddr: clientAddr, externalAddr: externalAddr}
}

func (r *natRouter) SendPacket(p simnet.Packet) error {
	r.mx.Lock()
	externalAddr := r.externalAddr
	r.mx.Unlock()

	switch {
	case p.From.String() == r.clientAddr.String():
		p.From = externalAddr
	case p.To.String() == externalAddr.String():
		p.To = r.clientAddr
	default:
		return nil
	}
	return r.PerfectRouter.SendPacket(p)
}

// Rebind changes the external address.
func (r *natRouter) Rebind(externalAddr net.Addr) {
	r.mx.Lock()
	defer r.mx.Unlock()
	r.externalAddr = externalAddr
}
