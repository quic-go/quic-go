package self_test

import (
	"net"
	"testing"
	"time"

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
	settings := simnet.NodeBiDiLinkSettings{
		Downlink: simnet.LinkSettings{BitsPerSecond: 1e8},
		Uplink:   simnet.LinkSettings{BitsPerSecond: 1e8},
		Latency:  rtt / 2, // Latency applies to downlink only; uplink is instant
	}
	clientPacketConn := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}, settings)
	serverPacketConn := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}, settings)

	require.NoError(t, n.Start())

	return clientPacketConn, serverPacketConn, func(t *testing.T) {
		require.NoError(t, clientPacketConn.Close())
		require.NoError(t, serverPacketConn.Close())
		require.NoError(t, n.Close())
	}
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
