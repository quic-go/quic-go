package self_test

import (
	"net"

	"github.com/quic-go/quic-go/testutils/simnet"
)

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
