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
	directionIncoming
	directionOutgoing
	directionBoth
)

func (d direction) String() string {
	switch d {
	case directionIncoming:
		return "incoming"
	case directionOutgoing:
		return "outgoing"
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
		dir = directionIncoming
	case d.ServerAddr.String():
		dir = directionOutgoing
	default:
		dir = directionUnknown
	}
	if d.Drop(dir, p) {
		return nil
	}
	return d.PerfectRouter.SendPacket(p)
}
