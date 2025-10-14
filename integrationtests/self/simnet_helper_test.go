package self_test

import "github.com/quic-go/quic-go/testutils/simnet"

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

var _ simnet.Router = &droppingRouter{}
