package http3

import "github.com/lucas-clemente/quic-go"

type ConnState struct {
	SupportsDatagram bool
}

type Conn struct {
	conn quic.Connection

	supportsDatagram bool
}

func (c *Conn) State() ConnState {
	return ConnState{SupportsDatagram: c.supportsDatagram}
}

func (c *Conn) SendDatagram(b []byte) error {
	return c.conn.SendMessage(b)
}
