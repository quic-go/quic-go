package quic

import (
	"net"

	"github.com/quic-go/quic-go/internal/protocol"
)

type sender interface {
	Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) error
	SendProbe(*packetBuffer, net.Addr)
}

type sendQueue struct {
	conn sendConn
}

var _ sender = &sendQueue{}

func newSendQueue(conn sendConn) sender {
	return &sendQueue{
		conn: conn,
	}
}

// Send sends out a packet. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise Send will panic.
func (h *sendQueue) Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) error {
	if err := h.conn.Write(p.Data, gsoSize, ecn); err != nil {
		// This additional check enables:
		// 1. Checking for "datagram too large" message from the kernel, as such,
		// 2. Path MTU discovery,and
		// 3. Eventual detection of loss PingFrame.
		if !isSendMsgSizeErr(err) {
			return err
		}
	}
	p.Release()
	return nil
}

func (h *sendQueue) SendProbe(p *packetBuffer, addr net.Addr) {
	h.conn.WriteTo(p.Data, addr)
}
