package quic

import (
	"net"

	"github.com/quic-go/quic-go/internal/protocol"
)

type sender interface {
	Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN)
	SendProbe(*packetBuffer, net.Addr, packetInfo)
	Run() error
	WouldBlock() bool
	Available() <-chan struct{}
	Close()
}

type queueEntry struct {
	buf     *packetBuffer
	gsoSize uint16
	ecn     protocol.ECN
}

type sendQueue struct {
	queue          chan queueEntry
	closeCalled    chan struct{} // runStopped when Close() is called
	runStopped     chan struct{} // runStopped when the run loop returns
	available      chan struct{}
	conn           sendConn
	sendMsgSizeErr chan<- struct{}
}

var _ sender = &sendQueue{}

const sendQueueCapacity = 8

func newSendQueue(conn sendConn, sendMsgSizeErr chan<- struct{}) sender {
	return &sendQueue{
		conn:           conn,
		sendMsgSizeErr: sendMsgSizeErr,
		runStopped:     make(chan struct{}),
		closeCalled:    make(chan struct{}),
		available:      make(chan struct{}, 1),
		queue:          make(chan queueEntry, sendQueueCapacity),
	}
}

// Send sends out a packet. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise Send will panic.
func (h *sendQueue) Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
	select {
	case h.queue <- queueEntry{buf: p, gsoSize: gsoSize, ecn: ecn}:
		// clear available channel if we've reached capacity
		if len(h.queue) == sendQueueCapacity {
			select {
			case <-h.available:
			default:
			}
		}
	case <-h.runStopped:
	default:
		panic("sendQueue.Send would have blocked")
	}
}

func (h *sendQueue) SendProbe(p *packetBuffer, addr net.Addr, info packetInfo) {
	h.conn.WriteTo(p.Data, addr, info)
}

func (h *sendQueue) WouldBlock() bool {
	return len(h.queue) == sendQueueCapacity
}

func (h *sendQueue) Available() <-chan struct{} {
	return h.available
}

func (h *sendQueue) Run() error {
	defer close(h.runStopped)
	var shouldClose bool
	for {
		if shouldClose && len(h.queue) == 0 {
			return nil
		}
		select {
		case <-h.closeCalled:
			h.closeCalled = nil // prevent this case from being selected again
			// make sure that all queued packets are actually sent out
			shouldClose = true
		case e := <-h.queue:
			if err := h.conn.Write(e.buf.Data, e.gsoSize, e.ecn); err != nil {
				if !isSendMsgSizeErr(err) {
					return err
				}
				// Notify the connection without blocking the send queue. Loss recovery
				// still handles the rejected packet; the connection can reduce the
				// size used for handshake retransmissions before PMTUD starts.
				if e.buf.Len() > protocol.MinInitialPacketSize {
					select {
					case h.sendMsgSizeErr <- struct{}{}:
					default:
					}
				}
			}
			e.buf.Release()
			select {
			case h.available <- struct{}{}:
			default:
			}
		}
	}
}

func (h *sendQueue) Close() {
	close(h.closeCalled)
	// wait until the run loop returned
	<-h.runStopped
}
