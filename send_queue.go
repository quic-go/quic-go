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
	CloseAndDiscard()
}

type queueEntry struct {
	buf     *packetBuffer
	gsoSize uint16
	ecn     protocol.ECN
}

type sendQueue struct {
	queue       chan queueEntry
	closeCalled chan struct{} // closed when Close or CloseAndDiscard is called
	runStopped  chan struct{} // runStopped when the run loop returns
	available   chan struct{}
	conn        sendConn
	discard     bool // written before closeCalled is closed, which publishes it to Run
}

var _ sender = &sendQueue{}

const sendQueueCapacity = 8

func newSendQueue(conn sendConn) sender {
	return &sendQueue{
		conn:        conn,
		runStopped:  make(chan struct{}),
		closeCalled: make(chan struct{}),
		available:   make(chan struct{}, 1),
		queue:       make(chan queueEntry, sendQueueCapacity),
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
		if shouldClose {
			if h.discard {
				for {
					select {
					case e := <-h.queue:
						e.buf.Release()
					default:
						return nil
					}
				}
			}
			if len(h.queue) == 0 {
				return nil
			}
		}
		// Handle a pending close before picking up another packet: once a
		// discarding close is seen, nothing further is written. At most one
		// packet the blocking select below has already picked up can still go
		// out, and both closes wait for the run loop, so nothing is written
		// after they return.
		select {
		case <-h.closeCalled:
			h.closeCalled = nil
			shouldClose = true
			continue
		default:
		}
		select {
		case <-h.closeCalled:
			h.closeCalled = nil // prevent this case from being selected again
			// for a plain Close, all queued packets are still sent out; a
			// discarding close is handled at the top of the loop
			shouldClose = true
		case e := <-h.queue:
			if err := h.conn.Write(e.buf.Data, e.gsoSize, e.ecn); err != nil {
				// This additional check enables:
				// 1. Checking for "datagram too large" message from the kernel, as such,
				// 2. Path MTU discovery,and
				// 3. Eventual detection of loss PingFrame.
				if !isSendMsgSizeErr(err) {
					return err
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

// CloseAndDiscard stops the run loop, dropping any packets still queued.
// It is for leaving a path behind: what is queued was packed for a path the
// connection is no longer using, so to the peer a dropped packet is ordinary
// loss, and loss recovery repacks its frames for the path in use now.
func (h *sendQueue) CloseAndDiscard() {
	h.discard = true
	close(h.closeCalled)
	// wait until the run loop returned
	<-h.runStopped
}
