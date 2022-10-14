package quic

type sender interface {
	Send(p *packetBuffer)
	Run() error
	WouldBlock() bool
	Available() <-chan struct{}
	Close()
}

type sendQueue struct {
	conn sendConn

	queue       chan *packetBuffer
	closeCalled chan struct{} // runStopped when Close() is called
	runStopped  chan struct{} // runStopped when the run loop returns
	available   chan struct{}

	packetBuf []*packetBuffer
	byteBuf   [][]byte
}

var _ sender = &sendQueue{}

const (
	sendQueueCapacity = 8
	writeBatchSize    = 8
)

func newSendQueue(conn sendConn) sender {
	return &sendQueue{
		conn:        conn,
		runStopped:  make(chan struct{}),
		closeCalled: make(chan struct{}),
		available:   make(chan struct{}, 1),
		queue:       make(chan *packetBuffer, sendQueueCapacity),
		packetBuf:   make([]*packetBuffer, 0, writeBatchSize),
		byteBuf:     make([][]byte, 0, writeBatchSize),
	}
}

// Send sends out a packet. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise Send will panic.
func (h *sendQueue) Send(p *packetBuffer) {
	select {
	case h.queue <- p:
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
		case p := <-h.queue:
			h.packetBuf = append(h.packetBuf, p)
			h.byteBuf = append(h.byteBuf, p.Data)
			for len(h.queue) > 0 {
				select {
				case p = <-h.queue:
				default:
					panic("would have blocked")
				}
				h.packetBuf = append(h.packetBuf, p)
				h.byteBuf = append(h.byteBuf, p.Data)
				if len(h.packetBuf) == cap(h.packetBuf) {
					break
				}
			}

			if err := h.conn.WritePackets(h.byteBuf); err != nil {
				// This additional check enables:
				// 1. Checking for "datagram too large" message from the kernel, as such,
				// 2. Path MTU discovery,and
				// 3. Eventual detection of loss PingFrame.
				if !isMsgSizeErr(err) {
					h.packetBuf = h.packetBuf[:0]
					h.byteBuf = h.byteBuf[:0]
					return err
				}
			}

			for _, p := range h.packetBuf {
				p.Release()
			}
			h.packetBuf = h.packetBuf[:0]
			h.byteBuf = h.byteBuf[:0]

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
