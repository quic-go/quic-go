package quic

import (
	"sync"
)

const sendQueueCapacity = 10

type sendQueue struct {
	mutex sync.Mutex

	queue     chan *packedPacket
	closeChan chan struct{}
	conn      connection

	available chan struct{}
	blocked   bool
}

func newSendQueue(conn connection) (*sendQueue, <-chan struct{}) {
	s := &sendQueue{
		conn:      conn,
		closeChan: make(chan struct{}),
		queue:     make(chan *packedPacket, sendQueueCapacity),
		available: make(chan struct{}, 1),
	}
	return s, s.available
}

// CanSend returns if a packet can be enqueued.
func (h *sendQueue) CanSend() bool {
	canSend := len(h.queue) < cap(h.queue)
	if !canSend {
		h.mutex.Lock()
		h.blocked = true
		h.mutex.Unlock()
	}
	return canSend
}

func (h *sendQueue) Send(p *packedPacket) {
	select {
	case h.queue <- p:
	default:
		panic("send would have blocked")
	}
}

func (h *sendQueue) Run() error {
	var p *packedPacket
	for {
		select {
		case <-h.closeChan:
			return nil
		case p = <-h.queue:
			if err := h.sendPacket(p); err != nil {
				return err
			}
		}
	}
}

func (h *sendQueue) sendPacket(p *packedPacket) error {
	if len(h.queue) == cap(h.queue)-1 {
		// If CanSend() indicated to the session that we're blocked, we need to unblock the session.
		h.mutex.Lock()
		if h.blocked {
			select {
			case h.available <- struct{}{}:
			default:
			}
			h.blocked = false
		}
		h.mutex.Unlock()
	}

	if err := h.conn.Write(p.raw); err != nil {
		return err
	}
	p.buffer.Release()
	return nil
}

func (h *sendQueue) Close() {
	close(h.closeChan)
}
