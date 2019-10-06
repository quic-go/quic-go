package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/wire"
)

type datagramQueue struct {
	mutex sync.Mutex
	queue chan *wire.DatagramFrame

	closeErr error
	closed   chan struct{}

	hasData func()
}

func newDatagramQueue(hasData func()) *datagramQueue {
	return &datagramQueue{
		queue:   make(chan *wire.DatagramFrame),
		hasData: hasData,
		closed:  make(chan struct{}),
	}
}

// AddAndWait queues a new DATAGRAM frame.
// It blocks until the frame has been dequeued.
func (h *datagramQueue) AddAndWait(f *wire.DatagramFrame) error {
	h.hasData()
	select {
	case h.queue <- f:
		return nil
	case <-h.closed:
		return h.closeErr
	}
}

func (h *datagramQueue) Get() *wire.DatagramFrame {
	select {
	case f := <-h.queue:
		return f
	default:
		return nil
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.closeErr = e
	close(h.closed)
}
