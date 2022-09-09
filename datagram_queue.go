package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type datagramQueue struct {
	mx            sync.Mutex
	nextFrameSize protocol.ByteCount

	sendQueue chan *wire.DatagramFrame
	rcvQueue  chan []byte

	closeErr error
	closed   chan struct{}

	hasData func()

	dequeued chan struct{}

	logger  utils.Logger
	version protocol.VersionNumber
}

func newDatagramQueue(hasData func(), logger utils.Logger, v protocol.VersionNumber) *datagramQueue {
	return &datagramQueue{
		hasData:       hasData,
		sendQueue:     make(chan *wire.DatagramFrame, 1),
		nextFrameSize: protocol.InvalidByteCount,
		rcvQueue:      make(chan []byte, protocol.DatagramRcvQueueLen),
		dequeued:      make(chan struct{}),
		closed:        make(chan struct{}),
		logger:        logger,
		version:       v,
	}
}

// AddAndWait queues a new DATAGRAM frame for sending.
// It blocks until the frame has been dequeued.
func (h *datagramQueue) AddAndWait(f *wire.DatagramFrame) error {
	select {
	case h.sendQueue <- f:
		h.mx.Lock()
		h.nextFrameSize = f.Length(h.version)
		h.mx.Unlock()
		h.hasData()
	case <-h.closed:
		return h.closeErr
	}

	select {
	case <-h.dequeued:
		return nil
	case <-h.closed:
		return h.closeErr
	}
}

// Get dequeues a DATAGRAM frame for sending.
func (h *datagramQueue) Get() *wire.DatagramFrame {
	select {
	case f := <-h.sendQueue:
		h.mx.Lock()
		h.nextFrameSize = protocol.InvalidByteCount
		h.mx.Unlock()
		h.dequeued <- struct{}{}
		return f
	default:
		return nil
	}
}

func (h *datagramQueue) NextFrameSize() protocol.ByteCount {
	h.mx.Lock()
	defer h.mx.Unlock()
	return h.nextFrameSize
}

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	data := make([]byte, len(f.Data))
	copy(data, f.Data)
	select {
	case h.rcvQueue <- data:
	default:
		h.logger.Debugf("Discarding DATAGRAM frame (%d bytes payload)", len(f.Data))
	}
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive() ([]byte, error) {
	select {
	case data := <-h.rcvQueue:
		return data, nil
	case <-h.closed:
		return nil, h.closeErr
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.closeErr = e
	close(h.closed)
}
