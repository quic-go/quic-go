package quic

import (
	"context"
	"fmt"
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

var (
	dropDatagramCtxCancelledErr = fmt.Errorf("Dropped datagram due to context cancelled")
)

type datagramQueue struct {
	sendQueue chan *queuedDatagramFrame
	nextFrame *queuedDatagramFrame

	rcvMx    sync.Mutex
	rcvQueue [][]byte
	rcvd     chan struct{} // used to notify Receive that a new datagram was received

	closeErr error
	closed   chan struct{}

	hasData func()

	dequeued chan error

	logger utils.Logger
}

type queuedDatagramFrame struct {
	cancelChan <-chan struct{}
	frame      *wire.DatagramFrame
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	return &datagramQueue{
		hasData:   hasData,
		sendQueue: make(chan *queuedDatagramFrame, 1),
		rcvd:      make(chan struct{}, 1),
		dequeued:  make(chan error),
		closed:    make(chan struct{}),
		logger:    logger,
	}
}

// AddAndWait queues a new DATAGRAM frame for sending.
// It blocks until the frame has been dequeued.
func (h *datagramQueue) AddAndWait(f *wire.DatagramFrame) error {
	frame := &queuedDatagramFrame{
		cancelChan: ctx.Done(),
		frame:      f,
	}

	select {
	case <-ctx.Done():
		return dropDatagramCtxCancelledErr
	case h.sendQueue <- frame:
		h.hasData()
	case <-h.closed:
		return h.closeErr
	}

	select {
	case err := <-h.dequeued:
		return err
	case <-h.closed:
		return h.closeErr
	}
}

// Peek gets the next DATAGRAM frame for sending.
// If actually sent out, Pop needs to be called before the next call to Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	if h.nextFrame != nil {
		return h.dequeueNextFrame()
	}
	select {
	case h.nextFrame = <-h.sendQueue:
		return h.dequeueNextFrame()
	default:
		return nil
	}
}

func (h *datagramQueue) dequeueNextFrame() *wire.DatagramFrame {
	h.nextFrame.peekCount++
	if h.nextFrame.peekCount > maxPeekAttempt {
		h.Pop(&DatagramQueuedTooLong{})
		return nil
	default:
		return h.nextFrame.frame
	}
}

func (h *datagramQueue) Pop(err error) {
	if h.nextFrame == nil {
		panic("datagramQueue BUG: Pop called for nil frame")
	}
	h.nextFrame = nil
	h.dequeued <- err
}

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	data := make([]byte, len(f.Data))
	copy(data, f.Data)
	var queued bool
	h.rcvMx.Lock()
	if len(h.rcvQueue) < protocol.DatagramRcvQueueLen {
		h.rcvQueue = append(h.rcvQueue, data)
		queued = true
		select {
		case h.rcvd <- struct{}{}:
		default:
		}
	}
	h.rcvMx.Unlock()
	if !queued && h.logger.Debug() {
		h.logger.Debugf("Discarding DATAGRAM frame (%d bytes payload)", len(f.Data))
	}
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
	for {
		h.rcvMx.Lock()
		if len(h.rcvQueue) > 0 {
			data := h.rcvQueue[0]
			h.rcvQueue = h.rcvQueue[1:]
			h.rcvMx.Unlock()
			return data, nil
		}
		h.rcvMx.Unlock()
		select {
		case <-h.rcvd:
			continue
		case <-h.closed:
			return nil, h.closeErr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.closeErr = e
	close(h.closed)
}
