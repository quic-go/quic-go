package quic

import (
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// The packetHandlerMap stores packetHandlers, identified by connection ID.
// It is used:
// * by the server to store sessions
// * when multiplexing outgoing connections to store clients
type packetHandlerMap struct {
	mutex sync.RWMutex

	handlers map[string] /* string(ConnectionID)*/ packetHandler
	closed   bool

	deleteClosedSessionsAfter time.Duration
}

var _ packetHandlerManager = &packetHandlerMap{}

func newPacketHandlerMap() packetHandlerManager {
	return &packetHandlerMap{
		handlers:                  make(map[string]packetHandler),
		deleteClosedSessionsAfter: protocol.ClosedSessionDeleteTimeout,
	}
}

func (h *packetHandlerMap) Get(id protocol.ConnectionID) (packetHandler, bool) {
	h.mutex.RLock()
	sess, ok := h.handlers[string(id)]
	h.mutex.RUnlock()
	return sess, ok
}

func (h *packetHandlerMap) Add(id protocol.ConnectionID, handler packetHandler) {
	h.mutex.Lock()
	h.handlers[string(id)] = handler
	h.mutex.Unlock()
}

func (h *packetHandlerMap) Remove(id protocol.ConnectionID) {
	h.mutex.Lock()
	h.handlers[string(id)] = nil
	h.mutex.Unlock()

	time.AfterFunc(h.deleteClosedSessionsAfter, func() {
		h.mutex.Lock()
		delete(h.handlers, string(id))
		h.mutex.Unlock()
	})
}

func (h *packetHandlerMap) Close() error {
	h.mutex.Lock()
	if h.closed {
		h.mutex.Unlock()
		return nil
	}
	h.closed = true

	var wg sync.WaitGroup
	for _, handler := range h.handlers {
		if handler != nil {
			wg.Add(1)
			go func(handler packetHandler) {
				// session.Close() blocks until the CONNECTION_CLOSE has been sent and the run-loop has stopped
				_ = handler.Close()
				wg.Done()
			}(handler)
		}
	}
	h.mutex.Unlock()
	wg.Wait()
	return nil
}
