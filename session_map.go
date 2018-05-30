package quic

import (
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type sessionMap struct {
	mutex sync.RWMutex

	sessions map[string] /* string(ConnectionID)*/ packetHandler
	closed   bool

	deleteClosedSessionsAfter time.Duration
}

var _ sessionHandler = &sessionMap{}

func newSessionMap() sessionHandler {
	return &sessionMap{
		sessions:                  make(map[string]packetHandler),
		deleteClosedSessionsAfter: protocol.ClosedSessionDeleteTimeout,
	}
}

func (h *sessionMap) Get(id protocol.ConnectionID) (packetHandler, bool) {
	h.mutex.RLock()
	sess, ok := h.sessions[string(id)]
	h.mutex.RUnlock()
	return sess, ok
}

func (h *sessionMap) Add(id protocol.ConnectionID, sess packetHandler) {
	h.mutex.Lock()
	h.sessions[string(id)] = sess
	h.mutex.Unlock()
}

func (h *sessionMap) Remove(id protocol.ConnectionID) {
	h.mutex.Lock()
	h.sessions[string(id)] = nil
	h.mutex.Unlock()

	time.AfterFunc(h.deleteClosedSessionsAfter, func() {
		h.mutex.Lock()
		delete(h.sessions, string(id))
		h.mutex.Unlock()
	})
}

func (h *sessionMap) Close() {
	h.mutex.Lock()
	if h.closed {
		h.mutex.Unlock()
		return
	}
	h.closed = true

	var wg sync.WaitGroup
	for _, session := range h.sessions {
		if session != nil {
			wg.Add(1)
			go func(sess packetHandler) {
				// session.Close() blocks until the CONNECTION_CLOSE has been sent and the run-loop has stopped
				_ = sess.Close(nil)
				wg.Done()
			}(session)
		}
	}
	h.mutex.Unlock()
	wg.Wait()
}
