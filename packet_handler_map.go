package quic

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type packetHandlerEntry struct {
	handler    packetHandler
	resetToken *[16]byte
}

// The packetHandlerMap stores packetHandlers, identified by connection ID.
// It is used:
// * by the server to store sessions
// * when multiplexing outgoing connections to store clients
type packetHandlerMap struct {
	mutex sync.RWMutex

	conn      net.PacketConn
	connIDLen int

	handlers    map[string] /* string(ConnectionID)*/ packetHandlerEntry
	resetTokens map[[16]byte] /* stateless reset token */ packetHandler
	server      unknownPacketHandler

	listening chan struct{} // is closed when listen returns
	closed    bool

	deleteRetiredSessionsAfter time.Duration

	logger utils.Logger
}

var _ packetHandlerManager = &packetHandlerMap{}

func newPacketHandlerMap(conn net.PacketConn, connIDLen int, logger utils.Logger) packetHandlerManager {
	m := &packetHandlerMap{
		conn:                       conn,
		connIDLen:                  connIDLen,
		listening:                  make(chan struct{}),
		handlers:                   make(map[string]packetHandlerEntry),
		resetTokens:                make(map[[16]byte]packetHandler),
		deleteRetiredSessionsAfter: protocol.RetiredConnectionIDDeleteTimeout,
		logger:                     logger,
	}
	go m.listen()
	return m
}

func (h *packetHandlerMap) Add(id protocol.ConnectionID, handler packetHandler) {
	h.mutex.Lock()
	h.handlers[string(id)] = packetHandlerEntry{handler: handler}
	h.mutex.Unlock()
}

func (h *packetHandlerMap) AddWithResetToken(id protocol.ConnectionID, handler packetHandler, token [16]byte) {
	h.mutex.Lock()
	h.handlers[string(id)] = packetHandlerEntry{handler: handler, resetToken: &token}
	h.resetTokens[token] = handler
	h.mutex.Unlock()
}

func (h *packetHandlerMap) Remove(id protocol.ConnectionID) {
	h.removeByConnectionIDAsString(string(id))
}

func (h *packetHandlerMap) removeByConnectionIDAsString(id string) {
	h.mutex.Lock()
	if handlerEntry, ok := h.handlers[id]; ok {
		if token := handlerEntry.resetToken; token != nil {
			delete(h.resetTokens, *token)
		}
		delete(h.handlers, id)
	}
	h.mutex.Unlock()
}

func (h *packetHandlerMap) Retire(id protocol.ConnectionID) {
	h.retireByConnectionIDAsString(string(id))
}

func (h *packetHandlerMap) retireByConnectionIDAsString(id string) {
	time.AfterFunc(h.deleteRetiredSessionsAfter, func() {
		h.removeByConnectionIDAsString(id)
	})
}

func (h *packetHandlerMap) SetServer(s unknownPacketHandler) {
	h.mutex.Lock()
	h.server = s
	h.mutex.Unlock()
}

func (h *packetHandlerMap) CloseServer() {
	h.mutex.Lock()
	h.server = nil
	var wg sync.WaitGroup
	for id, handlerEntry := range h.handlers {
		handler := handlerEntry.handler
		if handler.getPerspective() == protocol.PerspectiveServer {
			wg.Add(1)
			go func(id string, handler packetHandler) {
				// session.Close() blocks until the CONNECTION_CLOSE has been sent and the run-loop has stopped
				_ = handler.Close()
				h.retireByConnectionIDAsString(id)
				wg.Done()
			}(id, handler)
		}
	}
	h.mutex.Unlock()
	wg.Wait()
}

// Close the underlying connection and wait until listen() has returned.
func (h *packetHandlerMap) Close() error {
	if err := h.conn.Close(); err != nil {
		return err
	}
	<-h.listening // wait until listening returns
	return nil
}

func (h *packetHandlerMap) close(e error) error {
	h.mutex.Lock()
	if h.closed {
		h.mutex.Unlock()
		return nil
	}
	h.closed = true

	var wg sync.WaitGroup
	for _, handlerEntry := range h.handlers {
		wg.Add(1)
		go func(handlerEntry packetHandlerEntry) {
			handlerEntry.handler.destroy(e)
			wg.Done()
		}(handlerEntry)
	}

	if h.server != nil {
		h.server.closeWithError(e)
	}
	h.mutex.Unlock()
	wg.Wait()
	return getMultiplexer().RemoveConn(h.conn)
}

func (h *packetHandlerMap) listen() {
	defer close(h.listening)
	for {
		buffer := getPacketBuffer()
		data := buffer.Slice
		// The packet size should not exceed protocol.MaxReceivePacketSize bytes
		// If it does, we only read a truncated packet, which will then end up undecryptable
		n, addr, err := h.conn.ReadFrom(data)
		if err != nil {
			h.close(err)
			return
		}
		h.handlePacket(addr, buffer, data[:n])
	}
}

func (h *packetHandlerMap) handlePacket(
	addr net.Addr,
	buffer *packetBuffer,
	data []byte,
) {
	connID, err := wire.ParseConnectionID(data, h.connIDLen)
	if err != nil {
		h.logger.Debugf("error parsing connection ID on packet from %s: %s", addr, err)
		return
	}
	rcvTime := time.Now()

	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if isStatelessReset := h.maybeHandleStatelessReset(data); isStatelessReset {
		return
	}

	handlerEntry, handlerFound := h.handlers[string(connID)]

	p := &receivedPacket{
		remoteAddr: addr,
		rcvTime:    rcvTime,
		buffer:     buffer,
		data:       data,
	}
	if handlerFound { // existing session
		handlerEntry.handler.handlePacket(p)
		return
	}
	if data[0]&0x80 == 0 {
		// TODO(#943): send a stateless reset
		h.logger.Debugf("received a short header packet with an unexpected connection ID %s", connID)
		return
	}
	if h.server == nil { // no server set
		h.logger.Debugf("received a packet with an unexpected connection ID %s", connID)
		return
	}
	h.server.handlePacket(p)
}

func (h *packetHandlerMap) maybeHandleStatelessReset(data []byte) bool {
	// stateless resets are always short header packets
	if data[0]&0x80 != 0 {
		return false
	}
	if len(data) < protocol.MinStatelessResetSize {
		return false
	}

	var token [16]byte
	copy(token[:], data[len(data)-16:])
	if sess, ok := h.resetTokens[token]; ok {
		sess.destroy(errors.New("received a stateless reset"))
		return true
	}
	return false
}
