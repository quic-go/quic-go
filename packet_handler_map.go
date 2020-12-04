package quic

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"log"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/logging"
)

type statelessResetErr struct {
	token protocol.StatelessResetToken
}

func (e statelessResetErr) Error() string {
	return fmt.Sprintf("received a stateless reset with token %x", e.token)
}

// The packetHandlerMap stores packetHandlers, identified by connection ID.
// It is used:
// * by the server to store sessions
// * when multiplexing outgoing connections to store clients
type packetHandlerMap struct {
	mutex sync.Mutex

	conn      connection
	connIDLen int

	handlers    map[string] /* string(ConnectionID)*/ packetHandler
	resetTokens map[protocol.StatelessResetToken] /* stateless reset token */ packetHandler
	server      unknownPacketHandler

	listening chan struct{} // is closed when listen returns
	closed    bool

	deleteRetiredSessionsAfter time.Duration

	statelessResetEnabled bool
	statelessResetMutex   sync.Mutex
	statelessResetHasher  hash.Hash

	tracer logging.Tracer
	logger utils.Logger
}

var _ packetHandlerManager = &packetHandlerMap{}

func setReceiveBuffer(c net.PacketConn, logger utils.Logger) error {
	conn, ok := c.(interface{ SetReadBuffer(int) error })
	if !ok {
		return errors.New("connection doesn't allow setting of receive buffer size")
	}
	size, err := inspectReadBuffer(c)
	if err != nil {
		return fmt.Errorf("failed to determine receive buffer size: %w", err)
	}
	if size >= protocol.DesiredReceiveBufferSize {
		logger.Debugf("Conn has receive buffer of %d kiB (wanted: at least %d kiB)", size/1024, protocol.DesiredReceiveBufferSize/1024)
	}
	if err := conn.SetReadBuffer(protocol.DesiredReceiveBufferSize); err != nil {
		return fmt.Errorf("failed to increase receive buffer size: %w", err)
	}
	newSize, err := inspectReadBuffer(c)
	if err != nil {
		return fmt.Errorf("failed to determine receive buffer size: %w", err)
	}
	if newSize == size {
		return fmt.Errorf("failed to determine receive buffer size: %w", err)
	}
	if newSize < protocol.DesiredReceiveBufferSize {
		return fmt.Errorf("failed to sufficiently increase receive buffer size (was: %d kiB, wanted: %d kiB, got: %d kiB)", size/1024, protocol.DesiredReceiveBufferSize/1024, newSize/1024)
	}
	logger.Debugf("Increased receive buffer size to %d kiB", newSize/1024)
	return nil
}

// only print warnings about the UPD receive buffer size once
var receiveBufferWarningOnce sync.Once

func newPacketHandlerMap(
	c net.PacketConn,
	connIDLen int,
	statelessResetKey []byte,
	tracer logging.Tracer,
	logger utils.Logger,
) (packetHandlerManager, error) {
	if err := setReceiveBuffer(c, logger); err != nil {
		receiveBufferWarningOnce.Do(func() {
			log.Printf("%s. See https://github.com/lucas-clemente/quic-go/wiki/UDP-Receive-Buffer-Size for details.", err)
		})
	}
	conn, err := wrapConn(c)
	if err != nil {
		return nil, err
	}
	m := &packetHandlerMap{
		conn:                       conn,
		connIDLen:                  connIDLen,
		listening:                  make(chan struct{}),
		handlers:                   make(map[string]packetHandler),
		resetTokens:                make(map[protocol.StatelessResetToken]packetHandler),
		deleteRetiredSessionsAfter: protocol.RetiredConnectionIDDeleteTimeout,
		statelessResetEnabled:      len(statelessResetKey) > 0,
		statelessResetHasher:       hmac.New(sha256.New, statelessResetKey),
		tracer:                     tracer,
		logger:                     logger,
	}
	go m.listen()

	if logger.Debug() {
		go m.logUsage()
	}
	return m, nil
}

func (h *packetHandlerMap) logUsage() {
	ticker := time.NewTicker(2 * time.Second)
	var printedZero bool
	for {
		select {
		case <-h.listening:
			return
		case <-ticker.C:
		}

		h.mutex.Lock()
		numHandlers := len(h.handlers)
		numTokens := len(h.resetTokens)
		h.mutex.Unlock()
		// If the number tracked handlers and tokens is zero, only print it a single time.
		hasZero := numHandlers == 0 && numTokens == 0
		if !hasZero || (hasZero && !printedZero) {
			h.logger.Debugf("Tracking %d connection IDs and %d reset tokens.\n", numHandlers, numTokens)
			printedZero = false
			if hasZero {
				printedZero = true
			}
		}
	}
}

func (h *packetHandlerMap) Add(id protocol.ConnectionID, handler packetHandler) bool /* was added */ {
	sid := string(id)

	h.mutex.Lock()
	defer h.mutex.Unlock()

	if _, ok := h.handlers[sid]; ok {
		h.logger.Debugf("Not adding connection ID %s, as it already exists.", id)
		return false
	}
	h.handlers[sid] = handler
	h.logger.Debugf("Adding connection ID %s.", id)
	return true
}

func (h *packetHandlerMap) AddWithConnID(clientDestConnID, newConnID protocol.ConnectionID, fn func() packetHandler) bool {
	sid := string(clientDestConnID)
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if _, ok := h.handlers[sid]; ok {
		h.logger.Debugf("Not adding connection ID %s for a new session, as it already exists.", clientDestConnID)
		return false
	}

	sess := fn()
	h.handlers[sid] = sess
	h.handlers[string(newConnID)] = sess
	h.logger.Debugf("Adding connection IDs %s and %s for a new session.", clientDestConnID, newConnID)
	return true
}

func (h *packetHandlerMap) Remove(id protocol.ConnectionID) {
	h.mutex.Lock()
	delete(h.handlers, string(id))
	h.mutex.Unlock()
	h.logger.Debugf("Removing connection ID %s.", id)
}

func (h *packetHandlerMap) Retire(id protocol.ConnectionID) {
	h.logger.Debugf("Retiring connection ID %s in %s.", id, h.deleteRetiredSessionsAfter)
	time.AfterFunc(h.deleteRetiredSessionsAfter, func() {
		h.mutex.Lock()
		delete(h.handlers, string(id))
		h.mutex.Unlock()
		h.logger.Debugf("Removing connection ID %s after it has been retired.", id)
	})
}

func (h *packetHandlerMap) ReplaceWithClosed(id protocol.ConnectionID, handler packetHandler) {
	h.mutex.Lock()
	h.handlers[string(id)] = handler
	h.mutex.Unlock()
	h.logger.Debugf("Replacing session for connection ID %s with a closed session.", id)

	time.AfterFunc(h.deleteRetiredSessionsAfter, func() {
		h.mutex.Lock()
		handler.shutdown()
		delete(h.handlers, string(id))
		h.mutex.Unlock()
		h.logger.Debugf("Removing connection ID %s for a closed session after it has been retired.", id)
	})
}

func (h *packetHandlerMap) AddResetToken(token protocol.StatelessResetToken, handler packetHandler) {
	h.mutex.Lock()
	h.resetTokens[token] = handler
	h.mutex.Unlock()
}

func (h *packetHandlerMap) RemoveResetToken(token protocol.StatelessResetToken) {
	h.mutex.Lock()
	delete(h.resetTokens, token)
	h.mutex.Unlock()
}

func (h *packetHandlerMap) SetServer(s unknownPacketHandler) {
	h.mutex.Lock()
	h.server = s
	h.mutex.Unlock()
}

func (h *packetHandlerMap) CloseServer() {
	h.mutex.Lock()
	if h.server == nil {
		h.mutex.Unlock()
		return
	}
	h.server = nil
	var wg sync.WaitGroup
	for _, handler := range h.handlers {
		if handler.getPerspective() == protocol.PerspectiveServer {
			wg.Add(1)
			go func(handler packetHandler) {
				// blocks until the CONNECTION_CLOSE has been sent and the run-loop has stopped
				handler.shutdown()
				wg.Done()
			}(handler)
		}
	}
	h.mutex.Unlock()
	wg.Wait()
}

// Destroy the underlying connection and wait until listen() has returned.
// It does not close active sessions.
func (h *packetHandlerMap) Destroy() error {
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

	var wg sync.WaitGroup
	for _, handler := range h.handlers {
		wg.Add(1)
		go func(handler packetHandler) {
			handler.destroy(e)
			wg.Done()
		}(handler)
	}

	if h.server != nil {
		h.server.setCloseError(e)
	}
	h.closed = true
	h.mutex.Unlock()
	wg.Wait()
	return getMultiplexer().RemoveConn(h.conn)
}

func (h *packetHandlerMap) listen() {
	defer close(h.listening)
	for {
		p, err := h.conn.ReadPacket()
		if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
			h.logger.Debugf("Temporary error reading from conn: %w", err)
			continue
		}
		if err != nil {
			h.close(err)
			return
		}
		h.handlePacket(p)
	}
}

func (h *packetHandlerMap) handlePacket(p *receivedPacket) {
	connID, err := wire.ParseConnectionID(p.data, h.connIDLen)
	if err != nil {
		h.logger.Debugf("error parsing connection ID on packet from %s: %s", p.remoteAddr, err)
		if h.tracer != nil {
			h.tracer.DroppedPacket(p.remoteAddr, logging.PacketTypeNotDetermined, p.Size(), logging.PacketDropHeaderParseError)
		}
		p.buffer.MaybeRelease()
		return
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	if isStatelessReset := h.maybeHandleStatelessReset(p.data); isStatelessReset {
		return
	}

	if handler, ok := h.handlers[string(connID)]; ok { // existing session
		handler.handlePacket(p)
		return
	}
	if p.data[0]&0x80 == 0 {
		go h.maybeSendStatelessReset(p, connID)
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
	if len(data) < 17 /* type byte + 16 bytes for the reset token */ {
		return false
	}

	var token protocol.StatelessResetToken
	copy(token[:], data[len(data)-16:])
	if sess, ok := h.resetTokens[token]; ok {
		h.logger.Debugf("Received a stateless reset with token %#x. Closing session.", token)
		go sess.destroy(statelessResetErr{token: token})
		return true
	}
	return false
}

func (h *packetHandlerMap) GetStatelessResetToken(connID protocol.ConnectionID) protocol.StatelessResetToken {
	var token protocol.StatelessResetToken
	if !h.statelessResetEnabled {
		// Return a random stateless reset token.
		// This token will be sent in the server's transport parameters.
		// By using a random token, an off-path attacker won't be able to disrupt the connection.
		rand.Read(token[:])
		return token
	}
	h.statelessResetMutex.Lock()
	h.statelessResetHasher.Write(connID.Bytes())
	copy(token[:], h.statelessResetHasher.Sum(nil))
	h.statelessResetHasher.Reset()
	h.statelessResetMutex.Unlock()
	return token
}

func (h *packetHandlerMap) maybeSendStatelessReset(p *receivedPacket, connID protocol.ConnectionID) {
	defer p.buffer.Release()
	if !h.statelessResetEnabled {
		return
	}
	// Don't send a stateless reset in response to very small packets.
	// This includes packets that could be stateless resets.
	if len(p.data) <= protocol.MinStatelessResetSize {
		return
	}
	token := h.GetStatelessResetToken(connID)
	h.logger.Debugf("Sending stateless reset to %s (connection ID: %s). Token: %#x", p.remoteAddr, connID, token)
	data := make([]byte, protocol.MinStatelessResetSize-16, protocol.MinStatelessResetSize)
	rand.Read(data)
	data[0] = (data[0] & 0x7f) | 0x40
	data = append(data, token[:]...)
	if _, err := h.conn.WriteTo(data, p.remoteAddr); err != nil {
		h.logger.Debugf("Error sending Stateless Reset: %s", err)
	}
}
