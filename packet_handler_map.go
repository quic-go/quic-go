package quic

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// The packetHandlerMap stores packetHandlers, identified by connection ID.
// It is used:
// * by the server to store sessions
// * when multiplexing outgoing connections to store clients
type packetHandlerMap struct {
	mutex sync.RWMutex

	conn      net.PacketConn
	connIDLen int

	handlers map[string] /* string(ConnectionID)*/ packetHandler
	closed   bool

	deleteClosedSessionsAfter time.Duration

	logger utils.Logger
}

var _ packetHandlerManager = &packetHandlerMap{}

// TODO(#561): remove the listen flag
func newPacketHandlerMap(conn net.PacketConn, connIDLen int, logger utils.Logger, listen bool) packetHandlerManager {
	m := &packetHandlerMap{
		conn:                      conn,
		connIDLen:                 connIDLen,
		handlers:                  make(map[string]packetHandler),
		deleteClosedSessionsAfter: protocol.ClosedSessionDeleteTimeout,
		logger: logger,
	}
	if listen {
		go m.listen()
	}
	return m
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

func (h *packetHandlerMap) listen() {
	for {
		data := *getPacketBuffer()
		data = data[:protocol.MaxReceivePacketSize]
		// The packet size should not exceed protocol.MaxReceivePacketSize bytes
		// If it does, we only read a truncated packet, which will then end up undecryptable
		n, addr, err := h.conn.ReadFrom(data)
		if err != nil {
			if !strings.HasSuffix(err.Error(), "use of closed network connection") {
				h.Close()
			}
			return
		}
		data = data[:n]

		if err := h.handlePacket(addr, data); err != nil {
			h.logger.Debugf("error handling packet from %s: %s", addr, err)
		}
	}
}

func (h *packetHandlerMap) handlePacket(addr net.Addr, data []byte) error {
	rcvTime := time.Now()

	r := bytes.NewReader(data)
	iHdr, err := wire.ParseInvariantHeader(r, h.connIDLen)
	// drop the packet if we can't parse the header
	if err != nil {
		return fmt.Errorf("error parsing invariant header: %s", err)
	}
	handler, ok := h.Get(iHdr.DestConnectionID)
	if !ok {
		return fmt.Errorf("received a packet with an unexpected connection ID %s", iHdr.DestConnectionID)
	}
	if handler == nil {
		// Late packet for closed session
		return nil
	}
	hdr, err := iHdr.Parse(r, protocol.PerspectiveServer, handler.GetVersion())
	if err != nil {
		return fmt.Errorf("error parsing header: %s", err)
	}
	hdr.Raw = data[:len(data)-r.Len()]
	packetData := data[len(data)-r.Len():]

	if hdr.IsLongHeader {
		if protocol.ByteCount(len(packetData)) < hdr.PayloadLen {
			return fmt.Errorf("packet payload (%d bytes) is smaller than the expected payload length (%d bytes)", len(packetData), hdr.PayloadLen)
		}
		packetData = packetData[:int(hdr.PayloadLen)]
		// TODO(#1312): implement parsing of compound packets
	}

	handler.handlePacket(&receivedPacket{
		remoteAddr: addr,
		header:     hdr,
		data:       packetData,
		rcvTime:    rcvTime,
	})
	return nil
}
