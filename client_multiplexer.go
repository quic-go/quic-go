package quic

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

var (
	clientMuxerOnce sync.Once
	clientMuxer     *clientMultiplexer
)

// The clientMultiplexer listens on multiple net.PacketConns and dispatches
// incoming packets to the session handler.
type clientMultiplexer struct {
	mutex sync.Mutex

	conns                   map[net.PacketConn]packetHandlerManager
	newPacketHandlerManager func() packetHandlerManager // so it can be replaced in the tests

	logger utils.Logger
}

func getClientMultiplexer() *clientMultiplexer {
	clientMuxerOnce.Do(func() {
		clientMuxer = &clientMultiplexer{
			conns:                   make(map[net.PacketConn]packetHandlerManager),
			logger:                  utils.DefaultLogger.WithPrefix("client muxer"),
			newPacketHandlerManager: newPacketHandlerMap,
		}
	})
	return clientMuxer
}

func (m *clientMultiplexer) AddConn(c net.PacketConn) packetHandlerManager {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	sessions, ok := m.conns[c]
	if !ok {
		sessions = m.newPacketHandlerManager()
		m.conns[c] = sessions
		// If we didn't know this packet conn before, listen for incoming packets
		// and dispatch them to the right sessions.
		go m.listen(c, sessions)
	}
	return sessions
}

func (m *clientMultiplexer) AddHandler(c net.PacketConn, connID protocol.ConnectionID, handler packetHandler) error {
	sessions, ok := m.conns[c]
	if !ok {
		return errors.New("unknown packet conn %s")
	}
	sessions.Add(connID, handler)
	return nil
}

func (m *clientMultiplexer) listen(c net.PacketConn, sessions packetHandlerManager) {
	for {
		data := *getPacketBuffer()
		data = data[:protocol.MaxReceivePacketSize]
		// The packet size should not exceed protocol.MaxReceivePacketSize bytes
		// If it does, we only read a truncated packet, which will then end up undecryptable
		n, addr, err := c.ReadFrom(data)
		if err != nil {
			if !strings.HasSuffix(err.Error(), "use of closed network connection") {
				sessions.Close(err)
			}
			return
		}
		data = data[:n]
		rcvTime := time.Now()

		r := bytes.NewReader(data)
		iHdr, err := wire.ParseInvariantHeader(r)
		// drop the packet if we can't parse the header
		if err != nil {
			m.logger.Debugf("error parsing invariant header from %s: %s", addr, err)
			continue
		}
		client, ok := sessions.Get(iHdr.DestConnectionID)
		if !ok {
			m.logger.Debugf("received a packet with an unexpected connection ID %s", iHdr.DestConnectionID)
			continue
		}
		if client == nil {
			// Late packet for closed session
			continue
		}
		hdr, err := iHdr.Parse(r, protocol.PerspectiveServer, client.GetVersion())
		if err != nil {
			m.logger.Debugf("error parsing header from %s: %s", addr, err)
			continue
		}
		hdr.Raw = data[:len(data)-r.Len()]
		packetData := data[len(data)-r.Len():]

		client.handlePacket(&receivedPacket{
			remoteAddr: addr,
			header:     hdr,
			data:       packetData,
			rcvTime:    rcvTime,
		})
	}
}
