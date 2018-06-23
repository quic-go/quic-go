package quic

import (
	"bytes"
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

	conns map[net.PacketConn]packetHandlerManager

	logger utils.Logger
}

func getClientMultiplexer() *clientMultiplexer {
	clientMuxerOnce.Do(func() {
		clientMuxer = &clientMultiplexer{
			conns:  make(map[net.PacketConn]packetHandlerManager),
			logger: utils.DefaultLogger.WithPrefix("client muxer"),
		}
	})
	return clientMuxer
}

func (m *clientMultiplexer) Add(c net.PacketConn, connID protocol.ConnectionID, handler packetHandler) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	sessions, ok := m.conns[c]
	if !ok {
		sessions = newPacketHandlerMap()
		m.conns[c] = sessions
	}
	sessions.Add(connID, handler)
	if ok {
		return
	}

	// If we didn't know this packet conn before, listen for incoming packets
	// and dispatch them to the right sessions.
	go m.listen(c, sessions)
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
		hdr, err := wire.ParseHeaderSentByServer(r)
		// drop the packet if we can't parse the header
		if err != nil {
			m.logger.Debugf("error parsing packet from %s: %s", addr, err)
			continue
		}
		hdr.Raw = data[:len(data)-r.Len()]
		packetData := data[len(data)-r.Len():]

		client, ok := sessions.Get(hdr.DestConnectionID)
		if !ok {
			m.logger.Debugf("received a packet with an unexpected connection ID %s", hdr.DestConnectionID)
			continue
		}
		client.handlePacket(&receivedPacket{
			remoteAddr: addr,
			header:     hdr,
			data:       packetData,
			rcvTime:    rcvTime,
		})
	}
}
