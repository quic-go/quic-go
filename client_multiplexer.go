package quic

import (
	"bytes"
	"errors"
	"fmt"
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
	clientMuxer     multiplexer
)

type multiplexer interface {
	AddConn(net.PacketConn, int) (packetHandlerManager, error)
	AddHandler(net.PacketConn, protocol.ConnectionID, packetHandler) error
}

type connManager struct {
	connIDLen int
	manager   packetHandlerManager
}

// The clientMultiplexer listens on multiple net.PacketConns and dispatches
// incoming packets to the session handler.
type clientMultiplexer struct {
	mutex sync.Mutex

	conns                   map[net.PacketConn]connManager
	newPacketHandlerManager func() packetHandlerManager // so it can be replaced in the tests

	logger utils.Logger
}

var _ multiplexer = &clientMultiplexer{}

func getClientMultiplexer() multiplexer {
	clientMuxerOnce.Do(func() {
		clientMuxer = &clientMultiplexer{
			conns:                   make(map[net.PacketConn]connManager),
			logger:                  utils.DefaultLogger.WithPrefix("client muxer"),
			newPacketHandlerManager: newPacketHandlerMap,
		}
	})
	return clientMuxer
}

func (m *clientMultiplexer) AddConn(c net.PacketConn, connIDLen int) (packetHandlerManager, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	p, ok := m.conns[c]
	if !ok {
		manager := m.newPacketHandlerManager()
		p = connManager{connIDLen: connIDLen, manager: manager}
		m.conns[c] = p
		// If we didn't know this packet conn before, listen for incoming packets
		// and dispatch them to the right sessions.
		go m.listen(c, &p)
	}
	if p.connIDLen != connIDLen {
		return nil, fmt.Errorf("cannot use %d byte connection IDs on a connection that is already using %d byte connction IDs", connIDLen, p.connIDLen)
	}
	return p.manager, nil
}

func (m *clientMultiplexer) AddHandler(c net.PacketConn, connID protocol.ConnectionID, handler packetHandler) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	p, ok := m.conns[c]
	if !ok {
		return errors.New("unknown packet conn %s")
	}
	p.manager.Add(connID, handler)
	return nil
}

func (m *clientMultiplexer) listen(c net.PacketConn, p *connManager) {
	for {
		data := *getPacketBuffer()
		data = data[:protocol.MaxReceivePacketSize]
		// The packet size should not exceed protocol.MaxReceivePacketSize bytes
		// If it does, we only read a truncated packet, which will then end up undecryptable
		n, addr, err := c.ReadFrom(data)
		if err != nil {
			if !strings.HasSuffix(err.Error(), "use of closed network connection") {
				p.manager.Close()
			}
			return
		}
		data = data[:n]

		if err := m.handlePacket(addr, data, p); err != nil {
			m.logger.Debugf("error handling packet from %s: %s", addr, err)
		}
	}
}

func (m *clientMultiplexer) handlePacket(addr net.Addr, data []byte, p *connManager) error {
	rcvTime := time.Now()

	r := bytes.NewReader(data)
	iHdr, err := wire.ParseInvariantHeader(r, p.connIDLen)
	// drop the packet if we can't parse the header
	if err != nil {
		return fmt.Errorf("error parsing invariant header: %s", err)
	}
	client, ok := p.manager.Get(iHdr.DestConnectionID)
	if !ok {
		return fmt.Errorf("received a packet with an unexpected connection ID %s", iHdr.DestConnectionID)
	}
	if client == nil {
		// Late packet for closed session
		return nil
	}
	hdr, err := iHdr.Parse(r, protocol.PerspectiveServer, client.GetVersion())
	if err != nil {
		return fmt.Errorf("error parsing header: %s", err)
	}
	hdr.Raw = data[:len(data)-r.Len()]
	packetData := data[len(data)-r.Len():]

	client.handlePacket(&receivedPacket{
		remoteAddr: addr,
		header:     hdr,
		data:       packetData,
		rcvTime:    rcvTime,
	})
	return nil
}
