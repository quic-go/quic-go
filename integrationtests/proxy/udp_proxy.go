package proxy

import (
	"bytes"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/protocol"
)

// Connection is a UDP connection
type connection struct {
	ClientAddr *net.UDPAddr // Address of the client
	ServerConn *net.UDPConn // UDP connection to server

	incomingPacketCounter uint64
	outgoingPacketCounter uint64
}

// DropCallback is a callback that determines which packet gets dropped
type DropCallback func(protocol.PacketNumber) bool

// UDPProxy is a UDP proxy
type UDPProxy struct {
	serverAddr *net.UDPAddr
	mutex      sync.Mutex

	proxyConn          *net.UDPConn
	dropIncomingPacket DropCallback
	dropOutgoingPacket DropCallback
	rttGen             rttGenerator

	// Mapping from client addresses (as host:port) to connection
	clientDict map[string]*connection
}

// NewUDPProxy creates a new UDP proxy
func NewUDPProxy(proxyPort int, serverAddress string, serverPort int, dropIncomingPacket, dropOutgoingPacket DropCallback, rttMin time.Duration, rttMax time.Duration) (*UDPProxy, error) {
	dontDrop := func(p protocol.PacketNumber) bool {
		return false
	}

	if dropIncomingPacket == nil {
		dropIncomingPacket = dontDrop
	}
	if dropOutgoingPacket == nil {
		dropOutgoingPacket = dontDrop
	}

	p := UDPProxy{
		clientDict:         make(map[string]*connection),
		dropIncomingPacket: dropIncomingPacket,
		dropOutgoingPacket: dropOutgoingPacket,
		rttGen:             newRttGenerator(rttMin, rttMax),
	}

	saddr, err := net.ResolveUDPAddr("udp", ":"+strconv.Itoa(proxyPort))
	if err != nil {
		return nil, err
	}
	pudp, err := net.ListenUDP("udp", saddr)
	if err != nil {
		return nil, err
	}
	p.proxyConn = pudp

	srvaddr, err := net.ResolveUDPAddr("udp", serverAddress+":"+strconv.Itoa(serverPort))
	if err != nil {
		return nil, err
	}
	p.serverAddr = srvaddr

	go p.runProxy()

	return &p, nil
}

// Stop stops the UDP Proxy
func (p *UDPProxy) Stop() {
	p.proxyConn.Close()
}

func (p *UDPProxy) newConnection(cliAddr *net.UDPAddr) (*connection, error) {
	var conn connection
	conn.ClientAddr = cliAddr
	srvudp, err := net.DialUDP("udp", nil, p.serverAddr)
	if err != nil {
		return nil, err
	}
	conn.ServerConn = srvudp
	return &conn, nil
}

// runProxy handles inputs to Proxy port
func (p *UDPProxy) runProxy() error {
	for {
		buffer := make([]byte, 1500)
		n, cliaddr, err := p.proxyConn.ReadFromUDP(buffer[0:])
		if err != nil {
			return err
		}

		saddr := cliaddr.String()

		p.mutex.Lock()
		conn, ok := p.clientDict[saddr]

		if !ok {
			conn, err = p.newConnection(cliaddr)
			if err != nil {
				p.mutex.Unlock()
				return err
			}
			p.clientDict[saddr] = conn
			p.mutex.Unlock()
			go p.runConnection(conn)
		} else {
			p.mutex.Unlock()
		}

		atomic.AddUint64(&conn.incomingPacketCounter, 1)

		raw := buffer[0:n]
		r := bytes.NewReader(raw)
		hdr, err := quic.ParsePublicHeader(r, protocol.PerspectiveClient)
		if err != nil {
			return err
		}

		if !p.dropIncomingPacket(hdr.PacketNumber) {
			// Relay to server
			go func() {
				time.Sleep(p.rttGen.getRTT() / 2)
				conn.ServerConn.Write(raw)
			}()
		}
	}
}

// runConnection handles packets from server to a single client
func (p *UDPProxy) runConnection(conn *connection) error {
	for {
		buffer := make([]byte, 1500)
		n, err := conn.ServerConn.Read(buffer[0:])
		if err != nil {
			return err
		}

		raw := buffer[0:n]

		// TODO: Switch back to using the public header once Chrome properly sets the type byte.
		// r := bytes.NewReader(raw)
		// , err := quic.ParsePublicHeader(r, protocol.PerspectiveServer)
		// if err != nil {
		// return err
		// }

		v := atomic.AddUint64(&conn.outgoingPacketCounter, 1)

		if !p.dropOutgoingPacket(protocol.PacketNumber(v)) {
			// Relay it to client
			go func() {
				time.Sleep(p.rttGen.getRTT() / 2)
				p.proxyConn.WriteToUDP(raw, conn.ClientAddr)
			}()
		}
	}
}
