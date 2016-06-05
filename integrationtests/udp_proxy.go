package integrationtests

import (
	"net"
	"strconv"
	"sync"
)

// Connection is a UDP connection
type connection struct {
	ClientAddr *net.UDPAddr // Address of the client
	ServerConn *net.UDPConn // UDP connection to server

	incomingPacketCounter packetNumber
	outgoingPacketCounter packetNumber
}

type packetNumber uint64
type dropCallback func(packetNumber) bool

// UDPProxy is a UDP proxy
type UDPProxy struct {
	serverAddr *net.UDPAddr
	mutex      sync.Mutex

	proxyConn          *net.UDPConn
	dropIncomingPacket dropCallback
	dropOutgoingPacket dropCallback

	// Mapping from client addresses (as host:port) to connection
	clientDict map[string]*connection
}

// NewUDPProxy creates a new UDP proxy
func NewUDPProxy(proxyPort int, serverAddress string, serverPort int, dropIncomingPacket, dropOutgoingPacket dropCallback) (*UDPProxy, error) {
	dontDrop := func(p packetNumber) bool {
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
	buffer := make([]byte, 1500)

	for {
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

		conn.incomingPacketCounter++

		if !p.dropIncomingPacket(conn.incomingPacketCounter) {
			// Relay to server
			_, err = conn.ServerConn.Write(buffer[0:n])
			if err != nil {
				return err
			}
		}
	}
}

// runConnection handles packets from server to a single client
func (p *UDPProxy) runConnection(conn *connection) error {
	buffer := make([]byte, 1500)

	for {
		n, err := conn.ServerConn.Read(buffer[0:])
		if err != nil {
			return err
		}

		conn.outgoingPacketCounter++

		if !p.dropOutgoingPacket(conn.outgoingPacketCounter) {
			// Relay it to client
			_, err = p.proxyConn.WriteToUDP(buffer[0:n], conn.ClientAddr)
			if err != nil {
				return err
			}
		}
	}
}
