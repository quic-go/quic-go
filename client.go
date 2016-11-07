package quic

import (
	"bytes"
	"math/rand"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

// A Client of QUIC
type Client struct {
	addr *net.UDPAddr
	conn *net.UDPConn

	connectionID protocol.ConnectionID
	version      protocol.VersionNumber

	session *Session
}

// NewClient makes a new client
func NewClient(addr *net.UDPAddr) (*Client, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}

	// TODO: generate cryptographically secure random ConnectionID
	rand.Seed(time.Now().UTC().UnixNano())
	connectionID := protocol.ConnectionID(rand.Int63())

	client := &Client{
		addr:         addr,
		conn:         conn,
		version:      protocol.Version36,
		connectionID: connectionID,
	}

	streamCallback := func(session *Session, stream utils.Stream) {}

	client.session, err = newClientSession(conn, addr, client.version, client.connectionID, streamCallback, client.closeCallback)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Listen listens
func (c *Client) Listen() {
	go c.session.run()

	for {
		data := getPacketBuffer()
		data = data[:protocol.MaxPacketSize]

		n, _, err := c.conn.ReadFromUDP(data)
		utils.Debugf("%d", n)
		if err != nil {
			panic(err)
		}
		data = data[:n]

		err = c.handlePacket(data)
		if err != nil {
			utils.Errorf("error handling packet: %s", err.Error())
		}
	}
}

func (c *Client) handlePacket(packet []byte) error {
	if protocol.ByteCount(len(packet)) > protocol.MaxPacketSize {
		return qerr.PacketTooLarge
	}

	rcvTime := time.Now()

	r := bytes.NewReader(packet)

	hdr, err := ParsePublicHeader(r, protocol.PerspectiveServer)
	if err != nil {
		return qerr.Error(qerr.InvalidPacketHeader, err.Error())
	}
	hdr.Raw = packet[:len(packet)-r.Len()]

	c.session.handlePacket(&receivedPacket{
		remoteAddr:   c.addr,
		publicHeader: hdr,
		data:         packet[len(packet)-r.Len():],
		rcvTime:      rcvTime,
	})
	return nil
}

func (c *Client) closeCallback(id protocol.ConnectionID) {
	utils.Infof("Connection %x closed.", id)
	c.conn.Close()
}
