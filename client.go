package quic

import (
	"bytes"
	"errors"
	"math/rand"
	"net"
	"net/url"
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

var errHostname = errors.New("Invalid hostname")

// NewClient makes a new client
func NewClient(addr string) (*Client, error) {
	hostname, err := utils.HostnameFromAddr(addr)
	if err != nil || len(hostname) == 0 {
		return nil, errHostname
	}

	p, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	host := p.Host

	udpAddr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}

	// TODO: generate cryptographically secure random ConnectionID
	rand.Seed(time.Now().UTC().UnixNano())
	connectionID := protocol.ConnectionID(rand.Int63())

	utils.Infof("Starting new connection to %s (%s), connectionID %x", host, udpAddr.String(), connectionID)

	client := &Client{
		addr:         udpAddr,
		conn:         conn,
		version:      protocol.Version36,
		connectionID: connectionID,
	}

	streamCallback := func(session *Session, stream utils.Stream) {}

	client.session, err = newClientSession(conn, udpAddr, hostname, client.version, client.connectionID, streamCallback, client.closeCallback)
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
