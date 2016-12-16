package quic

import (
	"bytes"
	"errors"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

// A Client of QUIC
type Client struct {
	addr     *net.UDPAddr
	conn     *net.UDPConn
	hostname string

	connectionID      protocol.ConnectionID
	version           protocol.VersionNumber
	versionNegotiated bool

	cryptoChangeCallback     CryptoChangeCallback
	versionNegotiateCallback VersionNegotiateCallback

	session packetHandler
}

// VersionNegotiateCallback is called once the client has a negotiated version
type VersionNegotiateCallback func() error

var errHostname = errors.New("Invalid hostname")

var (
	errCloseSessionForNewVersion = errors.New("closing session in order to recreate it with a new version")
	errInvalidVersionNegotiation = qerr.Error(qerr.InvalidVersionNegotiationPacket, "Server already supports client's version and should have accepted the connection.")
)

// NewClient makes a new client
func NewClient(addr string, cryptoChangeCallback CryptoChangeCallback, versionNegotiateCallback VersionNegotiateCallback) (*Client, error) {
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

	client := &Client{
		addr:                     udpAddr,
		conn:                     conn,
		hostname:                 hostname,
		version:                  protocol.SupportedVersions[len(protocol.SupportedVersions)-1], // use the highest supported version by default
		connectionID:             connectionID,
		cryptoChangeCallback:     cryptoChangeCallback,
		versionNegotiateCallback: versionNegotiateCallback,
	}

	utils.Infof("Starting new connection to %s (%s), connectionID %x, version %d", host, udpAddr.String(), connectionID, client.version)

	err = client.createNewSession()
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Listen listens
func (c *Client) Listen() error {
	for {
		data := getPacketBuffer()
		data = data[:protocol.MaxPacketSize]

		n, _, err := c.conn.ReadFromUDP(data)
		if err != nil {
			if strings.HasSuffix(err.Error(), "use of closed network connection") {
				return nil
			}
			return err
		}
		data = data[:n]

		err = c.handlePacket(data)
		if err != nil {
			utils.Errorf("error handling packet: %s", err.Error())
			c.session.Close(err)
			return err
		}
	}
}

// OpenStream opens a stream, for client-side created streams (i.e. odd streamIDs)
func (c *Client) OpenStream(id protocol.StreamID) (utils.Stream, error) {
	return c.session.OpenStream(id)
}

// Close closes the connection
func (c *Client) Close() error {
	_ = c.session.Close(nil)
	return c.conn.Close()
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

	// ignore delayed / duplicated version negotiation packets
	if c.versionNegotiated && hdr.VersionFlag {
		return nil
	}

	// this is the first packet after the client sent a packet with the VersionFlag set
	// if the server doesn't send a version negotiation packet, it supports the suggested version
	if !hdr.VersionFlag && !c.versionNegotiated {
		c.versionNegotiated = true
		err = c.versionNegotiateCallback()
		if err != nil {
			return err
		}
	}

	if hdr.VersionFlag {
		// check if the server sent the offered version in supported versions
		for _, v := range hdr.SupportedVersions {
			if v == c.version {
				return errInvalidVersionNegotiation
			}
		}

		ok, highestSupportedVersion := protocol.HighestSupportedVersion(hdr.SupportedVersions)
		if !ok {
			return qerr.VersionNegotiationMismatch
		}

		utils.Infof("Switching to QUIC version %d", highestSupportedVersion)
		c.version = highestSupportedVersion
		c.versionNegotiated = true

		c.session.Close(errCloseSessionForNewVersion)
		err = c.createNewSession()
		if err != nil {
			return err
		}
		err = c.versionNegotiateCallback()
		if err != nil {
			return err
		}

		return nil // version negotiation packets have no payload
	}

	c.session.handlePacket(&receivedPacket{
		remoteAddr:   c.addr,
		publicHeader: hdr,
		data:         packet[len(packet)-r.Len():],
		rcvTime:      rcvTime,
	})
	return nil
}

func (c *Client) createNewSession() error {
	var err error
	c.session, err = newClientSession(c.conn, c.addr, c.hostname, c.version, c.connectionID, c.streamCallback, c.closeCallback, c.cryptoChangeCallback)
	if err != nil {
		return err
	}

	go c.session.run()
	return nil
}

func (c *Client) streamCallback(session *Session, stream utils.Stream) {}

func (c *Client) closeCallback(id protocol.ConnectionID) {
	utils.Infof("Connection %x closed.", id)
}
