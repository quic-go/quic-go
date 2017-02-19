package quic

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

// A Client of QUIC
type Client struct {
	conn     connection
	hostname string

	connectionID      protocol.ConnectionID
	version           protocol.VersionNumber
	versionNegotiated bool
	closed            uint32 // atomic bool

	tlsConfig                *tls.Config
	cryptoChangeCallback     CryptoChangeCallback
	versionNegotiateCallback VersionNegotiateCallback

	session packetHandler
}

// VersionNegotiateCallback is called once the client has a negotiated version
type VersionNegotiateCallback func() error

var errHostname = errors.New("Invalid hostname")

var (
	errCloseSessionForNewVersion = errors.New("closing session in order to recreate it with a new version")
)

// NewClient makes a new client
func NewClient(host string, tlsConfig *tls.Config, cryptoChangeCallback CryptoChangeCallback, versionNegotiateCallback VersionNegotiateCallback) (*Client, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}

	connectionID, err := utils.GenerateConnectionID()
	if err != nil {
		return nil, err
	}

	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return nil, err
	}

	client := &Client{
		conn:                     &conn{pconn: udpConn, currentAddr: udpAddr},
		hostname:                 hostname,
		version:                  protocol.SupportedVersions[len(protocol.SupportedVersions)-1], // use the highest supported version by default
		connectionID:             connectionID,
		tlsConfig:                tlsConfig,
		cryptoChangeCallback:     cryptoChangeCallback,
		versionNegotiateCallback: versionNegotiateCallback,
	}

	utils.Infof("Starting new connection to %s (%s), connectionID %x, version %d", host, udpAddr.String(), connectionID, client.version)

	err = client.createNewSession(nil)
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

		n, addr, err := c.conn.Read(data)
		if err != nil {
			if strings.HasSuffix(err.Error(), "use of closed network connection") {
				return nil
			}
			return err
		}
		data = data[:n]

		err = c.handlePacket(addr, data)
		if err != nil {
			utils.Errorf("error handling packet: %s", err.Error())
			c.session.Close(err)
			return err
		}
	}
}

// OpenStream opens a stream, for client-side created streams (i.e. odd streamIDs)
func (c *Client) OpenStream() (utils.Stream, error) {
	return c.session.OpenStream()
}

// Close closes the connection
func (c *Client) Close(e error) error {
	// Only close once
	if !atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return nil
	}

	_ = c.session.Close(e)
	return c.conn.Close()
}

func (c *Client) handlePacket(remoteAddr net.Addr, packet []byte) error {
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
		var hasCommonVersion bool // check if we're supporting any of the offered versions
		for _, v := range hdr.SupportedVersions {
			// check if the server sent the offered version in supported versions
			if v == c.version {
				return qerr.Error(qerr.InvalidVersionNegotiationPacket, "Server already supports client's version and should have accepted the connection.")
			}
			if v != protocol.VersionUnsupported {
				hasCommonVersion = true
			}
		}
		if !hasCommonVersion {
			utils.Infof("No common version found.")
			return qerr.InvalidVersion
		}

		ok, highestSupportedVersion := protocol.HighestSupportedVersion(hdr.SupportedVersions)
		if !ok {
			return qerr.VersionNegotiationMismatch
		}

		// switch to negotiated version
		c.version = highestSupportedVersion
		c.versionNegotiated = true
		c.connectionID, err = utils.GenerateConnectionID()
		if err != nil {
			return err
		}
		utils.Infof("Switching to QUIC version %d. New connection ID: %x", highestSupportedVersion, c.connectionID)

		c.session.Close(errCloseSessionForNewVersion)
		err = c.createNewSession(hdr.SupportedVersions)
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
		remoteAddr:   remoteAddr,
		publicHeader: hdr,
		data:         packet[len(packet)-r.Len():],
		rcvTime:      rcvTime,
	})
	return nil
}

func (c *Client) createNewSession(negotiatedVersions []protocol.VersionNumber) error {
	var err error
	c.session, err = newClientSession(
		c.conn,
		c.hostname,
		c.version,
		c.connectionID,
		c.tlsConfig,
		c.closeCallback,
		c.cryptoChangeCallback,
		negotiatedVersions)
	if err != nil {
		return err
	}

	go c.session.run()
	return nil
}

func (c *Client) closeCallback(id protocol.ConnectionID) {
	utils.Infof("Connection %x closed.", id)
}
