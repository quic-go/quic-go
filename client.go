package quic

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type client struct {
	mutex               sync.Mutex
	connStateChangeCond sync.Cond

	conn     connection
	hostname string

	config *Config

	connectionID      protocol.ConnectionID
	version           protocol.VersionNumber
	versionNegotiated bool
	closed            uint32 // atomic bool

	tlsConfig            *tls.Config
	cryptoChangeCallback CryptoChangeCallback

	session packetHandler
}

var errHostname = errors.New("Invalid hostname")

var (
	errCloseSessionForNewVersion = errors.New("closing session in order to recreate it with a new version")
)

// Dial establishes a new QUIC connection to a server
func Dial(pconn net.PacketConn, remoteAddr net.Addr, host string, config *Config) (Session, error) {
	connID, err := utils.GenerateConnectionID()
	if err != nil {
		return nil, err
	}

	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return nil, err
	}

	c := &client{
		conn:         &conn{pconn: pconn, currentAddr: remoteAddr},
		connectionID: connID,
		hostname:     hostname,
		config:       config,
		version:      protocol.SupportedVersions[len(protocol.SupportedVersions)-1], // use the highest supported version by default
	}

	c.connStateChangeCond.L = &c.mutex

	c.cryptoChangeCallback = func(isForwardSecure bool) {
		var state ConnState
		if isForwardSecure {
			state = ConnStateForwardSecure
		} else {
			state = ConnStateSecure
		}

		if c.config.ConnState != nil {
			go config.ConnState(c.session, state)
		}
	}

	err = c.createNewSession(nil)
	if err != nil {
		return nil, err
	}

	utils.Infof("Starting new connection to %s (%s), connectionID %x, version %d", hostname, c.conn.RemoteAddr().String(), c.connectionID, c.version)

	// TODO: handle errors
	go c.Listen()

	c.mutex.Lock()
	for !c.versionNegotiated {
		c.connStateChangeCond.Wait()
	}
	c.mutex.Unlock()

	return c.session, nil
}

// DialAddr establishes a new QUIC connection to a server
func DialAddr(hostname string, config *Config) (Session, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", hostname)
	if err != nil {
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}

	return Dial(udpConn, udpAddr, hostname, config)
}

// Listen listens
func (c *client) Listen() error {
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

// Close closes the connection
func (c *client) Close(e error) error {
	// Only close once
	if !atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return nil
	}

	_ = c.session.Close(e)
	return c.conn.Close()
}

func (c *client) handlePacket(remoteAddr net.Addr, packet []byte) error {
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
		c.mutex.Lock()
		c.versionNegotiated = true
		c.connStateChangeCond.Signal()
		c.mutex.Unlock()
		if c.config.ConnState != nil {
			go c.config.ConnState(c.session, ConnStateVersionNegotiated)
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
		if c.config.ConnState != nil {
			go c.config.ConnState(c.session, ConnStateVersionNegotiated)
		}
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

func (c *client) createNewSession(negotiatedVersions []protocol.VersionNumber) error {
	var err error
	c.session, err = newClientSession(
		c.conn,
		c.hostname,
		c.version,
		c.connectionID,
		c.config.TLSConfig,
		c.closeCallback,
		c.cryptoChangeCallback,
		negotiatedVersions)
	if err != nil {
		return err
	}

	go c.session.run()
	return nil
}

func (c *client) closeCallback(id protocol.ConnectionID) {
	utils.Infof("Connection %x closed.", id)
}
