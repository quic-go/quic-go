package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type client struct {
	mutex sync.Mutex

	conn     connection
	hostname string

	receivedRetry bool

	versionNegotiated                bool // has the server accepted our version
	receivedVersionNegotiationPacket bool
	negotiatedVersions               []protocol.VersionNumber // the list of versions from the version negotiation packet

	tlsConf *tls.Config
	config  *Config
	tls     handshake.MintTLS // only used when using TLS

	srcConnID  protocol.ConnectionID
	destConnID protocol.ConnectionID

	initialVersion protocol.VersionNumber
	version        protocol.VersionNumber

	handshakeChan chan struct{}

	session quicSession

	logger utils.Logger
}

var _ packetHandler = &client{}

var (
	// make it possible to mock connection ID generation in the tests
	generateConnectionID         = protocol.GenerateConnectionID
	errCloseSessionForNewVersion = errors.New("closing session in order to recreate it with a new version")
)

// DialAddr establishes a new QUIC connection to a server.
// The hostname for SNI is taken from the given address.
func DialAddr(
	addr string,
	tlsConf *tls.Config,
	config *Config,
) (Session, error) {
	return DialAddrContext(context.Background(), addr, tlsConf, config)
}

// DialAddrContext establishes a new QUIC connection to a server using the provided context.
// The hostname for SNI is taken from the given address.
func DialAddrContext(
	ctx context.Context,
	addr string,
	tlsConf *tls.Config,
	config *Config,
) (Session, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	c, err := newClient(udpConn, udpAddr, config, tlsConf, addr)
	if err != nil {
		return nil, err
	}
	go c.listen()
	if err := c.dial(ctx); err != nil {
		return nil, err
	}
	return c.session, nil
}

// Dial establishes a new QUIC connection to a server using a net.PacketConn.
// The host parameter is used for SNI.
func Dial(
	pconn net.PacketConn,
	remoteAddr net.Addr,
	host string,
	tlsConf *tls.Config,
	config *Config,
) (Session, error) {
	return DialContext(context.Background(), pconn, remoteAddr, host, tlsConf, config)
}

// DialContext establishes a new QUIC connection to a server using a net.PacketConn using the provided context.
// The host parameter is used for SNI.
func DialContext(
	ctx context.Context,
	pconn net.PacketConn,
	remoteAddr net.Addr,
	host string,
	tlsConf *tls.Config,
	config *Config,
) (Session, error) {
	c, err := newClient(pconn, remoteAddr, config, tlsConf, host)
	if err != nil {
		return nil, err
	}
	getClientMultiplexer().Add(pconn, c.srcConnID, c)
	if err := c.dial(ctx); err != nil {
		return nil, err
	}
	return c.session, nil
}

func newClient(pconn net.PacketConn, remoteAddr net.Addr, config *Config, tlsConf *tls.Config, host string) (*client, error) {
	clientConfig := populateClientConfig(config)
	version := clientConfig.Versions[0]
	srcConnID, err := generateConnectionID()
	if err != nil {
		return nil, err
	}
	destConnID := srcConnID
	if version.UsesTLS() {
		destConnID, err = generateConnectionID()
		if err != nil {
			return nil, err
		}
	}

	var hostname string
	if tlsConf != nil {
		hostname = tlsConf.ServerName
	}
	if hostname == "" {
		hostname, _, err = net.SplitHostPort(host)
		if err != nil {
			return nil, err
		}
	}

	// check that all versions are actually supported
	if config != nil {
		for _, v := range config.Versions {
			if !protocol.IsValidVersion(v) {
				return nil, fmt.Errorf("%s is not a valid QUIC version", v)
			}
		}
	}
	return &client{
		conn:          &conn{pconn: pconn, currentAddr: remoteAddr},
		srcConnID:     srcConnID,
		destConnID:    destConnID,
		hostname:      hostname,
		tlsConf:       tlsConf,
		config:        clientConfig,
		version:       version,
		handshakeChan: make(chan struct{}),
		logger:        utils.DefaultLogger.WithPrefix("client"),
	}, nil
}

// populateClientConfig populates fields in the quic.Config with their default values, if none are set
// it may be called with nil
func populateClientConfig(config *Config) *Config {
	if config == nil {
		config = &Config{}
	}
	versions := config.Versions
	if len(versions) == 0 {
		versions = protocol.SupportedVersions
	}

	handshakeTimeout := protocol.DefaultHandshakeTimeout
	if config.HandshakeTimeout != 0 {
		handshakeTimeout = config.HandshakeTimeout
	}
	idleTimeout := protocol.DefaultIdleTimeout
	if config.IdleTimeout != 0 {
		idleTimeout = config.IdleTimeout
	}

	maxReceiveStreamFlowControlWindow := config.MaxReceiveStreamFlowControlWindow
	if maxReceiveStreamFlowControlWindow == 0 {
		maxReceiveStreamFlowControlWindow = protocol.DefaultMaxReceiveStreamFlowControlWindowClient
	}
	maxReceiveConnectionFlowControlWindow := config.MaxReceiveConnectionFlowControlWindow
	if maxReceiveConnectionFlowControlWindow == 0 {
		maxReceiveConnectionFlowControlWindow = protocol.DefaultMaxReceiveConnectionFlowControlWindowClient
	}
	maxIncomingStreams := config.MaxIncomingStreams
	if maxIncomingStreams == 0 {
		maxIncomingStreams = protocol.DefaultMaxIncomingStreams
	} else if maxIncomingStreams < 0 {
		maxIncomingStreams = 0
	}
	maxIncomingUniStreams := config.MaxIncomingUniStreams
	if maxIncomingUniStreams == 0 {
		maxIncomingUniStreams = protocol.DefaultMaxIncomingUniStreams
	} else if maxIncomingUniStreams < 0 {
		maxIncomingUniStreams = 0
	}

	return &Config{
		Versions:                              versions,
		HandshakeTimeout:                      handshakeTimeout,
		IdleTimeout:                           idleTimeout,
		RequestConnectionIDOmission:           config.RequestConnectionIDOmission,
		MaxReceiveStreamFlowControlWindow:     maxReceiveStreamFlowControlWindow,
		MaxReceiveConnectionFlowControlWindow: maxReceiveConnectionFlowControlWindow,
		MaxIncomingStreams:                    maxIncomingStreams,
		MaxIncomingUniStreams:                 maxIncomingUniStreams,
		KeepAlive:                             config.KeepAlive,
	}
}

func (c *client) dial(ctx context.Context) error {
	c.logger.Infof("Starting new connection to %s (%s -> %s), source connection ID %s, destination connection ID %s, version %s", c.hostname, c.conn.LocalAddr(), c.conn.RemoteAddr(), c.srcConnID, c.destConnID, c.version)

	var err error
	if c.version.UsesTLS() {
		err = c.dialTLS(ctx)
	} else {
		err = c.dialGQUIC(ctx)
	}
	if err == errCloseSessionForNewVersion {
		return c.dial(ctx)
	}
	return err
}

func (c *client) dialGQUIC(ctx context.Context) error {
	if err := c.createNewGQUICSession(); err != nil {
		return err
	}
	return c.establishSecureConnection(ctx)
}

func (c *client) dialTLS(ctx context.Context) error {
	params := &handshake.TransportParameters{
		StreamFlowControlWindow:     protocol.ReceiveStreamFlowControlWindow,
		ConnectionFlowControlWindow: protocol.ReceiveConnectionFlowControlWindow,
		IdleTimeout:                 c.config.IdleTimeout,
		OmitConnectionID:            c.config.RequestConnectionIDOmission,
		MaxBidiStreams:              uint16(c.config.MaxIncomingStreams),
		MaxUniStreams:               uint16(c.config.MaxIncomingUniStreams),
	}
	csc := handshake.NewCryptoStreamConn(nil)
	extHandler := handshake.NewExtensionHandlerClient(params, c.initialVersion, c.config.Versions, c.version, c.logger)
	mintConf, err := tlsToMintConfig(c.tlsConf, protocol.PerspectiveClient)
	if err != nil {
		return err
	}
	mintConf.ExtensionHandler = extHandler
	mintConf.ServerName = c.hostname
	c.tls = newMintController(csc, mintConf, protocol.PerspectiveClient)

	if err := c.createNewTLSSession(extHandler.GetPeerParams(), c.version); err != nil {
		return err
	}
	if err := c.establishSecureConnection(ctx); err != nil {
		if err != handshake.ErrCloseSessionForRetry {
			return err
		}
		c.logger.Infof("Received a Retry packet. Recreating session.")
		c.mutex.Lock()
		c.receivedRetry = true
		c.mutex.Unlock()
		if err := c.createNewTLSSession(extHandler.GetPeerParams(), c.version); err != nil {
			return err
		}
		if err := c.establishSecureConnection(ctx); err != nil {
			return err
		}
	}
	return nil
}

// establishSecureConnection runs the session, and tries to establish a secure connection
// It returns:
// - errCloseSessionForNewVersion when the server sends a version negotiation packet
// - handshake.ErrCloseSessionForRetry when the server performs a stateless retry (for IETF QUIC)
// - any other error that might occur
// - when the connection is secure (for gQUIC), or forward-secure (for IETF QUIC)
func (c *client) establishSecureConnection(ctx context.Context) error {
	errorChan := make(chan error, 1)

	go func() {
		err := c.session.run() // returns as soon as the session is closed
		errorChan <- err
	}()

	select {
	case <-ctx.Done():
		// The session sending a PeerGoingAway error to the server.
		c.session.Close(nil)
		return ctx.Err()
	case err := <-errorChan:
		return err
	case <-c.handshakeChan:
		// handshake successfully completed
		return nil
	}
}

// Listen listens on the underlying connection and passes packets on for handling.
// It returns when the connection is closed.
func (c *client) listen() {
	var err error

	for {
		var n int
		var addr net.Addr
		data := *getPacketBuffer()
		data = data[:protocol.MaxReceivePacketSize]
		// The packet size should not exceed protocol.MaxReceivePacketSize bytes
		// If it does, we only read a truncated packet, which will then end up undecryptable
		n, addr, err = c.conn.Read(data)
		if err != nil {
			if !strings.HasSuffix(err.Error(), "use of closed network connection") {
				c.mutex.Lock()
				if c.session != nil {
					c.session.Close(err)
				}
				c.mutex.Unlock()
			}
			break
		}
		c.handleRead(addr, data[:n])
	}
}

func (c *client) handleRead(remoteAddr net.Addr, packet []byte) {
	rcvTime := time.Now()

	r := bytes.NewReader(packet)
	hdr, err := wire.ParseHeaderSentByServer(r)
	// drop the packet if we can't parse the header
	if err != nil {
		c.logger.Errorf("error handling packet: %s", err)
		return
	}
	hdr.Raw = packet[:len(packet)-r.Len()]
	packetData := packet[len(packet)-r.Len():]
	c.handlePacket(&receivedPacket{
		remoteAddr: remoteAddr,
		header:     hdr,
		data:       packetData,
		rcvTime:    rcvTime,
	})
}

func (c *client) handlePacket(p *receivedPacket) {
	if err := c.handlePacketImpl(p); err != nil {
		c.logger.Errorf("error handling packet: %s", err)
	}
}

func (c *client) handlePacketImpl(p *receivedPacket) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// handle Version Negotiation Packets
	if p.header.IsVersionNegotiation {
		// ignore delayed / duplicated version negotiation packets
		if c.receivedVersionNegotiationPacket || c.versionNegotiated {
			return errors.New("received a delayed Version Negotiation Packet")
		}

		// version negotiation packets have no payload
		if err := c.handleVersionNegotiationPacket(p.header); err != nil {
			c.session.Close(err)
		}
		return nil
	}

	if p.header.IsPublicHeader {
		return c.handleGQUICPacket(p)
	}
	return c.handleIETFQUICPacket(p)
}

func (c *client) handleIETFQUICPacket(p *receivedPacket) error {
	// reject packets with the wrong connection ID
	if !p.header.DestConnectionID.Equal(c.srcConnID) {
		return fmt.Errorf("received a packet with an unexpected connection ID (%s, expected %s)", p.header.DestConnectionID, c.srcConnID)
	}
	if p.header.IsLongHeader {
		switch p.header.Type {
		case protocol.PacketTypeRetry:
			if c.receivedRetry {
				return nil
			}
		case protocol.PacketTypeHandshake:
		default:
			return fmt.Errorf("Received unsupported packet type: %s", p.header.Type)
		}
		if protocol.ByteCount(len(p.data)) < p.header.PayloadLen {
			return fmt.Errorf("packet payload (%d bytes) is smaller than the expected payload length (%d bytes)", len(p.data), p.header.PayloadLen)
		}
		p.data = p.data[:int(p.header.PayloadLen)]
		// TODO(#1312): implement parsing of compound packets
	}

	// this is the first packet we are receiving
	// since it is not a Version Negotiation Packet, this means the server supports the suggested version
	if !c.versionNegotiated {
		c.versionNegotiated = true
	}

	c.session.handlePacket(p)
	return nil
}

func (c *client) handleGQUICPacket(p *receivedPacket) error {
	connID := p.header.DestConnectionID
	// reject packets with truncated connection id if we didn't request truncation
	if !c.config.RequestConnectionIDOmission && connID.Len() == 0 {
		return errors.New("received packet with truncated connection ID, but didn't request truncation")
	}
	// reject packets with the wrong connection ID
	if connID.Len() > 0 && !connID.Equal(c.srcConnID) {
		return fmt.Errorf("received a packet with an unexpected connection ID (%s, expected %s)", connID, c.srcConnID)
	}

	if p.header.ResetFlag {
		cr := c.conn.RemoteAddr()
		// check if the remote address and the connection ID match
		// otherwise this might be an attacker trying to inject a PUBLIC_RESET to kill the connection
		if cr.Network() != p.remoteAddr.Network() || cr.String() != p.remoteAddr.String() || !connID.Equal(c.srcConnID) {
			return errors.New("Received a spoofed Public Reset")
		}
		pr, err := wire.ParsePublicReset(bytes.NewReader(p.data))
		if err != nil {
			return fmt.Errorf("Received a Public Reset. An error occurred parsing the packet: %s", err)
		}
		c.session.closeRemote(qerr.Error(qerr.PublicReset, fmt.Sprintf("Received a Public Reset for packet number %#x", pr.RejectedPacketNumber)))
		c.logger.Infof("Received Public Reset, rejected packet number: %#x", pr.RejectedPacketNumber)
		return nil
	}

	// this is the first packet we are receiving
	// since it is not a Version Negotiation Packet, this means the server supports the suggested version
	if !c.versionNegotiated {
		c.versionNegotiated = true
	}

	c.session.handlePacket(p)
	return nil
}

func (c *client) handleVersionNegotiationPacket(hdr *wire.Header) error {
	for _, v := range hdr.SupportedVersions {
		if v == c.version {
			// the version negotiation packet contains the version that we offered
			// this might be a packet sent by an attacker (or by a terribly broken server implementation)
			// ignore it
			return nil
		}
	}

	c.logger.Infof("Received a Version Negotiation Packet. Supported Versions: %s", hdr.SupportedVersions)

	newVersion, ok := protocol.ChooseSupportedVersion(c.config.Versions, hdr.SupportedVersions)
	if !ok {
		return qerr.InvalidVersion
	}
	c.receivedVersionNegotiationPacket = true
	c.negotiatedVersions = hdr.SupportedVersions

	// switch to negotiated version
	c.initialVersion = c.version
	c.version = newVersion
	var err error
	c.destConnID, err = generateConnectionID()
	if err != nil {
		return err
	}
	// in gQUIC, there's only one connection ID
	if !c.version.UsesTLS() {
		c.srcConnID = c.destConnID
	}
	c.logger.Infof("Switching to QUIC version %s. New connection ID: %s", newVersion, c.destConnID)
	c.session.Close(errCloseSessionForNewVersion)
	return nil
}

func (c *client) createNewGQUICSession() (err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	runner := &runner{
		onHandshakeCompleteImpl: func(_ Session) { close(c.handshakeChan) },
		removeConnectionIDImpl:  func(protocol.ConnectionID) {},
	}
	c.session, err = newClientSession(
		c.conn,
		runner,
		c.hostname,
		c.version,
		c.destConnID,
		c.tlsConf,
		c.config,
		c.initialVersion,
		c.negotiatedVersions,
		c.logger,
	)
	return err
}

func (c *client) createNewTLSSession(
	paramsChan <-chan handshake.TransportParameters,
	version protocol.VersionNumber,
) (err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	runner := &runner{
		onHandshakeCompleteImpl: func(_ Session) { close(c.handshakeChan) },
		removeConnectionIDImpl:  func(protocol.ConnectionID) {},
	}
	c.session, err = newTLSClientSession(
		c.conn,
		runner,
		c.hostname,
		c.version,
		c.destConnID,
		c.srcConnID,
		c.config,
		c.tls,
		paramsChan,
		1,
		c.logger,
	)
	return err
}

func (c *client) Close(err error) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.session == nil {
		return nil
	}
	return c.session.Close(err)
}
