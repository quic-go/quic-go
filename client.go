package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
)

type client struct {
	sconn sendConn
	// If the client is created with DialAddr, we create a packet conn.
	// If it is started with Dial, we take a packet conn as a parameter.
	createdPacketConn bool

	use0RTT bool

	packetHandlers packetHandlerManager

	tlsConf *tls.Config
	config  *Config

	srcConnID  protocol.ConnectionID
	destConnID protocol.ConnectionID

	initialPacketNumber  protocol.PacketNumber
	hasNegotiatedVersion bool
	version              protocol.VersionNumber

	handshakeChan chan struct{}

	conn quicConn

	tracer    logging.ConnectionTracer
	tracingID uint64
	logger    utils.Logger
}

// make it possible to mock connection ID for initial generation in the tests
var generateConnectionIDForInitial = protocol.GenerateConnectionIDForInitial

// DialAddr establishes a new QUIC connection to a server.
// It uses a new UDP connection and closes this connection when the QUIC connection is closed.
// The hostname for SNI is taken from the given address.
func DialAddr(ctx context.Context, addr string, tlsConf *tls.Config, config *Config) (Connection, error) {
	return dialAddrContext(ctx, addr, tlsConf, config, false)
}

// DialAddrEarly establishes a new 0-RTT QUIC connection to a server.
// It uses a new UDP connection and closes this connection when the QUIC connection is closed.
func DialAddrEarly(ctx context.Context, addr string, tlsConf *tls.Config, config *Config) (EarlyConnection, error) {
	conn, err := dialAddrContext(ctx, addr, tlsConf, config, true)
	if err != nil {
		return nil, err
	}
	utils.Logger.WithPrefix(utils.DefaultLogger, "client").Debugf("Returning early connection")
	return conn, nil
}

func dialAddrContext(ctx context.Context, addr string, tlsConf *tls.Config, config *Config, use0RTT bool) (quicConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	return dialContext(ctx, udpConn, udpAddr, tlsConf, config, use0RTT, true)
}

// Dial establishes a new QUIC connection to a server using a net.PacketConn. If
// the PacketConn satisfies the OOBCapablePacketConn interface (as a net.UDPConn
// does), ECN and packet info support will be enabled. In this case, ReadMsgUDP
// and WriteMsgUDP will be used instead of ReadFrom and WriteTo to read/write
// packets.
// The same PacketConn can be used for multiple calls to Dial and Listen.
// QUIC connection IDs are used for demultiplexing the different connections.
// The tls.Config must define an application protocol (using NextProtos).
func Dial(ctx context.Context, pconn net.PacketConn, addr net.Addr, tlsConf *tls.Config, config *Config) (Connection, error) {
	return dialContext(ctx, pconn, addr, tlsConf, config, false, false)
}

// DialEarly establishes a new 0-RTT QUIC connection to a server using a net.PacketConn.
// The same PacketConn can be used for multiple calls to Dial and Listen,
// QUIC connection IDs are used for demultiplexing the different connections.
// The tls.Config must define an application protocol (using NextProtos).
func DialEarly(ctx context.Context, pconn net.PacketConn, addr net.Addr, tlsConf *tls.Config, config *Config) (EarlyConnection, error) {
	return dialContext(ctx, pconn, addr, tlsConf, config, true, false)
}

func dialContext(ctx context.Context, pconn net.PacketConn, addr net.Addr, tlsConf *tls.Config, config *Config, use0RTT bool, createdPacketConn bool) (quicConn, error) {
	if tlsConf == nil {
		return nil, errors.New("quic: tls.Config not set")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	config = populateClientConfig(config, createdPacketConn)
	packetHandlers, err := getMultiplexer().AddConn(pconn, config.ConnectionIDGenerator.ConnectionIDLen(), config.StatelessResetKey, config.Tracer)
	if err != nil {
		return nil, err
	}
	c, err := newClient(pconn, addr, config, tlsConf, use0RTT, createdPacketConn)
	if err != nil {
		return nil, err
	}
	c.packetHandlers = packetHandlers

	c.tracingID = nextConnTracingID()
	if c.config.Tracer != nil {
		c.tracer = c.config.Tracer.TracerForConnection(
			context.WithValue(ctx, ConnectionTracingKey, c.tracingID),
			protocol.PerspectiveClient,
			c.destConnID,
		)
	}
	if c.tracer != nil {
		c.tracer.StartedConnection(c.sconn.LocalAddr(), c.sconn.RemoteAddr(), c.srcConnID, c.destConnID)
	}
	if err := c.dial(ctx); err != nil {
		return nil, err
	}
	return c.conn, nil
}

func newClient(pconn net.PacketConn, remoteAddr net.Addr, config *Config, tlsConf *tls.Config, use0RTT bool, createdPacketConn bool) (*client, error) {
	if tlsConf == nil {
		tlsConf = &tls.Config{}
	} else {
		tlsConf = tlsConf.Clone()
	}

	srcConnID, err := config.ConnectionIDGenerator.GenerateConnectionID()
	if err != nil {
		return nil, err
	}
	destConnID, err := generateConnectionIDForInitial()
	if err != nil {
		return nil, err
	}
	c := &client{
		srcConnID:         srcConnID,
		destConnID:        destConnID,
		sconn:             newSendPconn(pconn, remoteAddr),
		createdPacketConn: createdPacketConn,
		use0RTT:           use0RTT,
		tlsConf:           tlsConf,
		config:            config,
		version:           config.Versions[0],
		handshakeChan:     make(chan struct{}),
		logger:            utils.DefaultLogger.WithPrefix("client"),
	}
	return c, nil
}

func (c *client) dial(ctx context.Context) error {
	c.logger.Infof("Starting new connection to %s (%s -> %s), source connection ID %s, destination connection ID %s, version %s", c.tlsConf.ServerName, c.sconn.LocalAddr(), c.sconn.RemoteAddr(), c.srcConnID, c.destConnID, c.version)

	c.conn = newClientConnection(
		c.sconn,
		c.packetHandlers,
		c.destConnID,
		c.srcConnID,
		c.config,
		c.tlsConf,
		c.initialPacketNumber,
		c.use0RTT,
		c.hasNegotiatedVersion,
		c.tracer,
		c.tracingID,
		c.logger,
		c.version,
	)
	c.packetHandlers.Add(c.srcConnID, c.conn)

	errorChan := make(chan error, 1)
	go func() {
		err := c.conn.run() // returns as soon as the connection is closed

		if e := (&errCloseForRecreating{}); !errors.As(err, &e) && c.createdPacketConn {
			c.packetHandlers.Destroy()
		}
		errorChan <- err
	}()

	// only set when we're using 0-RTT
	// Otherwise, earlyConnChan will be nil. Receiving from a nil chan blocks forever.
	var earlyConnChan <-chan struct{}
	if c.use0RTT {
		earlyConnChan = c.conn.earlyConnReady()
	}

	select {
	case <-ctx.Done():
		c.conn.shutdown()
		return ctx.Err()
	case err := <-errorChan:
		var recreateErr *errCloseForRecreating
		if errors.As(err, &recreateErr) {
			c.initialPacketNumber = recreateErr.nextPacketNumber
			c.version = recreateErr.nextVersion
			c.hasNegotiatedVersion = true
			return c.dial(ctx)
		}
		return err
	case <-earlyConnChan:
		// ready to send 0-RTT data
		return nil
	case <-c.conn.HandshakeComplete():
		// handshake successfully completed
		return nil
	}
}
