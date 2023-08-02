package quic

import (
	"context"
	"errors"

	"github.com/quic-go/quic-go/internal/protocol"
	tls "github.com/refraction-networking/utls"
)

type uClient struct {
	*client
	uSpec *QUICSpec // [UQUIC]
}

func udial(
	ctx context.Context,
	conn sendConn,
	connIDGenerator ConnectionIDGenerator,
	packetHandlers packetHandlerManager,
	tlsConf *tls.Config,
	config *Config,
	onClose func(),
	use0RTT bool,
	uSpec *QUICSpec, // [UQUIC]
) (quicConn, error) {
	c, err := newClient(conn, connIDGenerator, config, tlsConf, onClose, use0RTT)
	if err != nil {
		return nil, err
	}
	c.packetHandlers = packetHandlers

	// [UQUIC]
	if uSpec.InitialPacketSpec.DestConnIDLength > 0 {
		destConnID, err := generateConnectionIDForInitialWithLength(uSpec.InitialPacketSpec.DestConnIDLength)
		if err != nil {
			return nil, err
		}
		c.destConnID = destConnID
	}
	c.initialPacketNumber = protocol.PacketNumber(uSpec.InitialPacketSpec.InitPacketNumber)
	// [/UQUIC]

	c.tracingID = nextConnTracingID()
	if c.config.Tracer != nil {
		c.tracer = c.config.Tracer(context.WithValue(ctx, ConnectionTracingKey, c.tracingID), protocol.PerspectiveClient, c.destConnID)
	}
	if c.tracer != nil {
		c.tracer.StartedConnection(c.sendConn.LocalAddr(), c.sendConn.RemoteAddr(), c.srcConnID, c.destConnID)
	}

	// [UQUIC]
	uc := &uClient{
		client: c,
		uSpec:  uSpec,
	}
	// [/UQUIC]

	if err := uc.dial(ctx); err != nil {
		return nil, err
	}
	return uc.conn, nil
}

func (c *uClient) dial(ctx context.Context) error {
	c.logger.Infof("Starting new uQUIC connection to %s (%s -> %s), source connection ID %s, destination connection ID %s, version %s", c.tlsConf.ServerName, c.sendConn.LocalAddr(), c.sendConn.RemoteAddr(), c.srcConnID, c.destConnID, c.version)

	// [UQUIC]
	if c.uSpec.ClientHelloSpec == nil {
		c.conn = newClientConnection(
			c.sendConn,
			c.packetHandlers,
			c.destConnID,
			c.srcConnID,
			c.connIDGenerator,
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
	} else {
		// [UQUIC]: use custom version of the connection
		c.conn = newUClientConnection(
			c.sendConn,
			c.packetHandlers,
			c.destConnID,
			c.srcConnID,
			c.connIDGenerator,
			c.config,
			c.tlsConf,
			c.initialPacketNumber,
			c.use0RTT,
			c.hasNegotiatedVersion,
			c.tracer,
			c.tracingID,
			c.logger,
			c.version,
			c.uSpec,
		)
	}
	// [/UQUIC]

	c.packetHandlers.Add(c.srcConnID, c.conn)

	errorChan := make(chan error, 1)
	recreateChan := make(chan errCloseForRecreating)
	go func() {
		err := c.conn.run()
		var recreateErr *errCloseForRecreating
		if errors.As(err, &recreateErr) {
			recreateChan <- *recreateErr
			return
		}
		if c.onClose != nil {
			c.onClose()
		}
		errorChan <- err // returns as soon as the connection is closed
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
		return err
	case recreateErr := <-recreateChan:
		c.initialPacketNumber = recreateErr.nextPacketNumber
		c.version = recreateErr.nextVersion
		c.hasNegotiatedVersion = true
		return c.dial(ctx)
	case <-earlyConnChan:
		// ready to send 0-RTT data
		return nil
	case <-c.conn.HandshakeComplete():
		// handshake successfully completed
		return nil
	}
}
