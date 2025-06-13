package quic

import (
	"context"
	"errors"
	"net"

	"github.com/Noooste/uquic-go/internal/protocol"
	"github.com/Noooste/uquic-go/internal/utils"
	"github.com/Noooste/uquic-go/logging"
	tls "github.com/Noooste/utls"
)

type UTransport struct {
	*Transport

	QUICSpec *QUICSpec // [UQUIC] using ptr to avoid copying
}

// Dial dials a new connection to a remote host (not using 0-RTT).
func (t *UTransport) Dial(ctx context.Context, addr net.Addr, tlsConf *tls.Config, conf *Config) (Connection, error) {
	return t.dial(ctx, addr, "", tlsConf, conf, false)
}

// DialEarly dials a new connection, attempting to use 0-RTT if possible.
func (t *UTransport) DialEarly(ctx context.Context, addr net.Addr, tlsConf *tls.Config, conf *Config) (EarlyConnection, error) {
	return t.dial(ctx, addr, "", tlsConf, conf, true)
}

func (t *UTransport) dial(ctx context.Context, addr net.Addr, host string, tlsConf *tls.Config, conf *Config, use0RTT bool) (EarlyConnection, error) {
	if err := t.init(t.isSingleUse); err != nil {
		return nil, err
	}
	if err := validateConfig(conf); err != nil {
		return nil, err
	}
	conf = populateConfig(conf)

	// [UQUIC]
	// Override the default connection ID generator if the user has specified a length in QUICSpec.
	if t.QUICSpec != nil {
		if t.QUICSpec.InitialPacketSpec.SrcConnIDLength != 0 {
			t.ConnectionIDGenerator = &protocol.DefaultConnectionIDGenerator{ConnLen: t.QUICSpec.InitialPacketSpec.SrcConnIDLength}
		} else {
			t.ConnectionIDGenerator = &protocol.ExpEmptyConnectionIDGenerator{}
		}
	}
	// [/UQUIC]

	tlsConf = tlsConf.Clone()
	setTLSConfigServerName(tlsConf, addr, host)
	return t.doDial(ctx,
		newSendConn(t.conn, addr, packetInfo{}, utils.DefaultLogger),
		tlsConf,
		conf,
		0,
		false,
		use0RTT,
		conf.Versions[0],
	)
}

func (t *UTransport) doDial(
	ctx context.Context,
	sendConn sendConn,
	tlsConf *tls.Config,
	config *Config,
	initialPacketNumber protocol.PacketNumber,
	hasNegotiatedVersion bool,
	use0RTT bool,
	version protocol.Version,
) (quicConn, error) {
	srcConnID, err := t.connIDGenerator.GenerateConnectionID()
	if err != nil {
		return nil, err
	}
	destConnID, err := generateConnectionIDForInitial()
	if err != nil {
		return nil, err
	}

	tracingID := nextConnTracingID()
	ctx = context.WithValue(ctx, ConnectionTracingKey, tracingID)

	t.mutex.Lock()
	if t.closeErr != nil {
		t.mutex.Unlock()
		return nil, t.closeErr
	}

	var tracer *logging.ConnectionTracer
	if config.Tracer != nil {
		tracer = config.Tracer(ctx, protocol.PerspectiveClient, destConnID)
	}
	if tracer != nil && tracer.StartedConnection != nil {
		tracer.StartedConnection(sendConn.LocalAddr(), sendConn.RemoteAddr(), srcConnID, destConnID)
	}

	logger := utils.DefaultLogger.WithPrefix("client")
	logger.Infof("Starting new connection to %s (%s -> %s), source connection ID %s, destination connection ID %s, version %s", tlsConf.ServerName, sendConn.LocalAddr(), sendConn.RemoteAddr(), srcConnID, destConnID, version)

	// [uQUIC SECTION BEGIN]
	var conn quicConn
	if t.QUICSpec == nil {
		conn = newClientConnection(
			context.WithoutCancel(ctx),
			sendConn,
			(*packetHandlerMap)(t.Transport),
			destConnID,
			srcConnID,
			t.connIDGenerator,
			t.statelessResetter,
			config,
			tlsConf,
			initialPacketNumber,
			use0RTT,
			hasNegotiatedVersion,
			tracer,
			logger,
			version,
		)
	} else {
		conn = newUClientConnection(
			context.WithoutCancel(ctx),
			sendConn,
			(*packetHandlerMap)(t.Transport),
			destConnID,
			srcConnID,
			t.connIDGenerator,
			t.statelessResetter,
			config,
			tlsConf,
			initialPacketNumber,
			use0RTT,
			hasNegotiatedVersion,
			tracer,
			logger,
			version,
			t.QUICSpec,
		)
	}
	// [uQUIC SECTION END]

	(*packetHandlerMap)(t.Transport).Add(srcConnID, conn)
	t.mutex.Unlock()

	// The error channel needs to be buffered, as the run loop will continue running
	// after doDial returns (if the handshake is successful).
	errChan := make(chan error, 1)
	recreateChan := make(chan errCloseForRecreating)
	go func() {
		err := conn.run()
		var recreateErr *errCloseForRecreating
		if errors.As(err, &recreateErr) {
			recreateChan <- *recreateErr
			return
		}
		if t.isSingleUse {
			t.Close()
		}
		errChan <- err
	}()

	// Only set when we're using 0-RTT.
	// Otherwise, earlyConnChan will be nil. Receiving from a nil chan blocks forever.
	var earlyConnChan <-chan struct{}
	if use0RTT {
		earlyConnChan = conn.earlyConnReady()
	}

	select {
	case <-ctx.Done():
		conn.destroy(nil)
		// wait until the Go routine that called Connection.run() returns
		select {
		case <-errChan:
		case <-recreateChan:
		}
		return nil, context.Cause(ctx)
	case params := <-recreateChan:
		return t.doDial(ctx,
			sendConn,
			tlsConf,
			config,
			params.nextPacketNumber,
			true,
			use0RTT,
			params.nextVersion,
		)
	case err := <-errChan:
		return nil, err
	case <-earlyConnChan:
		// ready to send 0-RTT data
		return conn, nil
	case <-conn.HandshakeComplete():
		// handshake successfully completed
		return conn, nil
	}
}

func (ut *UTransport) MakeDialer() func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *Config) (EarlyConnection, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *Config) (EarlyConnection, error) {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		return ut.DialEarly(ctx, udpAddr, tlsCfg, cfg)
	}
}
