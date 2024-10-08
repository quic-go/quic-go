package quic

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
)

func exchangeTptParamsQos(logger utils.Logger, conf *Config, conn io.ReadWriter, myPers protocol.Perspective) (*wire.TransportParameters, error) {
	go func() {
		myParams := &wire.TransportParameters{
			InitialMaxStreamDataBidiLocal:  protocol.ByteCount(conf.InitialStreamReceiveWindow),
			InitialMaxStreamDataBidiRemote: protocol.ByteCount(conf.InitialStreamReceiveWindow),
			InitialMaxStreamDataUni:        protocol.ByteCount(conf.InitialStreamReceiveWindow),
			InitialMaxData:                 protocol.ByteCount(conf.InitialConnectionReceiveWindow),
			MaxBidiStreamNum:               protocol.StreamNum(conf.MaxIncomingStreams),
			MaxUniStreamNum:                protocol.StreamNum(conf.MaxIncomingUniStreams),
		}

		// max_idle_timeout
		// initial_max_data
		// initial_max_stream_data_bidi_local
		// initial_max_stream_data_bidi_remote
		// initial_max_stream_data_uni
		// initial_max_streams_bidi
		// initial_max_streams_uni

		f := &wire.QoSTransportParameters{
			Perspective: myPers,
			Params:      myParams,
		}
		buf := make([]byte, 0, f.Length(Version1))
		buf, err := f.Append(buf, Version1)
		if err != nil {
			logger.Errorf("error appending QoSTransportParameters: %s", err)
		}
		conn.Write(buf)
	}()

	f := wire.QoSTransportParameters{}
	err := wire.ReadQoSTransportParametersFrame(&f, conn, myPers.Opposite(), protocol.Version1)
	if err != nil {
		return nil, err
	}
	return f.Params, nil
}

type qosSendConn struct {
	stream io.ReadWriteCloser
}

// Close implements sendConn.
func (q *qosSendConn) Close() error {
	return q.stream.Close()
}

type streamBackedAddr struct {
	addr string
}

// Network implements net.Addr.
func (s *streamBackedAddr) Network() string {
	return "qos"
}

// String implements net.Addr.
func (s *streamBackedAddr) String() string {
	return s.addr
}

var _ net.Addr = &streamBackedAddr{}

// LocalAddr implements sendConn.
func (q *qosSendConn) LocalAddr() net.Addr {
	return &streamBackedAddr{
		addr: "stream",
	}
}

// RemoteAddr implements sendConn.
func (q *qosSendConn) RemoteAddr() net.Addr {
	return &streamBackedAddr{
		addr: "stream",
	}
}

// Write implements sendConn.
func (q *qosSendConn) Write(b []byte, gsoSize uint16, ecn protocol.ECN) error {
	_, err := q.stream.Write(b)
	fmt.Println("Wrote packet of size", len(b))
	return err
}

// capabilities implements sendConn.
func (q *qosSendConn) capabilities() connCapabilities {
	return connCapabilities{}
}

var _ sendConn = &qosSendConn{}

type qosRunner struct {
	label   string
	logger  utils.Logger
	stream  io.ReadWriteCloser
	readBuf []byte
	conn    *connection
	// If we've read a partial frame, where does it end?
	partialFrameBufIdx int
	// For sending
	ctlFrames    []ackhandler.Frame
	streamFrames []ackhandler.StreamFrame
	writer       *bufio.Writer
}

func (q *qosRunner) init(label string, logger utils.Logger) error {
	q.readBuf = make([]byte, 4*16<<10)
	q.label = label
	q.logger = logger
	return nil
}
func (q *qosRunner) setConn(conn *connection) {
	q.conn = conn
}

func (q *qosRunner) run(ctx context.Context) error {
	// Read loop
	for {
		n, err := q.stream.Read(q.readBuf[q.partialFrameBufIdx:])
		if err != nil {
			return err
		}
		frameData := q.readBuf[:q.partialFrameBufIdx+n]
		q.logger.Debugf("[%s] Received %d bytes", q.label, len(frameData))
		// q.logger.Debugf("[%s] [dump] %x", q.label, frameData)
		_, restData, err := q.conn.handleFrames(frameData, protocol.ConnectionID{}, protocol.Encryption1RTT, nil)
		parsedByteCount := len(frameData) - len(restData)
		if parsedByteCount == 0 && len(frameData) > 20<<10 {
			q.logger.Debugf("[%s] [dump] %x", q.label, frameData)
			q.logger.Debugf("[%s] no bytes parsed, %v", q.label, err)
			panic("todo")
		}
		q.logger.Debugf("[%s] parsed %d bytes", q.label, parsedByteCount)
		copy(q.readBuf, restData)
		q.partialFrameBufIdx = len(restData)
		if err == io.EOF {
			continue
		}
		if err != nil {
			q.logger.Errorf("[%s] handle frames err %v", q.label, err)
			q.logger.Errorf("[%s] [dump] %x", q.label, q.readBuf[:q.partialFrameBufIdx])
			return err
		}
	}
}

func (q *qosRunner) send(f framer) error {
	buf := make([]byte, 0, 16<<10)
	q.ctlFrames, _ = f.AppendControlFrames(q.ctlFrames, 16<<10, Version1)
	var wroteData bool
	var err error
	for _, f := range q.ctlFrames {
		wire.LogFrame(q.logger, f.Frame, true)
		buf, err = f.Frame.Append(buf, Version1)
		if err != nil {
			return err
		}
		_, err = q.writer.Write(buf)
		if err != nil {
			return err
		}
		wroteData = true
		buf = buf[:0]
	}
	q.ctlFrames = q.ctlFrames[:0]
	var l protocol.ByteCount
	q.streamFrames, l = f.AppendStreamFrames(q.streamFrames, 16<<10, Version1)
	q.logger.Debugf("[%s] I have %d bytes to write", q.label, l)
	for _, f := range q.streamFrames {
		q.logger.Debugf("[%s] has len: %v", q.label, f.Frame.DataLenPresent)
		f.Frame.DataLenPresent = true
		wire.LogFrame(q.logger, f.Frame, true)
		buf, err = f.Frame.Append(buf, Version1)
		if err != nil {
			return err
		}
		q.logger.Debugf("[%s] dump", q.label, buf)
		_, err = q.writer.Write(buf)
		if err != nil {
			return err
		}
		wroteData = true
		q.logger.Debugf("[%s] wrote %d bytes", q.label, len(buf))
		buf = buf[:0]
	}
	q.streamFrames = q.streamFrames[:0]

	if wroteData {
		return q.writer.Flush()
	}
	return nil
}

type qosConnGenerator struct{}

// ConnectionIDLen implements ConnectionIDGenerator.
func (q *qosConnGenerator) ConnectionIDLen() int {
	return 4
}

// GenerateConnectionID implements ConnectionIDGenerator.
func (q *qosConnGenerator) GenerateConnectionID() (protocol.ConnectionID, error) {
	return protocol.ConnectionID{}, nil
}

var _ ConnectionIDGenerator = &qosConnGenerator{}

func NewQoSConn(stream io.ReadWriteCloser, tlsConf *tls.Config, conf *Config, perspective protocol.Perspective) (EarlyConnection, error) {
	logger := utils.DefaultLogger
	peerParams, err := exchangeTptParamsQos(logger, conf, stream, perspective)
	if err != nil {
		return nil, err
	}
	logger.Debugf("Client Received QoSTransportParameters: %s", peerParams)

	runner := &qosRunner{
		stream: stream,
		writer: bufio.NewWriter(stream),
	}
	err = runner.init(perspective.String(), logger)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	conn := newQoSConnection(
		ctx,
		cancel,
		perspective,
		&qosSendConn{stream: stream},
		nil,
		protocol.ConnectionID{},
		&protocol.ConnectionID{},
		protocol.ConnectionID{},
		protocol.ConnectionID{},
		protocol.ConnectionID{},
		&qosConnGenerator{},
		protocol.StatelessResetToken{},
		conf,
		tlsConf,
		&handshake.TokenGenerator{},
		true,
		nil,
		logger,
		Version1,
	)
	c := conn.(*connection)

	runner.setConn(c)

	go func() {
		err := runner.run(context.Background())
		if err != nil {
			logger.Debugf("QoS runner failed: %s", err)
		}
	}()

	peerParams.RetrySourceConnectionID = nil
	c.quicOnStream = runner
	c.isQuicOnStream = true
	c.peerParams = peerParams
	c.streamsMap.UpdateLimits(peerParams)
	err = c.handleTransportParameters(peerParams)
	if err != nil {
		return nil, err
	}
	if perspective == protocol.PerspectiveClient {
		c.applyTransportParameters()
	}

	c.sentPacketHandler.DropPackets(protocol.EncryptionInitial)
	c.sentPacketHandler.DropPackets(protocol.EncryptionHandshake)
	c.sentPacketHandler.SetHandshakeConfirmed()
	c.handshakeComplete = true
	close(c.handshakeCompleteChan)

	go func() {
		err := c.run()
		logger.Debugf("Connection run done: %s", err)
	}()
	c.scheduleSending()

	return conn, nil

}

var newQoSConnection = func(
	ctx context.Context,
	ctxCancel context.CancelCauseFunc,
	perspective protocol.Perspective,
	conn sendConn,
	runner connRunner,
	origDestConnID protocol.ConnectionID,
	retrySrcConnID *protocol.ConnectionID,
	clientDestConnID protocol.ConnectionID,
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	connIDGenerator ConnectionIDGenerator,
	statelessResetToken protocol.StatelessResetToken,
	conf *Config,
	tlsConf *tls.Config,
	tokenGenerator *handshake.TokenGenerator,
	clientAddressValidated bool,
	tracer *logging.ConnectionTracer,
	logger utils.Logger,
	v protocol.Version,
) quicConn {
	s := &connection{
		isQuicOnStream:      true,
		ctx:                 ctx,
		ctxCancel:           ctxCancel,
		conn:                conn,
		config:              conf,
		handshakeDestConnID: destConnID,
		srcConnIDLen:        srcConnID.Len(),
		tokenGenerator:      tokenGenerator,
		oneRTTStream:        newCryptoStream(),
		perspective:         perspective,
		tracer:              tracer,
		logger:              logger,
		version:             v,
	}
	if origDestConnID.Len() > 0 {
		s.logID = origDestConnID.String()
	} else {
		s.logID = destConnID.String()
	}
	if runner != nil {
		s.connIDManager = newConnIDManager(
			destConnID,
			func(token protocol.StatelessResetToken) { runner.AddResetToken(token, s) },
			runner.RemoveResetToken,
			s.queueControlFrame,
		)
		s.connIDGenerator = newConnIDGenerator(
			srcConnID,
			&clientDestConnID,
			func(connID protocol.ConnectionID) { runner.Add(connID, s) },
			runner.GetStatelessResetToken,
			runner.Remove,
			runner.Retire,
			runner.ReplaceWithClosed,
			s.queueControlFrame,
			connIDGenerator,
		)
	}
	s.preSetup()
	s.sentPacketHandler, s.receivedPacketHandler = ackhandler.NewAckHandler(
		0,
		protocol.ByteCount(s.config.InitialPacketSize),
		s.rttStats,
		clientAddressValidated,
		s.conn.capabilities().ECN,
		s.perspective,
		s.tracer,
		s.logger,
	)
	s.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(protocol.ByteCount(s.config.InitialPacketSize))))
	params := &wire.TransportParameters{
		InitialMaxStreamDataBidiLocal:   protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataBidiRemote:  protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataUni:         protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxData:                  protocol.ByteCount(s.config.InitialConnectionReceiveWindow),
		MaxIdleTimeout:                  s.config.MaxIdleTimeout,
		MaxBidiStreamNum:                protocol.StreamNum(s.config.MaxIncomingStreams),
		MaxUniStreamNum:                 protocol.StreamNum(s.config.MaxIncomingUniStreams),
		MaxAckDelay:                     protocol.MaxAckDelayInclGranularity,
		AckDelayExponent:                protocol.AckDelayExponent,
		MaxUDPPayloadSize:               protocol.MaxPacketBufferSize,
		DisableActiveMigration:          true,
		StatelessResetToken:             &statelessResetToken,
		OriginalDestinationConnectionID: origDestConnID,
		// For interoperability with quic-go versions before May 2023, this value must be set to a value
		// different from protocol.DefaultActiveConnectionIDLimit.
		// If set to the default value, it will be omitted from the transport parameters, which will make
		// old quic-go versions interpret it as 0, instead of the default value of 2.
		// See https://github.com/quic-go/quic-go/pull/3806.
		ActiveConnectionIDLimit:   protocol.MaxActiveConnectionIDs,
		InitialSourceConnectionID: srcConnID,
		RetrySourceConnectionID:   retrySrcConnID,
	}
	if s.config.EnableDatagrams {
		params.MaxDatagramFrameSize = wire.MaxDatagramSize
	} else {
		params.MaxDatagramFrameSize = protocol.InvalidByteCount
	}
	if s.tracer != nil && s.tracer.SentTransportParameters != nil {
		s.tracer.SentTransportParameters(params)
	}
	cs := handshake.NewCryptoSetupServer(
		clientDestConnID,
		conn.LocalAddr(),
		conn.RemoteAddr(),
		params,
		tlsConf,
		conf.Allow0RTT,
		s.rttStats,
		tracer,
		logger,
		s.version,
	)
	s.cryptoStreamHandler = cs
	s.packer = newPacketPacker(srcConnID, s.connIDManager.Get, s.initialStream, s.handshakeStream, s.sentPacketHandler, s.retransmissionQueue, cs, s.framer, s.receivedPacketHandler, s.datagramQueue, s.perspective)
	s.unpacker = newPacketUnpacker(cs, s.srcConnIDLen)
	s.cryptoStreamManager = newCryptoStreamManager(cs, s.initialStream, s.handshakeStream, s.oneRTTStream)
	return s
}
