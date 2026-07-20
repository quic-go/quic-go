package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/quicvarint"
)

// DialQMux establishes a QMux connection over conn and returns it as a regular quic-go Conn.
func DialQMux(ctx context.Context, conn net.Conn, tlsConf *tls.Config, conf *Config) (*Conn, error) {
	if tlsConf == nil {
		return nil, errors.New("quic: tls.Config not set")
	}
	if err := validateConfig(conf); err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, tlsConf.Clone())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	if err := checkQMuxALPN(tlsConf, tlsConn.ConnectionState()); err != nil {
		conn.Close()
		return nil, err
	}
	return newQMuxConnection(ctx, tlsConn, protocol.PerspectiveClient, tlsConn.ConnectionState(), populateConfig(conf))
}

// AcceptQMux accepts a QMux connection over conn and returns it as a regular quic-go Conn.
func AcceptQMux(ctx context.Context, conn net.Conn, tlsConf *tls.Config, conf *Config) (*Conn, error) {
	if tlsConf == nil {
		return nil, errors.New("quic: tls.Config not set")
	}
	if err := validateConfig(conf); err != nil {
		return nil, err
	}
	tlsConn := tls.Server(conn, tlsConf.Clone())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	if err := checkQMuxALPN(tlsConf, tlsConn.ConnectionState()); err != nil {
		conn.Close()
		return nil, err
	}
	return newQMuxConnection(ctx, tlsConn, protocol.PerspectiveServer, tlsConn.ConnectionState(), populateConfig(conf))
}

// checkQMuxALPN enforces that an application protocol was negotiated via ALPN.
// As required by Section 8.1 of draft-ietf-quic-qmux, both clients and servers MUST abort
// when ALPN negotiation fails. Enforcement only applies when the endpoint configured ALPN
// identifiers; otherwise an out-of-band mechanism for agreeing on the application protocol is assumed.
//
// Deviation from Section 8.1: the draft asks for a no_application_protocol TLS alert when
// aborting. crypto/tls sends this alert itself in most failure cases (e.g. no protocol overlap),
// but doesn't allow sending alerts after the handshake completed, so the case caught here
// (the peer didn't negotiate ALPN at all) closes the connection without an alert.
func checkQMuxALPN(tlsConf *tls.Config, state tls.ConnectionState) error {
	if len(tlsConf.NextProtos) > 0 && state.NegotiatedProtocol == "" {
		return errors.New("quic: ALPN application protocol not negotiated")
	}
	return nil
}

func newQMuxConnection(ctx context.Context, conn net.Conn, perspective protocol.Perspective, tlsState tls.ConnectionState, conf *Config) (*Conn, error) {
	localParams := newQMuxTransportParameters(conf)
	peerParams, leftover, err := exchangeQMuxTransportParameters(ctx, conn, localParams)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// The ctx passed to DialQMux / AcceptQMux only bounds connection setup.
	// It must not cancel the established connection (cf. Transport.dial).
	ctx, ctxCancel := context.WithCancelCause(context.WithoutCancel(ctx))
	state := &qmuxState{
		maxRecordSize:                effectiveQMuxMaxRecordSize(peerParams.MaxRecordSize),
		recordQueueSpace:             make(chan struct{}, 1),
		writtenFrameBatchesAvailable: make(chan struct{}, 1),
	}
	qconn := &qmuxSendConn{conn: conn}
	c := &Conn{
		ctx:                 ctx,
		ctxCancel:           ctxCancel,
		conn:                qconn,
		config:              conf,
		perspective:         perspective,
		logger:              utils.DefaultLogger,
		version:             protocol.Version1,
		qmux:                state,
		handshakeComplete:   true,
		handshakeConfirmed:  true,
		sentFirstPacket:     true,
		versionNegotiated:   true,
		receivedFirstPacket: true,
	}
	c.logID = fmt.Sprintf("qmux-%s", conn.RemoteAddr())
	if conf.Tracer != nil {
		c.qlogTrace = conf.Tracer(ctx, perspective == protocol.PerspectiveClient, protocol.ConnectionID{})
		if c.qlogTrace != nil {
			c.qlogger = c.qlogTrace.AddProducer()
		}
	}
	c.preSetup()
	c.sendQueue = newQMuxSender(qconn, state)
	c.cryptoStreamHandler = newQMuxCryptoStreamHandler(tlsState)
	c.cryptoStreamManager = newCryptoStreamManager(c.initialStream, c.handshakeStream, newCryptoStream())
	c.sentPacketHandler = &qmuxSentPacketHandler{connStats: &c.connStats}
	runner := noopConnRunner{}
	c.connIDManager = newConnIDManager(protocol.ConnectionID{}, func(protocol.StatelessResetToken) {}, func(protocol.StatelessResetToken) {}, c.queueControlFrame)
	c.connIDManager.SetHandshakeComplete()
	c.connIDGenerator = newConnIDGenerator(
		runner,
		protocol.ConnectionID{},
		nil,
		nil,
		connRunnerCallbacks{
			AddConnectionID:    func(protocol.ConnectionID) {},
			RemoveConnectionID: func(protocol.ConnectionID) {},
			ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
		},
		c.queueControlFrame,
		zeroLengthConnectionIDGenerator{},
	)
	c.packer = &qmuxPacker{state: state, framer: c.framer, datagramQueue: c.datagramQueue}
	c.peerParams = peerParams
	c.applyTransportParameters()
	close(c.handshakeCompleteChan)
	close(c.earlyConnReadyChan)

	// Process any frames the peer coalesced after QX_TRANSPORT_PARAMETERS in the first record.
	if len(leftover) > 0 {
		buf := getLargePacketBuffer()
		buf.Data = append(buf.Data[:0], leftover...)
		c.queueQMuxRecord(receivedPacket{
			buffer:     buf,
			remoteAddr: conn.RemoteAddr(),
			rcvTime:    monotime.Now(),
			data:       buf.Data,
			ecn:        protocol.ECNUnsupported,
		})
	}

	go readQMuxRecords(c, conn, localParams.MaxRecordSize)
	go func() {
		c.run()
		// QMux owns the underlying transport for this connection. Close it once the run loop
		// exits so the transport is released immediately (Section 7) and the readQMuxRecords
		// goroutine, blocked on conn.Read, unblocks.
		conn.Close()
	}()
	return c, nil
}

func effectiveQMuxMaxRecordSize(peerMaxRecordSize protocol.ByteCount) protocol.ByteCount {
	// A QMux record consists of the Size prefix followed by the Frames payload.
	// We pack records into a large packet buffer, so the prefix and the payload combined
	// must fit into protocol.MaxLargePacketBufferSize. Reserve space for the Size prefix,
	// which is encoded as a variable-length integer sized for the maximum record size.
	maxSize := protocol.ByteCount(protocol.MaxLargePacketBufferSize)
	maxSize -= protocol.ByteCount(quicvarint.Len(uint64(maxSize)))
	return min(peerMaxRecordSize, maxSize)
}

// maxDatagramPayloadSize returns the largest DATAGRAM frame payload that is guaranteed to fit
// into a record: the effective record size minus the frame's type byte and the worst-case
// length encoding. Using this as the payload size estimate ensures that any datagram accepted
// by SendDatagram can actually be packed (QMux runs over a reliable transport, so a datagram
// that can never be sent would otherwise be dropped silently).
func (s *qmuxState) maxDatagramPayloadSize() protocol.ByteCount {
	return s.maxRecordSize - 1 /* frame type */ - protocol.ByteCount(quicvarint.Len(uint64(s.maxRecordSize)))
}

func newQMuxTransportParameters(conf *Config) *wire.TransportParameters {
	params := &wire.TransportParameters{
		InitialMaxStreamDataBidiLocal:  protocol.ByteCount(conf.InitialStreamReceiveWindow),
		InitialMaxStreamDataBidiRemote: protocol.ByteCount(conf.InitialStreamReceiveWindow),
		InitialMaxStreamDataUni:        protocol.ByteCount(conf.InitialStreamReceiveWindow),
		InitialMaxData:                 protocol.ByteCount(conf.InitialConnectionReceiveWindow),
		MaxIdleTimeout:                 conf.MaxIdleTimeout,
		MaxBidiStreamNum:               protocol.StreamNum(conf.MaxIncomingStreams),
		MaxUniStreamNum:                protocol.StreamNum(conf.MaxIncomingUniStreams),
		MaxDatagramFrameSize:           protocol.InvalidByteCount,
		MaxRecordSize:                  wire.DefaultMaxRecordSize,
	}
	if conf.EnableDatagrams {
		params.MaxDatagramFrameSize = wire.MaxDatagramSize
	}
	return params
}

// exchangeQMuxTransportParameters sends the local QX_TRANSPORT_PARAMETERS frame and reads the
// peer's first record, which must start with a QX_TRANSPORT_PARAMETERS frame. Any frames the peer
// coalesced after it in the same record are returned so they can be processed by the connection.
// If a QMux protocol violation is detected, a CONNECTION_CLOSE frame conveying the error is sent
// to the peer before returning.
func exchangeQMuxTransportParameters(ctx context.Context, conn net.Conn, local *wire.TransportParameters) (*wire.TransportParameters, []byte, error) {
	params, leftover, err := negotiateQMuxTransportParameters(ctx, conn, local)
	if err != nil {
		// A typed transport error means we detected a protocol violation after our own
		// transport parameters were written, so it is safe to send a CONNECTION_CLOSE.
		var transportErr *qerr.TransportError
		if errors.As(err, &transportErr) {
			writeQMuxConnectionClose(conn, transportErr)
		}
	}
	return params, leftover, err
}

// writeQMuxConnectionClose sends a CONNECTION_CLOSE frame conveying transportErr to the peer.
// It is best-effort and uses a short write deadline so a non-reading peer can't block teardown.
func writeQMuxConnectionClose(conn net.Conn, transportErr *qerr.TransportError) {
	ccf := &wire.ConnectionCloseFrame{
		ErrorCode:    uint64(transportErr.ErrorCode),
		FrameType:    transportErr.FrameType,
		ReasonPhrase: transportErr.ErrorMessage,
	}
	payload, err := ccf.Append(nil, protocol.Version1)
	if err != nil {
		return
	}
	record, err := appendQMuxRecord(nil, payload, wire.DefaultMaxRecordSize)
	if err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = conn.Write(record)
}

func negotiateQMuxTransportParameters(ctx context.Context, conn net.Conn, local *wire.TransportParameters) (params *wire.TransportParameters, leftover []byte, retErr error) {
	deadlineSet := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
		close(deadlineSet)
	})
	exchangeSucceeded := false
	defer func() {
		// If cancellation raced with completion, wait for the watcher before clearing its
		// deadline. This prevents a late callback from poisoning an established connection.
		if !stopCancellation() {
			<-deadlineSet
		}
		if exchangeSucceeded {
			if err := conn.SetDeadline(time.Time{}); retErr == nil && err != nil {
				retErr = err
			}
		}
	}()

	localFrame := &wire.QXTransportParametersFrame{TransportParameters: local.MarshalQMux()}
	payload, err := localFrame.Append(nil, protocol.Version1)
	if err != nil {
		return nil, nil, err
	}
	record, err := appendQMuxRecord(nil, payload, wire.DefaultMaxRecordSize)
	if err != nil {
		return nil, nil, err
	}
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(record)
		writeErr <- err
	}()

	peerRecord, err := readQMuxRecord(conn, local.MaxRecordSize, make([]byte, 0, int(local.MaxRecordSize)))
	if err != nil {
		// Unblock and join the concurrent write before returning. In particular, this keeps
		// cancellation and an unresponsive peer from leaking the writer goroutine.
		_ = conn.SetDeadline(time.Now())
		<-writeErr
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		return nil, nil, err
	}
	if err := <-writeErr; err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		return nil, nil, err
	}
	parser := wire.NewFrameParser(false, false, false)
	parser.SetSupportsQMux(true)
	frameType, l, err := parser.ParseType(peerRecord, protocol.Encryption1RTT)
	if err != nil {
		return nil, nil, err
	}
	if frameType != wire.FrameTypeQXTransportParametersFrame {
		// Section 4.2: if the first frame received is not a QX_TRANSPORT_PARAMETERS frame,
		// the endpoint MUST close the connection with a TRANSPORT_PARAMETER_ERROR.
		return nil, nil, &qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: fmt.Sprintf("expected QX_TRANSPORT_PARAMETERS as the first frame, got %#x", frameType),
		}
	}
	frame, n, err := parser.ParseLessCommonFrame(frameType, peerRecord[l:], protocol.Version1)
	if err != nil {
		return nil, nil, err
	}
	params = &wire.TransportParameters{}
	if err := params.UnmarshalQMux(frame.(*wire.QXTransportParametersFrame).TransportParameters); err != nil {
		return nil, nil, err
	}
	// The peer is allowed to coalesce additional frames after QX_TRANSPORT_PARAMETERS in the
	// first record (e.g. to start sending stream data immediately). Return them for processing.
	if rest := peerRecord[l+n:]; len(rest) > 0 {
		leftover = append(leftover, rest...)
	}
	exchangeSucceeded = true
	return params, leftover, nil
}

func readQMuxRecords(c *Conn, conn net.Conn, maxRecordSize protocol.ByteCount) {
	for {
		// Records can't be dropped: the transport is reliable and ordered. Instead, apply
		// backpressure by pausing reads while the connection's receive queue is full, so a
		// peer flooding cheap frames can't grow the queue without bound (Section 12 of
		// draft-ietf-quic-qmux). The transport's flow control then throttles the peer.
		for c.queuedQMuxRecordCount() >= protocol.MaxConnUnprocessedPackets {
			select {
			case <-c.qmux.recordQueueSpace:
			case <-c.ctx.Done():
				return
			}
		}
		buf := getLargePacketBuffer()
		record, err := readQMuxRecord(conn, maxRecordSize, buf.Data)
		if err != nil {
			buf.Release()
			// Protocol violations detected at the record layer (e.g. a record exceeding
			// max_record_size) must be conveyed to the peer with a CONNECTION_CLOSE frame.
			// Transport-level read errors (EOF, closed connection) tear down immediately.
			var transportErr *qerr.TransportError
			if errors.As(err, &transportErr) {
				c.closeLocal(err)
			} else {
				c.destroyImpl(err)
			}
			return
		}
		buf.Data = record
		c.queueQMuxRecord(receivedPacket{
			buffer:     buf,
			remoteAddr: conn.RemoteAddr(),
			rcvTime:    monotime.Now(),
			data:       buf.Data,
			ecn:        protocol.ECNUnsupported,
		})
	}
}

type noopConnRunner struct{}

func (noopConnRunner) Add(protocol.ConnectionID, packetHandler) bool { return true }
func (noopConnRunner) Remove(protocol.ConnectionID)                  {}
func (noopConnRunner) ReplaceWithClosed([]protocol.ConnectionID, []byte, time.Duration) {
}
func (noopConnRunner) AddResetToken(protocol.StatelessResetToken, packetHandler) {}
func (noopConnRunner) RemoveResetToken(protocol.StatelessResetToken)             {}

type zeroLengthConnectionIDGenerator struct{}

func (zeroLengthConnectionIDGenerator) GenerateConnectionID() (protocol.ConnectionID, error) {
	return protocol.ConnectionID{}, nil
}

func (zeroLengthConnectionIDGenerator) ConnectionIDLen() int { return 0 }
