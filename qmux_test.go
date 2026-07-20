package quic

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func newQMuxConnPair(t *testing.T, conf *Config) (*Conn, *Conn) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	serverTLS, clientTLS := newQMuxTLSConfigs(t, "qmux-test")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	serverCh := make(chan struct {
		conn *Conn
		err  error
	}, 1)
	go func() {
		conn, err := AcceptQMux(ctx, serverConn, serverTLS, conf)
		serverCh <- struct {
			conn *Conn
			err  error
		}{conn: conn, err: err}
	}()
	client, err := DialQMux(ctx, clientConn, clientTLS, conf)
	require.NoError(t, err)
	res := <-serverCh
	require.NoError(t, res.err)
	t.Cleanup(func() {
		client.CloseWithError(0, "")
		res.conn.CloseWithError(0, "")
	})
	return client, res.conn
}

func TestQMuxStreamRoundTrip(t *testing.T) {
	client, server := newQMuxConnPair(t, nil)

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		str, err := server.AcceptStream(context.Background())
		require.NoError(t, err)
		data, err := io.ReadAll(str)
		require.NoError(t, err)
		require.Equal(t, []byte("hello over qmux"), data)
		_, err = str.Write([]byte("response over qmux"))
		require.NoError(t, err)
		require.NoError(t, str.Close())
	}()

	str, err := client.OpenStreamSync(context.Background())
	require.NoError(t, err)
	_, err = str.Write([]byte("hello over qmux"))
	require.NoError(t, err)
	require.NoError(t, str.Close())
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, []byte("response over qmux"), data)
	<-serverDone
}

func TestQMuxLargeStreamTransfer(t *testing.T) {
	client, server := newQMuxConnPair(t, nil)

	// 128 KB in each direction: this spans many records (records are capped at
	// max_record_size, 16382 bytes by default) and exceeds the initial stream and
	// connection flow control windows, so window updates are exercised as well.
	const transferSize = 128 * 1024
	clientData := make([]byte, transferSize)
	_, err := rand.Read(clientData)
	require.NoError(t, err)
	serverData := make([]byte, transferSize)
	_, err = rand.Read(serverData)
	require.NoError(t, err)

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		str, err := server.AcceptStream(context.Background())
		require.NoError(t, err)
		received, err := io.ReadAll(str)
		require.NoError(t, err)
		require.Equal(t, clientData, received)
		_, err = str.Write(serverData)
		require.NoError(t, err)
		require.NoError(t, str.Close())
	}()

	str, err := client.OpenStreamSync(context.Background())
	require.NoError(t, err)
	n, err := str.Write(clientData)
	require.NoError(t, err)
	require.Equal(t, transferSize, n)
	require.NoError(t, str.Close())
	received, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, serverData, received)
	<-serverDone
}

func TestQMuxDatagramRoundTrip(t *testing.T) {
	client, server := newQMuxConnPair(t, &Config{EnableDatagrams: true})

	require.NoError(t, client.SendDatagram([]byte("datagram over qmux")))
	data, err := server.ReceiveDatagram(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("datagram over qmux"), data)
}

func TestQMuxMaxSizeDatagram(t *testing.T) {
	client, server := newQMuxConnPair(t, &Config{EnableDatagrams: true})

	// determine the largest datagram SendDatagram accepts
	var maxSize int
	for size := 17000; size > 0; size-- {
		err := client.SendDatagram(make([]byte, size))
		if err == nil {
			maxSize = size
			break
		}
		var tooLarge *DatagramTooLargeError
		require.ErrorAs(t, err, &tooLarge)
	}
	require.Greater(t, maxSize, 16000)

	// QMux runs over a reliable transport: a datagram accepted by SendDatagram
	// must fit into a record and actually be delivered.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	data, err := server.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Len(t, data, maxSize)
}

func TestQMuxDialContextDoesNotBindConnectionLifetime(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	serverTLS, clientTLS := newQMuxTLSConfigs(t, "qmux-test")
	dialCtx, dialCancel := context.WithCancel(context.Background())
	defer dialCancel()

	serverCh := make(chan *Conn, 1)
	go func() {
		conn, err := AcceptQMux(context.Background(), serverConn, serverTLS, nil)
		if err != nil {
			serverCh <- nil
			return
		}
		serverCh <- conn
	}()
	client, err := DialQMux(dialCtx, clientConn, clientTLS, nil)
	require.NoError(t, err)
	server := <-serverCh
	require.NotNil(t, server)
	t.Cleanup(func() {
		client.CloseWithError(0, "")
		server.CloseWithError(0, "")
	})

	// canceling the dial context after the connection is established
	// must not cancel the connection's context
	dialCancel()
	select {
	case <-client.Context().Done():
		t.Fatal("connection context was canceled when the dial context was canceled")
	case <-time.After(scaleDuration(50 * time.Millisecond)):
	}

	// the connection is still usable
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		str, err := server.AcceptStream(context.Background())
		require.NoError(t, err)
		_, err = io.Copy(str, str)
		require.NoError(t, err)
		require.NoError(t, str.Close())
	}()
	str, err := client.OpenStreamSync(context.Background())
	require.NoError(t, err)
	_, err = str.Write([]byte("still alive"))
	require.NoError(t, err)
	require.NoError(t, str.Close())
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, []byte("still alive"), data)
	<-serverDone
}

func TestQMuxRejectsPostSetupTransportParameters(t *testing.T) {
	client, server := newQMuxConnPair(t, nil)

	client.queueControlFrame(&wire.QXTransportParametersFrame{
		TransportParameters: newQMuxTransportParameters(client.config).MarshalQMux(),
	})

	select {
	case <-server.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for QMux server to close")
	}
	var transportErr *qerr.TransportError
	require.True(t, errors.As(context.Cause(server.Context()), &transportErr))
	require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
}

func TestQMuxPingResponseSequenceValidation(t *testing.T) {
	newConn := func() *Conn {
		return &Conn{
			qmux:              &qmuxState{},
			keepAlivePingSent: true,
			logger:            utils.DefaultLogger,
		}
	}
	handleResponse := func(c *Conn, seq uint64) error {
		t.Helper()
		_, err := c.handleFrame(
			&wire.QXPingFrame{SequenceNumber: seq, IsResponse: true},
			protocol.Encryption1RTT,
			protocol.ConnectionID{},
			monotime.Now(),
		)
		return err
	}

	t.Run("future sequence is a protocol violation", func(t *testing.T) {
		c := newConn()
		require.Equal(t, uint64(1), c.qmux.nextPingRequest())

		err := handleResponse(c, 2)
		var transportErr *qerr.TransportError
		require.ErrorAs(t, err, &transportErr)
		require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode)
		require.True(t, c.qmux.pendingPing)
		require.True(t, c.keepAlivePingSent)
	})

	t.Run("exact sequence satisfies pending ping", func(t *testing.T) {
		c := newConn()
		require.Equal(t, uint64(1), c.qmux.nextPingRequest())

		require.NoError(t, handleResponse(c, 1))
		require.False(t, c.qmux.pendingPing)
		require.False(t, c.keepAlivePingSent)
	})

	t.Run("stale sequence does not satisfy latest ping", func(t *testing.T) {
		c := newConn()
		require.Equal(t, uint64(1), c.qmux.nextPingRequest())
		require.Equal(t, uint64(2), c.qmux.nextPingRequest())

		require.NoError(t, handleResponse(c, 1))
		require.True(t, c.qmux.pendingPing)
		require.True(t, c.keepAlivePingSent)
	})

	t.Run("duplicate response with no pending ping is ignored", func(t *testing.T) {
		c := newConn()
		require.Equal(t, uint64(1), c.qmux.nextPingRequest())
		require.NoError(t, handleResponse(c, 1))
		require.False(t, c.qmux.pendingPing)

		c.keepAlivePingSent = true
		require.NoError(t, handleResponse(c, 1))
		require.False(t, c.qmux.pendingPing)
		require.True(t, c.keepAlivePingSent)
	})
}

func TestQMuxRejectsNonContiguousStreamFrame(t *testing.T) {
	client, server := newQMuxConnPair(t, nil)

	client.queueControlFrame(&wire.StreamFrame{
		StreamID:       protocol.StreamID(0),
		Offset:         1,
		Data:           []byte("out of order"),
		DataLenPresent: true,
	})

	select {
	case <-server.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for QMux server to close")
	}
	var transportErr *qerr.TransportError
	require.True(t, errors.As(context.Cause(server.Context()), &transportErr))
	require.Equal(t, qerr.ProtocolViolation, transportErr.ErrorCode)
	require.Contains(t, transportErr.ErrorMessage, "non-contiguous QMux STREAM frame")
}

func TestQMuxExchangeTransportParametersContextTimeout(t *testing.T) {
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })
	local := newQMuxTransportParameters(populateConfig(nil))

	// Consume our transport parameters, but never send the peer's response.
	peerRead := make(chan struct{})
	go func() {
		_, _ = readQMuxRecord(c2, wire.DefaultMaxRecordSize, make([]byte, 0, int(wire.DefaultMaxRecordSize)))
		close(peerRead)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := exchangeQMuxTransportParameters(ctx, c1, local)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), time.Second)
	select {
	case <-peerRead:
	case <-time.After(time.Second):
		t.Fatal("peer didn't receive local transport parameters")
	}
}

func TestQMuxPackerPreservesConnectionCloseFrameType(t *testing.T) {
	p := &qmuxPacker{state: &qmuxState{maxRecordSize: wire.DefaultMaxRecordSize}}
	packet, err := p.PackConnectionClose(&qerr.TransportError{
		ErrorCode:    qerr.FrameEncodingError,
		FrameType:    uint64(wire.FrameTypeMaxData),
		ErrorMessage: "bad MAX_DATA",
	}, protocol.MaxByteCount, protocol.Version1)
	require.NoError(t, err)
	t.Cleanup(packet.buffer.Release)
	require.Len(t, packet.shortHdrPacket.Frames, 1)
	closeFrame, ok := packet.shortHdrPacket.Frames[0].Frame.(*wire.ConnectionCloseFrame)
	require.True(t, ok)
	require.Equal(t, uint64(wire.FrameTypeMaxData), closeFrame.FrameType)
}

func TestQMuxSendConnectionCloseReleasesBuffer(t *testing.T) {
	local, peer := net.Pipe()
	t.Cleanup(func() { local.Close(); peer.Close() })
	mockCtrl := gomock.NewController(t)
	packer := NewMockPacker(mockCtrl)
	buf := getPacketWithContents([]byte("close"))
	packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), protocol.Version1).Return(&coalescedPacket{
		buffer:         buf,
		shortHdrPacket: &shortHeaderPacket{},
	}, nil)

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		b := make([]byte, len(buf.Data))
		_, _ = io.ReadFull(peer, b)
	}()
	c := &Conn{
		conn:              &qmuxSendConn{conn: local},
		packer:            packer,
		qmux:              &qmuxState{maxRecordSize: wire.DefaultMaxRecordSize},
		sentPacketHandler: &qmuxSentPacketHandler{},
		logger:            utils.DefaultLogger,
		version:           protocol.Version1,
	}
	closePacket, err := c.sendConnectionClose(&qerr.TransportError{ErrorCode: qerr.InternalError})
	require.NoError(t, err)
	require.Nil(t, closePacket)
	require.Zero(t, buf.refCount)
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("peer didn't receive CONNECTION_CLOSE")
	}
}

type qmuxTestFrameHandler struct {
	acked int
}

func (h *qmuxTestFrameHandler) OnAcked(wire.Frame) { h.acked++ }
func (*qmuxTestFrameHandler) OnLost(wire.Frame)    {}

func TestQMuxSenderQueuesCompletionExactlyOnce(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	conn := NewMockSendConn(mockCtrl)
	state := &qmuxState{writtenFrameBatchesAvailable: make(chan struct{}, 1)}
	sender := newQMuxSender(conn, state).(*qmuxSender)
	buf := getPacketWithContents([]byte("record"))
	handler := &qmuxTestFrameHandler{}
	frame := &wire.PingFrame{}
	conn.EXPECT().Write(buf.Data, uint16(0), protocol.ECNUnsupported).Return(nil)
	sender.sendRecord(qmuxOutboundRecord{
		buf:        buf,
		ecn:        protocol.ECNUnsupported,
		completion: qmuxWrittenFrameBatch{frames: []ackhandler.Frame{{Frame: frame, Handler: handler}}},
	})
	close(sender.closeCalled)

	require.NoError(t, sender.Run())
	require.Zero(t, buf.refCount)
	require.Zero(t, handler.acked, "the sender goroutine must not run completion handlers")
	c := &Conn{qmux: state}
	require.True(t, c.handleQMuxWrittenFrameBatches())
	require.Equal(t, 1, handler.acked)
	require.False(t, c.handleQMuxWrittenFrameBatches())
	require.Equal(t, 1, handler.acked)
}

func TestQMuxSenderDoesNotCompleteFailedOrAbandonedRecords(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	conn := NewMockSendConn(mockCtrl)
	state := &qmuxState{writtenFrameBatchesAvailable: make(chan struct{}, 1)}
	sender := newQMuxSender(conn, state).(*qmuxSender)
	failedBuf := getPacketWithContents([]byte("failed"))
	abandonedBuf := getPacketWithContents([]byte("abandoned"))
	failedHandler := &qmuxTestFrameHandler{}
	abandonedHandler := &qmuxTestFrameHandler{}
	conn.EXPECT().Write(failedBuf.Data, uint16(0), protocol.ECNUnsupported).Return(assert.AnError)
	sender.sendRecord(qmuxOutboundRecord{
		buf:        failedBuf,
		ecn:        protocol.ECNUnsupported,
		completion: qmuxWrittenFrameBatch{frames: []ackhandler.Frame{{Frame: &wire.PingFrame{}, Handler: failedHandler}}},
	})
	sender.sendRecord(qmuxOutboundRecord{
		buf:        abandonedBuf,
		ecn:        protocol.ECNUnsupported,
		completion: qmuxWrittenFrameBatch{frames: []ackhandler.Frame{{Frame: &wire.PingFrame{}, Handler: abandonedHandler}}},
	})

	require.ErrorIs(t, sender.Run(), assert.AnError)
	require.Zero(t, failedBuf.refCount)
	require.Zero(t, abandonedBuf.refCount)
	require.Empty(t, state.popWrittenFrameBatches())
	require.Zero(t, failedHandler.acked)
	require.Zero(t, abandonedHandler.acked)
}

func TestQMuxOutboundRecordCompletionSurvivesBufferReuse(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	conn := NewMockSendConn(mockCtrl)
	state := &qmuxState{writtenFrameBatchesAvailable: make(chan struct{}, 1)}
	sender := newQMuxSender(conn, state).(*qmuxSender)
	buf := getPacketWithContents([]byte("old"))
	oldHandler := &qmuxTestFrameHandler{}
	newHandler := &qmuxTestFrameHandler{}
	conn.EXPECT().Write([]byte("old"), uint16(0), protocol.ECNUnsupported).Return(nil)
	sender.sendRecord(qmuxOutboundRecord{
		buf:        buf,
		ecn:        protocol.ECNUnsupported,
		completion: qmuxWrittenFrameBatch{frames: []ackhandler.Frame{{Frame: &wire.PingFrame{}, Handler: oldHandler}}},
	})
	close(sender.closeCalled)
	require.NoError(t, sender.Run())

	// Obtain the same packetBuffer object from the pool for a different record and
	// completion batch. The old completion remains queued independently of it.
	reusedBuf := getPacketBuffer()
	require.Same(t, buf, reusedBuf)
	reusedBuf.Data = append(reusedBuf.Data, "new"...)
	sender = newQMuxSender(conn, state).(*qmuxSender)
	conn.EXPECT().Write([]byte("new"), uint16(0), protocol.ECNUnsupported).Return(nil)
	sender.sendRecord(qmuxOutboundRecord{
		buf:        reusedBuf,
		ecn:        protocol.ECNUnsupported,
		completion: qmuxWrittenFrameBatch{frames: []ackhandler.Frame{{Frame: &wire.PingFrame{}, Handler: newHandler}}},
	})
	close(sender.closeCalled)
	require.NoError(t, sender.Run())

	c := &Conn{qmux: state}
	require.True(t, c.handleQMuxWrittenFrameBatches())
	require.Equal(t, 1, oldHandler.acked)
	require.Equal(t, 1, newHandler.acked)
	require.False(t, c.handleQMuxWrittenFrameBatches())
}

func TestQMuxSenderReleasesBuffersAfterWriteError(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	conn := NewMockSendConn(mockCtrl)
	sender := newQMuxSender(conn, &qmuxState{}).(*qmuxSender)
	first := getPacketWithContents([]byte("first"))
	second := getPacketWithContents([]byte("second"))
	third := getPacketWithContents([]byte("third"))
	conn.EXPECT().Write(first.Data, uint16(0), protocol.ECNUnsupported).Return(assert.AnError)
	sender.Send(first, 0, protocol.ECNUnsupported)
	sender.Send(second, 0, protocol.ECNUnsupported)
	sender.Send(third, 0, protocol.ECNUnsupported)

	err := sender.Run()
	require.ErrorIs(t, err, assert.AnError)
	require.Zero(t, first.refCount)
	require.Zero(t, second.refCount)
	require.Zero(t, third.refCount)
}

func TestQMuxExchangeRejectsNonTPFirstFrame(t *testing.T) {
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })
	local := newQMuxTransportParameters(populateConfig(nil))

	closeFrameCh := make(chan *wire.ConnectionCloseFrame, 1)
	go func() {
		// Read (and discard) the local QX_TRANSPORT_PARAMETERS record.
		_, _ = readQMuxRecord(c2, wire.DefaultMaxRecordSize, make([]byte, 0, int(wire.DefaultMaxRecordSize)))
		// Send a first record whose first frame is a STREAM frame, not QX_TRANSPORT_PARAMETERS.
		payload, _ := (&wire.StreamFrame{StreamID: 0, Data: []byte("x"), DataLenPresent: true}).Append(nil, protocol.Version1)
		record, _ := appendQMuxRecord(nil, payload, wire.DefaultMaxRecordSize)
		_, _ = c2.Write(record)
		// The peer must respond with a CONNECTION_CLOSE frame.
		ccRecord, err := readQMuxRecord(c2, wire.DefaultMaxRecordSize, make([]byte, 0, int(wire.DefaultMaxRecordSize)))
		if err != nil {
			closeFrameCh <- nil
			return
		}
		parser := wire.NewFrameParser(false, false, false)
		parser.SetSupportsQMux(true)
		ft, l, err := parser.ParseType(ccRecord, protocol.Encryption1RTT)
		if err != nil {
			closeFrameCh <- nil
			return
		}
		frame, _, err := parser.ParseLessCommonFrame(ft, ccRecord[l:], protocol.Version1)
		if err != nil {
			closeFrameCh <- nil
			return
		}
		ccf, _ := frame.(*wire.ConnectionCloseFrame)
		closeFrameCh <- ccf
	}()

	_, _, err := exchangeQMuxTransportParameters(context.Background(), c1, local)
	require.Error(t, err)
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)

	select {
	case ccf := <-closeFrameCh:
		require.NotNil(t, ccf)
		require.False(t, ccf.IsApplicationError)
		require.Equal(t, uint64(qerr.TransportParameterError), ccf.ErrorCode)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for CONNECTION_CLOSE")
	}
}

func TestQMuxALPNEnforcement(t *testing.T) {
	// ALPN configured and negotiated: ok.
	require.NoError(t, checkQMuxALPN(&tls.Config{NextProtos: []string{"h3"}}, tls.ConnectionState{NegotiatedProtocol: "h3"}))
	// No ALPN configured: out-of-band agreement assumed, no enforcement.
	require.NoError(t, checkQMuxALPN(&tls.Config{}, tls.ConnectionState{}))
	// ALPN configured but not negotiated: must abort.
	err := checkQMuxALPN(&tls.Config{NextProtos: []string{"h3"}}, tls.ConnectionState{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "ALPN")
}

func TestQMuxClientRequiresNegotiatedALPN(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	serverTLS, clientTLS := newQMuxTLSConfigs(t, "qmux-test")
	// The server doesn't configure ALPN, so the handshake succeeds without a negotiated protocol.
	serverTLS.NextProtos = nil
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	go func() {
		if conn, err := AcceptQMux(ctx, serverConn, serverTLS, nil); err == nil {
			conn.CloseWithError(0, "")
		}
	}()
	_, err := DialQMux(ctx, clientConn, clientTLS, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ALPN")
}

func TestQMuxExchangeTransportParametersCoalescedFrames(t *testing.T) {
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })
	local := newQMuxTransportParameters(populateConfig(nil))

	go func() {
		// Read (and discard) the local QX_TRANSPORT_PARAMETERS record.
		_, _ = readQMuxRecord(c2, wire.DefaultMaxRecordSize, make([]byte, 0, int(wire.DefaultMaxRecordSize)))
		// Reply with a record that coalesces a STREAM frame after QX_TRANSPORT_PARAMETERS.
		peerParams := newQMuxTransportParameters(populateConfig(nil))
		payload, _ := (&wire.QXTransportParametersFrame{TransportParameters: peerParams.MarshalQMux()}).Append(nil, protocol.Version1)
		payload, _ = (&wire.StreamFrame{StreamID: 0, Data: []byte("coalesced"), DataLenPresent: true}).Append(payload, protocol.Version1)
		record, _ := appendQMuxRecord(nil, payload, wire.DefaultMaxRecordSize)
		_, _ = c2.Write(record)
	}()

	params, leftover, err := exchangeQMuxTransportParameters(context.Background(), c1, local)
	require.NoError(t, err)
	require.NotNil(t, params)
	require.NotEmpty(t, leftover)

	parser := wire.NewFrameParser(false, false, false)
	parser.SetSupportsQMux(true)
	frameType, l, err := parser.ParseType(leftover, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.True(t, frameType.IsStreamFrameType())
	frame, n, err := parser.ParseStreamFrame(frameType, leftover[l:], protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, []byte("coalesced"), frame.Data)
	require.Equal(t, len(leftover)-l, n)
}

func TestEffectiveQMuxMaxRecordSizeCapsLargePeerValue(t *testing.T) {
	require.Equal(t,
		wire.DefaultMaxRecordSize,
		effectiveQMuxMaxRecordSize(wire.DefaultMaxRecordSize),
	)
	// The peer's value is capped so that a full record (Size prefix + payload)
	// still fits into a large packet buffer.
	capped := effectiveQMuxMaxRecordSize(protocol.MaxLargePacketBufferSize + 1)
	require.Equal(t,
		protocol.ByteCount(protocol.MaxLargePacketBufferSize)-protocol.ByteCount(quicvarint.Len(protocol.MaxLargePacketBufferSize)),
		capped,
	)
	require.LessOrEqual(t,
		int(capped)+quicvarint.Len(uint64(capped)),
		protocol.MaxLargePacketBufferSize,
	)
}

func newQMuxTLSConfigs(t *testing.T, alpn string) (*tls.Config, *tls.Config) {
	t.Helper()
	ca, caPrivateKey := generateQMuxCA(t)
	leafCert, leafPrivateKey := generateQMuxLeafCert(t, ca, caPrivateKey)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafCert.Raw},
			PrivateKey:  leafPrivateKey,
		}},
		NextProtos: []string{alpn},
	}
	root := x509.NewCertPool()
	root.AddCert(ca)
	clientTLS := &tls.Config{
		ServerName: "localhost",
		RootCAs:    root,
		NextProtos: []string{alpn},
	}
	return serverTLS, clientTLS
}

func generateQMuxCA(t *testing.T) (*x509.Certificate, crypto.PrivateKey) {
	t.Helper()
	certTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caBytes, err := x509.CreateCertificate(rand.Reader, certTempl, certTempl, pub, priv)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caBytes)
	require.NoError(t, err)
	return ca, priv
}

func generateQMuxLeafCert(t *testing.T, ca *x509.Certificate, caPriv crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey) {
	t.Helper()
	certTempl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	certBytes, err := x509.CreateCertificate(rand.Reader, certTempl, ca, pub, caPriv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)
	return cert, priv
}

type closeTrackingConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *closeTrackingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestQMuxClosesUnderlyingConn(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	clientTrack := &closeTrackingConn{Conn: clientRaw, closed: make(chan struct{})}
	serverTrack := &closeTrackingConn{Conn: serverRaw, closed: make(chan struct{})}
	serverTLS, clientTLS := newQMuxTLSConfigs(t, "qmux-test")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	serverCh := make(chan *Conn, 1)
	go func() {
		conn, err := AcceptQMux(ctx, serverTrack, serverTLS, nil)
		if err != nil {
			serverCh <- nil
			return
		}
		serverCh <- conn
	}()
	client, err := DialQMux(ctx, clientTrack, clientTLS, nil)
	require.NoError(t, err)
	server := <-serverCh
	require.NotNil(t, server)

	require.NoError(t, client.CloseWithError(0, "bye"))

	// The local transport must be closed once the connection is closed.
	select {
	case <-clientTrack.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("client underlying conn not closed after CloseWithError")
	}
	// The peer also tears down (and closes its transport) on receiving the CONNECTION_CLOSE.
	select {
	case <-serverTrack.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("server underlying conn not closed after peer close")
	}
}

func TestQMuxPrunesStreamOffsets(t *testing.T) {
	client, server := newQMuxConnPair(t, nil)

	const numStreams = 5
	for range numStreams {
		serverDone := make(chan struct{})
		go func() {
			defer close(serverDone)
			str, err := server.AcceptStream(context.Background())
			require.NoError(t, err)
			_, err = io.Copy(str, str) // echo back
			require.NoError(t, err)
			require.NoError(t, str.Close())
		}()

		str, err := client.OpenStreamSync(context.Background())
		require.NoError(t, err)
		_, err = str.Write([]byte("hello"))
		require.NoError(t, err)
		require.NoError(t, str.Close())
		data, err := io.ReadAll(str)
		require.NoError(t, err)
		require.Equal(t, []byte("hello"), data)
		<-serverDone
	}

	// Once streams complete, their receive-side offset tracking must be pruned on both ends.
	require.Eventually(t, func() bool {
		return qmuxStreamOffsetCount(client.qmux) == 0 && qmuxStreamOffsetCount(server.qmux) == 0
	}, 2*time.Second, 10*time.Millisecond)
}

func qmuxStreamOffsetCount(s *qmuxState) int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return len(s.nextStreamOffsets)
}

// newQMuxServerWithRawClient establishes a QMux connection where the server side is a regular
// *Conn, but the client side is a raw TLS connection that the test drives manually.
func newQMuxServerWithRawClient(t *testing.T) (*Conn, *tls.Conn) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	serverTLS, clientTLS := newQMuxTLSConfigs(t, "qmux-test")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	serverCh := make(chan struct {
		conn *Conn
		err  error
	}, 1)
	go func() {
		conn, err := AcceptQMux(ctx, serverConn, serverTLS, nil)
		serverCh <- struct {
			conn *Conn
			err  error
		}{conn: conn, err: err}
	}()

	tlsConn := tls.Client(clientConn, clientTLS)
	require.NoError(t, tlsConn.HandshakeContext(ctx))
	// exchange transport parameters with the server
	params := newQMuxTransportParameters(populateConfig(nil))
	payload, err := (&wire.QXTransportParametersFrame{TransportParameters: params.MarshalQMux()}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	record, err := appendQMuxRecord(nil, payload, wire.DefaultMaxRecordSize)
	require.NoError(t, err)
	writeDone := make(chan error, 1)
	go func() {
		_, err := tlsConn.Write(record)
		writeDone <- err
	}()
	_, err = readQMuxRecord(tlsConn, wire.DefaultMaxRecordSize, make([]byte, 0, int(wire.DefaultMaxRecordSize)))
	require.NoError(t, err)
	require.NoError(t, <-writeDone)

	res := <-serverCh
	require.NoError(t, res.err)
	t.Cleanup(func() {
		// Close the raw side first: the server's CONNECTION_CLOSE write would otherwise
		// block forever on the pipe, as the raw client is no longer reading.
		// Close the underlying pipe rather than the TLS layer: tlsConn.Close would block
		// (up to crypto/tls's internal 5s deadline) trying to write a close_notify alert
		// that no one reads.
		tlsConn.NetConn().Close()
		res.conn.CloseWithError(0, "")
	})
	return res.conn, tlsConn
}

func TestQMuxOversizedRecordClosesWithFrameEncodingError(t *testing.T) {
	server, raw := newQMuxServerWithRawClient(t)

	// announce a record larger than the server's max_record_size
	_, err := raw.Write(quicvarint.Append(nil, uint64(wire.DefaultMaxRecordSize)+1))
	require.NoError(t, err)

	// Section 5.2: the server must close the connection with a FRAME_ENCODING_ERROR,
	// conveyed to the peer in a CONNECTION_CLOSE frame.
	record, err := readQMuxRecord(raw, wire.DefaultMaxRecordSize, make([]byte, 0, int(wire.DefaultMaxRecordSize)))
	require.NoError(t, err)
	parser := wire.NewFrameParser(false, false, false)
	parser.SetSupportsQMux(true)
	ft, l, err := parser.ParseType(record, protocol.Encryption1RTT)
	require.NoError(t, err)
	frame, _, err := parser.ParseLessCommonFrame(ft, record[l:], protocol.Version1)
	require.NoError(t, err)
	ccf, ok := frame.(*wire.ConnectionCloseFrame)
	require.True(t, ok)
	require.False(t, ccf.IsApplicationError)
	require.Equal(t, uint64(qerr.FrameEncodingError), ccf.ErrorCode)

	select {
	case <-server.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for the server to close")
	}
	var transportErr *qerr.TransportError
	require.ErrorAs(t, context.Cause(server.Context()), &transportErr)
	require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
}

func TestQMuxWritesLargeStreamFrames(t *testing.T) {
	server, raw := newQMuxServerWithRawClient(t)

	const transferSize = 64 * 1024
	data := make([]byte, transferSize)
	_, err := rand.Read(data)
	require.NoError(t, err)

	go func() {
		str, err := server.OpenStreamSync(context.Background())
		require.NoError(t, err)
		_, err = str.Write(data)
		require.NoError(t, err)
		require.NoError(t, str.Close())
	}()

	// read the records and reassemble the STREAM frames
	parser := wire.NewFrameParser(false, false, false)
	parser.SetSupportsQMux(true)
	buf := make([]byte, 0, int(wire.DefaultMaxRecordSize))
	received := make([]byte, 0, transferSize)
	var maxFrameDataLen protocol.ByteCount
	var finReceived bool
	for !finReceived {
		record, err := readQMuxRecord(raw, wire.DefaultMaxRecordSize, buf)
		require.NoError(t, err)
		for len(record) > 0 {
			ft, l, err := parser.ParseType(record, protocol.Encryption1RTT)
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			record = record[l:]
			require.True(t, ft.IsStreamFrameType())
			frame, n, err := parser.ParseStreamFrame(ft, record, protocol.Version1)
			require.NoError(t, err)
			record = record[n:]
			require.Equal(t, protocol.ByteCount(len(received)), frame.Offset)
			received = append(received, frame.Data...)
			maxFrameDataLen = max(maxFrameDataLen, frame.DataLen())
			if frame.Fin {
				finReceived = true
			}
		}
	}
	require.Equal(t, data, received)
	// STREAM frames are not limited to the size of a QUIC packet:
	// a single frame carries (almost) an entire record.
	require.Greater(t, maxFrameDataLen, protocol.ByteCount(protocol.MaxPacketBufferSize))
}

func TestQMuxReceiveQueueBackpressure(t *testing.T) {
	server, raw := newQMuxServerWithRawClient(t)

	// Flood the server with records containing QX_PING requests.
	// The server's receive queue must stay bounded (the read loop pauses instead of
	// queueing without limit), and the connection must stay functional.
	const numPings = 1000
	floodDone := make(chan error, 1)
	go func() {
		for i := 1; i <= numPings; i++ {
			payload, err := (&wire.QXPingFrame{SequenceNumber: uint64(i)}).Append(nil, protocol.Version1)
			if err != nil {
				floodDone <- err
				return
			}
			record, err := appendQMuxRecord(nil, payload, wire.DefaultMaxRecordSize)
			if err != nil {
				floodDone <- err
				return
			}
			if _, err := raw.Write(record); err != nil {
				floodDone <- err
				return
			}
		}
		floodDone <- nil
	}()

	// read the server's QX_PING responses until the final sequence number is echoed
	parser := wire.NewFrameParser(false, false, false)
	parser.SetSupportsQMux(true)
	buf := make([]byte, 0, int(wire.DefaultMaxRecordSize))
	var sawFinalResponse bool
	for !sawFinalResponse {
		require.LessOrEqual(t, server.queuedQMuxRecordCount(), protocol.MaxConnUnprocessedPackets)
		record, err := readQMuxRecord(raw, wire.DefaultMaxRecordSize, buf)
		require.NoError(t, err)
		for len(record) > 0 {
			ft, l, err := parser.ParseType(record, protocol.Encryption1RTT)
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			record = record[l:]
			frame, n, err := parser.ParseLessCommonFrame(ft, record, protocol.Version1)
			require.NoError(t, err)
			record = record[n:]
			if pf, ok := frame.(*wire.QXPingFrame); ok && pf.IsResponse && pf.SequenceNumber == numPings {
				sawFinalResponse = true
			}
		}
	}
	require.NoError(t, <-floodDone)
}
