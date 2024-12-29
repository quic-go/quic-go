package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/mocks"
	mockackhandler "github.com/quic-go/quic-go/internal/mocks/ackhandler"
	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type testConnectionOpt func(*connection)

func connectionOptCryptoSetup(cs *mocks.MockCryptoSetup) testConnectionOpt {
	return func(conn *connection) { conn.cryptoStreamHandler = cs }
}

func connectionOptStreamManager(sm *MockStreamManager) testConnectionOpt {
	return func(conn *connection) { conn.streamsMap = sm }
}

func connectionOptConnFlowController(cfc *mocks.MockConnectionFlowController) testConnectionOpt {
	return func(conn *connection) { conn.connFlowController = cfc }
}

func connectionOptTracer(tr *logging.ConnectionTracer) testConnectionOpt {
	return func(conn *connection) { conn.tracer = tr }
}

func connectionOptSentPacketHandler(sph ackhandler.SentPacketHandler) testConnectionOpt {
	return func(conn *connection) { conn.sentPacketHandler = sph }
}

func connectionOptReceivedPacketHandler(rph ackhandler.ReceivedPacketHandler) testConnectionOpt {
	return func(conn *connection) { conn.receivedPacketHandler = rph }
}

func connectionOptUnpacker(u unpacker) testConnectionOpt {
	return func(conn *connection) { conn.unpacker = u }
}

func connectionOptSender(s sender) testConnectionOpt {
	return func(conn *connection) { conn.sendQueue = s }
}

func connectionOptHandshakeConfirmed() testConnectionOpt {
	return func(conn *connection) {
		conn.handshakeComplete = true
		conn.handshakeConfirmed = true
	}
}

func connectionOptRTTStats(s *utils.RTTStats) testConnectionOpt {
	return func(conn *connection) { conn.rttStats = s }
}

func connectionOptRetrySrcConnID(rcid protocol.ConnectionID) testConnectionOpt {
	return func(conn *connection) { conn.retrySrcConnID = &rcid }
}

type testConnection struct {
	conn       *connection
	connRunner *MockConnRunner
	sendConn   *MockSendConn
	packer     *MockPacker
	destConnID protocol.ConnectionID
	srcConnID  protocol.ConnectionID
}

func newServerTestConnection(
	t *testing.T,
	mockCtrl *gomock.Controller,
	config *Config,
	gso bool,
	opts ...testConnectionOpt,
) *testConnection {
	if mockCtrl == nil {
		mockCtrl = gomock.NewController(t)
	}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321}
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	connRunner := NewMockConnRunner(mockCtrl)
	sendConn := NewMockSendConn(mockCtrl)
	sendConn.EXPECT().capabilities().Return(connCapabilities{GSO: gso}).AnyTimes()
	sendConn.EXPECT().RemoteAddr().Return(remoteAddr).AnyTimes()
	sendConn.EXPECT().LocalAddr().Return(localAddr).AnyTimes()
	packer := NewMockPacker(mockCtrl)
	b := make([]byte, 12)
	rand.Read(b)
	origDestConnID := protocol.ParseConnectionID(b[:6])
	srcConnID := protocol.ParseConnectionID(b[6:12])
	ctx, cancel := context.WithCancelCause(context.Background())
	if config == nil {
		config = &Config{DisablePathMTUDiscovery: true}
	}
	conn := newConnection(
		ctx,
		cancel,
		sendConn,
		connRunner,
		origDestConnID,
		nil,
		protocol.ConnectionID{},
		protocol.ConnectionID{},
		srcConnID,
		&protocol.DefaultConnectionIDGenerator{},
		protocol.StatelessResetToken{},
		populateConfig(config),
		&tls.Config{},
		handshake.NewTokenGenerator(handshake.TokenProtectorKey{}),
		false,
		nil,
		utils.DefaultLogger,
		protocol.Version1,
	).(*connection)
	conn.packer = packer
	for _, opt := range opts {
		opt(conn)
	}
	return &testConnection{
		conn:       conn,
		connRunner: connRunner,
		sendConn:   sendConn,
		packer:     packer,
		destConnID: origDestConnID,
		srcConnID:  srcConnID,
	}
}

func newClientTestConnection(
	t *testing.T,
	mockCtrl *gomock.Controller,
	config *Config,
	enable0RTT bool,
	opts ...testConnectionOpt,
) *testConnection {
	if mockCtrl == nil {
		mockCtrl = gomock.NewController(t)
	}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321}
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	connRunner := NewMockConnRunner(mockCtrl)
	sendConn := NewMockSendConn(mockCtrl)
	sendConn.EXPECT().capabilities().Return(connCapabilities{}).AnyTimes()
	sendConn.EXPECT().RemoteAddr().Return(remoteAddr).AnyTimes()
	sendConn.EXPECT().LocalAddr().Return(localAddr).AnyTimes()
	packer := NewMockPacker(mockCtrl)
	b := make([]byte, 12)
	rand.Read(b)
	destConnID := protocol.ParseConnectionID(b[:6])
	srcConnID := protocol.ParseConnectionID(b[6:12])
	if config == nil {
		config = &Config{DisablePathMTUDiscovery: true}
	}
	conn := newClientConnection(
		context.Background(),
		sendConn,
		connRunner,
		destConnID,
		srcConnID,
		&protocol.DefaultConnectionIDGenerator{},
		populateConfig(config),
		&tls.Config{ServerName: "quic-go.net"},
		0,
		enable0RTT,
		false,
		nil,
		utils.DefaultLogger,
		protocol.Version1,
	).(*connection)
	conn.packer = packer
	for _, opt := range opts {
		opt(conn)
	}
	return &testConnection{
		conn:       conn,
		connRunner: connRunner,
		sendConn:   sendConn,
		packer:     packer,
		destConnID: destConnID,
		srcConnID:  srcConnID,
	}
}

func TestConnectionHandleReceiveStreamFrames(t *testing.T) {
	const streamID protocol.StreamID = 5
	now := time.Now()
	connID := protocol.ConnectionID{}
	f := &wire.StreamFrame{StreamID: streamID, Data: []byte("foobar")}
	rsf := &wire.ResetStreamFrame{StreamID: streamID, ErrorCode: 42, FinalSize: 1337}
	sdbf := &wire.StreamDataBlockedFrame{StreamID: streamID, MaximumStreamData: 1337}

	t.Run("for existing and new streams", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		streamsMap := NewMockStreamManager(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptStreamManager(streamsMap))
		str := NewMockReceiveStreamI(mockCtrl)
		// STREAM frame
		streamsMap.EXPECT().GetOrOpenReceiveStream(streamID).Return(str, nil)
		str.EXPECT().handleStreamFrame(f, now)
		require.NoError(t, tc.conn.handleFrame(f, protocol.Encryption1RTT, connID, now))
		// RESET_STREAM frame
		streamsMap.EXPECT().GetOrOpenReceiveStream(streamID).Return(str, nil)
		str.EXPECT().handleResetStreamFrame(rsf, now)
		require.NoError(t, tc.conn.handleFrame(rsf, protocol.Encryption1RTT, connID, now))
		// STREAM_DATA_BLOCKED frames are not passed to the stream
		require.NoError(t, tc.conn.handleFrame(sdbf, protocol.Encryption1RTT, connID, now))
	})

	t.Run("for closed streams", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		streamsMap := NewMockStreamManager(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptStreamManager(streamsMap))
		// STREAM frame
		streamsMap.EXPECT().GetOrOpenReceiveStream(streamID).Return(nil, nil)
		require.NoError(t, tc.conn.handleFrame(f, protocol.Encryption1RTT, connID, now))
		// RESET_STREAM frame
		streamsMap.EXPECT().GetOrOpenReceiveStream(streamID).Return(nil, nil)
		require.NoError(t, tc.conn.handleFrame(rsf, protocol.Encryption1RTT, connID, now))
		// STREAM_DATA_BLOCKED frames are not passed to the stream
		// TODO(#4822): validate stream ID of STREAM_DATA_BLOCKED frames
		require.NoError(t, tc.conn.handleFrame(sdbf, protocol.Encryption1RTT, connID, now))
	})

	t.Run("for invalid streams", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		streamsMap := NewMockStreamManager(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptStreamManager(streamsMap))
		testErr := errors.New("test err")
		// STREAM frame
		streamsMap.EXPECT().GetOrOpenReceiveStream(streamID).Return(nil, testErr)
		require.ErrorIs(t, tc.conn.handleFrame(f, protocol.Encryption1RTT, connID, now), testErr)
		// RESET_STREAM frame
		streamsMap.EXPECT().GetOrOpenReceiveStream(streamID).Return(nil, testErr)
		require.ErrorIs(t, tc.conn.handleFrame(rsf, protocol.Encryption1RTT, connID, now), testErr)
		// STREAM_DATA_BLOCKED frames are not passed to the stream
		// TODO(#4822): validate stream ID of STREAM_DATA_BLOCKED frames
		require.NoError(t, tc.conn.handleFrame(sdbf, protocol.Encryption1RTT, connID, now))
	})
}

func TestConnectionHandleSendStreamFrames(t *testing.T) {
	const streamID protocol.StreamID = 3
	now := time.Now()
	connID := protocol.ConnectionID{}
	ss := &wire.StopSendingFrame{StreamID: streamID, ErrorCode: 42}
	msd := &wire.MaxStreamDataFrame{StreamID: streamID, MaximumStreamData: 1337}

	t.Run("for existing and new streams", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		streamsMap := NewMockStreamManager(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptStreamManager(streamsMap))
		str := NewMockSendStreamI(mockCtrl)
		// STOP_SENDING frame
		streamsMap.EXPECT().GetOrOpenSendStream(streamID).Return(str, nil)
		str.EXPECT().handleStopSendingFrame(ss)
		require.NoError(t, tc.conn.handleFrame(ss, protocol.Encryption1RTT, connID, now))
		// MAX_STREAM_DATA frame
		streamsMap.EXPECT().GetOrOpenSendStream(streamID).Return(str, nil)
		str.EXPECT().updateSendWindow(msd.MaximumStreamData)
		require.NoError(t, tc.conn.handleFrame(msd, protocol.Encryption1RTT, connID, now))
	})

	t.Run("for closed streams", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		streamsMap := NewMockStreamManager(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptStreamManager(streamsMap))
		// STOP_SENDING frame
		streamsMap.EXPECT().GetOrOpenSendStream(streamID).Return(nil, nil)
		require.NoError(t, tc.conn.handleFrame(ss, protocol.Encryption1RTT, connID, now))
		// MAX_STREAM_DATA frame
		streamsMap.EXPECT().GetOrOpenSendStream(streamID).Return(nil, nil)
		require.NoError(t, tc.conn.handleFrame(msd, protocol.Encryption1RTT, connID, now))
	})

	t.Run("for invalid streams", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		streamsMap := NewMockStreamManager(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptStreamManager(streamsMap))
		testErr := errors.New("test err")
		// STOP_SENDING frame
		streamsMap.EXPECT().GetOrOpenSendStream(streamID).Return(nil, testErr)
		require.ErrorIs(t, tc.conn.handleFrame(ss, protocol.Encryption1RTT, connID, now), testErr)
		// MAX_STREAM_DATA frame
		streamsMap.EXPECT().GetOrOpenSendStream(streamID).Return(nil, testErr)
		require.ErrorIs(t, tc.conn.handleFrame(msd, protocol.Encryption1RTT, connID, now), testErr)
	})
}

func TestConnectionHandleStreamNumFrames(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	streamsMap := NewMockStreamManager(mockCtrl)
	tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptStreamManager(streamsMap))
	now := time.Now()
	connID := protocol.ConnectionID{}
	// MAX_STREAMS frame
	msf := &wire.MaxStreamsFrame{Type: protocol.StreamTypeBidi, MaxStreamNum: 10}
	streamsMap.EXPECT().HandleMaxStreamsFrame(msf)
	require.NoError(t, tc.conn.handleFrame(msf, protocol.Encryption1RTT, connID, now))
	// STREAMS_BLOCKED frame
	tc.conn.handleFrame(&wire.StreamsBlockedFrame{Type: protocol.StreamTypeBidi, StreamLimit: 1}, protocol.Encryption1RTT, connID, now)
}

func TestConnectionHandleConnectionFlowControlFrames(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	connFC := mocks.NewMockConnectionFlowController(mockCtrl)
	tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptConnFlowController(connFC))
	now := time.Now()
	connID := protocol.ConnectionID{}
	// MAX_DATA frame
	connFC.EXPECT().UpdateSendWindow(protocol.ByteCount(1337))
	require.NoError(t, tc.conn.handleFrame(&wire.MaxDataFrame{MaximumData: 1337}, protocol.Encryption1RTT, connID, now))
	// DATA_BLOCKED frame
	require.NoError(t, tc.conn.handleFrame(&wire.DataBlockedFrame{MaximumData: 1337}, protocol.Encryption1RTT, connID, now))
}

func TestConnectionOpenStreams(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	streamsMap := NewMockStreamManager(mockCtrl)
	tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptStreamManager(streamsMap))

	// using OpenStream
	mstr := NewMockStreamI(mockCtrl)
	streamsMap.EXPECT().OpenStream().Return(mstr, nil)
	str, err := tc.conn.OpenStream()
	require.NoError(t, err)
	require.Equal(t, mstr, str)

	// using OpenStreamSync
	streamsMap.EXPECT().OpenStreamSync(context.Background()).Return(mstr, nil)
	str, err = tc.conn.OpenStreamSync(context.Background())
	require.NoError(t, err)
	require.Equal(t, mstr, str)

	// using OpenUniStream
	streamsMap.EXPECT().OpenUniStream().Return(mstr, nil)
	ustr, err := tc.conn.OpenUniStream()
	require.NoError(t, err)
	require.Equal(t, mstr, ustr)

	// using OpenUniStreamSync
	streamsMap.EXPECT().OpenUniStreamSync(context.Background()).Return(mstr, nil)
	ustr, err = tc.conn.OpenUniStreamSync(context.Background())
	require.NoError(t, err)
	require.Equal(t, mstr, ustr)
}

func TestConnectionAcceptStreams(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	streamsMap := NewMockStreamManager(mockCtrl)
	tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptStreamManager(streamsMap))

	// bidirectional streams
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	mstr := NewMockStreamI(mockCtrl)
	streamsMap.EXPECT().AcceptStream(ctx).Return(mstr, nil)
	str, err := tc.conn.AcceptStream(ctx)
	require.NoError(t, err)
	require.Equal(t, mstr, str)

	// unidirectional streams
	streamsMap.EXPECT().AcceptUniStream(ctx).Return(mstr, nil)
	ustr, err := tc.conn.AcceptUniStream(ctx)
	require.NoError(t, err)
	require.Equal(t, mstr, ustr)
}

func TestConnectionServerInvalidFrames(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tc := newServerTestConnection(t, mockCtrl, nil, false)

	for _, test := range []struct {
		Name  string
		Frame wire.Frame
	}{
		{Name: "NEW_TOKEN", Frame: &wire.NewTokenFrame{Token: []byte("foobar")}},
		{Name: "HANDSHAKE_DONE", Frame: &wire.HandshakeDoneFrame{}},
		{Name: "PATH_RESPONSE", Frame: &wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}},
	} {
		t.Run(test.Name, func(t *testing.T) {
			require.ErrorIs(t,
				tc.conn.handleFrame(test.Frame, protocol.Encryption1RTT, protocol.ConnectionID{}, time.Now()),
				&qerr.TransportError{ErrorCode: qerr.ProtocolViolation},
			)
		})
	}
}

func TestConnectionTransportError(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(tr))
	errChan := make(chan error, 1)
	expectedErr := &qerr.TransportError{
		ErrorCode:    1337,
		FrameType:    42,
		ErrorMessage: "test error",
	}
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	b := getPacketBuffer()
	b.Data = append(b.Data, []byte("connection close")...)
	tc.packer.EXPECT().PackConnectionClose(expectedErr, gomock.Any(), protocol.Version1).Return(&coalescedPacket{buffer: b}, nil)
	tc.sendConn.EXPECT().Write([]byte("connection close"), gomock.Any(), gomock.Any())
	tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any()).AnyTimes()
	gomock.InOrder(
		tracer.EXPECT().ClosedConnection(expectedErr),
		tracer.EXPECT().Close(),
	)

	go func() { errChan <- tc.conn.run() }()
	tc.conn.closeLocal(expectedErr)

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, expectedErr)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// further calls to CloseWithError don't do anything
	tc.conn.CloseWithError(42, "another error")
}

func TestConnectionApplicationClose(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(tr))
	errChan := make(chan error, 1)
	expectedErr := &qerr.ApplicationError{
		ErrorCode:    1337,
		ErrorMessage: "test error",
	}
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	b := getPacketBuffer()
	b.Data = append(b.Data, []byte("connection close")...)
	tc.packer.EXPECT().PackApplicationClose(expectedErr, gomock.Any(), protocol.Version1).Return(&coalescedPacket{buffer: b}, nil)
	tc.sendConn.EXPECT().Write([]byte("connection close"), gomock.Any(), gomock.Any())
	tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any()).AnyTimes()
	gomock.InOrder(
		tracer.EXPECT().ClosedConnection(expectedErr),
		tracer.EXPECT().Close(),
	)

	go func() { errChan <- tc.conn.run() }()
	tc.conn.CloseWithError(1337, "test error")

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, expectedErr)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// further calls to CloseWithError don't do anything
	tc.conn.CloseWithError(42, "another error")
}

func TestConnectionStatelessReset(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(tr))
	errChan := make(chan error, 1)
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	gomock.InOrder(
		tracer.EXPECT().ClosedConnection(&StatelessResetError{}),
		tracer.EXPECT().Close(),
	)

	go func() { errChan <- tc.conn.run() }()
	tc.conn.destroy(&StatelessResetError{})

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, &StatelessResetError{})
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func getLongHeaderPacket(t *testing.T, extHdr *wire.ExtendedHeader, data []byte) receivedPacket {
	t.Helper()
	b, err := extHdr.Append(nil, protocol.Version1)
	require.NoError(t, err)
	return receivedPacket{
		data:    append(b, data...),
		buffer:  getPacketBuffer(),
		rcvTime: time.Now(),
	}
}

func getShortHeaderPacket(t *testing.T, connID protocol.ConnectionID, pn protocol.PacketNumber, data []byte) receivedPacket {
	t.Helper()
	b, err := wire.AppendShortHeader(nil, connID, pn, protocol.PacketNumberLen2, protocol.KeyPhaseOne)
	require.NoError(t, err)
	return receivedPacket{
		data:    append(b, data...),
		buffer:  getPacketBuffer(),
		rcvTime: time.Now(),
	}
}

func TestConnectionServerInvalidPackets(t *testing.T) {
	t.Run("Retry", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(tr))

		p := getLongHeaderPacket(t, &wire.ExtendedHeader{Header: wire.Header{
			Type:             protocol.PacketTypeRetry,
			DestConnectionID: tc.conn.origDestConnID,
			SrcConnectionID:  tc.srcConnID,
			Version:          tc.conn.version,
			Token:            []byte("foobar"),
		}}, make([]byte, 16) /* Retry integrity tag */)
		tracer.EXPECT().DroppedPacket(logging.PacketTypeRetry, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropUnexpectedPacket)
		require.False(t, tc.conn.handlePacketImpl(p))
	})

	t.Run("version negotiation", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(tr))

		b := wire.ComposeVersionNegotiation(
			protocol.ArbitraryLenConnectionID(tc.srcConnID.Bytes()),
			protocol.ArbitraryLenConnectionID(tc.conn.origDestConnID.Bytes()),
			[]Version{Version1},
		)
		tracer.EXPECT().DroppedPacket(logging.PacketTypeVersionNegotiation, protocol.InvalidPacketNumber, protocol.ByteCount(len(b)), logging.PacketDropUnexpectedPacket)
		require.False(t, tc.conn.handlePacketImpl(receivedPacket{data: b, buffer: getPacketBuffer()}))
	})

	t.Run("unsupported version", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(tr))

		p := getLongHeaderPacket(t, &wire.ExtendedHeader{
			Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: 1234},
			PacketNumberLen: protocol.PacketNumberLen2,
		}, nil)
		tracer.EXPECT().DroppedPacket(logging.PacketTypeNotDetermined, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropUnsupportedVersion)
		require.False(t, tc.conn.handlePacketImpl(p))
	})

	t.Run("invalid header", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(tr))

		p := getLongHeaderPacket(t, &wire.ExtendedHeader{
			Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: Version1},
			PacketNumberLen: protocol.PacketNumberLen2,
		}, nil)
		p.data[0] ^= 0x40 // unset the QUIC bit
		tracer.EXPECT().DroppedPacket(logging.PacketTypeNotDetermined, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropHeaderParseError)
		require.False(t, tc.conn.handlePacketImpl(p))
	})
}

func TestConnectionClientInvalidPackets(t *testing.T) {
	t.Skip("TODO")

	t.Run("0-RTT packet", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(tr))

		p := getLongHeaderPacket(t, &wire.ExtendedHeader{
			Header:          wire.Header{Type: protocol.PacketType0RTT, Version: protocol.Version1},
			PacketNumberLen: protocol.PacketNumberLen2,
		}, nil)
		tracer.EXPECT().DroppedPacket(logging.PacketType0RTT, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropUnsupportedVersion)
		require.False(t, tc.conn.handlePacketImpl(p))
	})
}

func TestConnectionUnpacking(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptReceivedPacketHandler(rph),
		connectionOptUnpacker(unpacker),
		connectionOptTracer(tr),
	)

	// receive a long header packet
	hdr := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeInitial,
			DestConnectionID: tc.srcConnID,
			Version:          protocol.Version1,
			Length:           1,
		},
		PacketNumber:    0x37,
		PacketNumberLen: protocol.PacketNumberLen1,
	}
	unpackedHdr := *hdr
	unpackedHdr.PacketNumber = 0x1337
	packet := getLongHeaderPacket(t, hdr, nil)
	packet.ecn = protocol.ECNCE
	rcvTime := time.Now().Add(-10 * time.Second)
	packet.rcvTime = rcvTime
	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(&unpackedPacket{
		encryptionLevel: protocol.EncryptionInitial,
		hdr:             &unpackedHdr,
		data:            []byte{0}, // one PADDING frame
	}, nil)
	gomock.InOrder(
		rph.EXPECT().IsPotentiallyDuplicate(protocol.PacketNumber(0x1337), protocol.EncryptionInitial),
		rph.EXPECT().ReceivedPacket(protocol.PacketNumber(0x1337), protocol.ECNCE, protocol.EncryptionInitial, rcvTime, false),
	)

	tracer.EXPECT().NegotiatedVersion(gomock.Any(), gomock.Any(), gomock.Any())
	tracer.EXPECT().StartedConnection(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
	tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), gomock.Any(), logging.ECNCE, []logging.Frame{})
	require.True(t, tc.conn.handlePacketImpl(packet))
	require.True(t, mockCtrl.Satisfied())

	// receive a duplicate of this packet
	packet = getLongHeaderPacket(t, hdr, nil)
	rph.EXPECT().IsPotentiallyDuplicate(protocol.PacketNumber(0x1337), protocol.EncryptionInitial).Return(true)
	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(&unpackedPacket{
		encryptionLevel: protocol.EncryptionInitial,
		hdr:             &unpackedHdr,
		data:            []byte{0}, // one PADDING frame
	}, nil)
	tracer.EXPECT().DroppedPacket(logging.PacketTypeInitial, protocol.PacketNumber(0x1337), protocol.ByteCount(len(packet.data)), logging.PacketDropDuplicate)
	require.False(t, tc.conn.handlePacketImpl(packet))
	require.True(t, mockCtrl.Satisfied())

	// receive a short header packet
	packet = getShortHeaderPacket(t, tc.srcConnID, 0x37, nil)
	packet.ecn = protocol.ECT1
	packet.rcvTime = rcvTime
	gomock.InOrder(
		rph.EXPECT().IsPotentiallyDuplicate(protocol.PacketNumber(0x1337), protocol.Encryption1RTT),
		rph.EXPECT().ReceivedPacket(protocol.PacketNumber(0x1337), protocol.ECT1, protocol.Encryption1RTT, rcvTime, false),
	)
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(
		protocol.PacketNumber(0x1337), protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{0} /* PADDING */, nil,
	)
	tracer.EXPECT().ReceivedShortHeaderPacket(gomock.Any(), gomock.Any(), logging.ECT1, []logging.Frame{})
	require.True(t, tc.conn.handlePacketImpl(packet))
}

func TestConnectionUnpackCoalescedPacket(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptReceivedPacketHandler(rph),
		connectionOptUnpacker(unpacker),
		connectionOptTracer(tr),
	)
	hdr1 := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeInitial,
			DestConnectionID: tc.srcConnID,
			Version:          protocol.Version1,
			Length:           1,
		},
		PacketNumber:    37,
		PacketNumberLen: protocol.PacketNumberLen1,
	}
	hdr2 := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeHandshake,
			DestConnectionID: tc.srcConnID,
			Version:          protocol.Version1,
			Length:           1,
		},
		PacketNumber:    38,
		PacketNumberLen: protocol.PacketNumberLen1,
	}
	// add a packet with a different source connection ID
	incorrectSrcConnID := protocol.ParseConnectionID([]byte{0xa, 0xb, 0xc})
	hdr3 := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeHandshake,
			DestConnectionID: incorrectSrcConnID,
			Version:          protocol.Version1,
			Length:           1,
		},
		PacketNumber:    0x42,
		PacketNumberLen: protocol.PacketNumberLen1,
	}
	unpackedHdr1 := *hdr1
	unpackedHdr1.PacketNumber = 1337
	unpackedHdr2 := *hdr2
	unpackedHdr2.PacketNumber = 1338

	packet := getLongHeaderPacket(t, hdr1, nil)
	packet2 := getLongHeaderPacket(t, hdr2, nil)
	packet3 := getLongHeaderPacket(t, hdr3, nil)
	packet.data = append(packet.data, packet2.data...)
	packet.data = append(packet.data, packet3.data...)
	packet.ecn = protocol.ECT1
	rcvTime := time.Now()
	packet.rcvTime = rcvTime

	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(&unpackedPacket{
		encryptionLevel: protocol.EncryptionInitial,
		hdr:             &unpackedHdr1,
		data:            []byte{0}, // one PADDING frame
	}, nil)
	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(&unpackedPacket{
		encryptionLevel: protocol.EncryptionHandshake,
		hdr:             &unpackedHdr2,
		data:            []byte{1}, // one PING frame
	}, nil)
	gomock.InOrder(
		rph.EXPECT().IsPotentiallyDuplicate(protocol.PacketNumber(1337), protocol.EncryptionInitial),
		rph.EXPECT().ReceivedPacket(protocol.PacketNumber(1337), protocol.ECT1, protocol.EncryptionInitial, rcvTime, false),
		rph.EXPECT().IsPotentiallyDuplicate(protocol.PacketNumber(1338), protocol.EncryptionHandshake),
		rph.EXPECT().ReceivedPacket(protocol.PacketNumber(1338), protocol.ECT1, protocol.EncryptionHandshake, rcvTime, true),
	)
	tracer.EXPECT().NegotiatedVersion(gomock.Any(), gomock.Any(), gomock.Any())
	tracer.EXPECT().StartedConnection(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
	tracer.EXPECT().DroppedEncryptionLevel(protocol.EncryptionInitial)
	rph.EXPECT().DropPackets(protocol.EncryptionInitial)
	gomock.InOrder(
		tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), gomock.Any(), logging.ECT1, []logging.Frame{}),
		tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), gomock.Any(), logging.ECT1, []logging.Frame{&wire.PingFrame{}}),
		tracer.EXPECT().DroppedPacket(logging.PacketTypeNotDetermined, protocol.InvalidPacketNumber, protocol.ByteCount(len(packet3.data)), logging.PacketDropUnknownConnectionID),
	)
	require.True(t, tc.conn.handlePacketImpl(packet))
}

func TestConnectionUnpackFailure(t *testing.T) {
	t.Run("other errors", func(t *testing.T) {
		require.ErrorIs(t,
			testConnectionUnpackFailure(t, &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError}),
			&qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError},
		)
	})

	t.Run("invalid reserved bits", func(t *testing.T) {
		require.ErrorIs(t,
			testConnectionUnpackFailure(t, wire.ErrInvalidReservedBits),
			&qerr.TransportError{ErrorCode: qerr.ProtocolViolation},
		)
	})
}

func testConnectionUnpackFailure(t *testing.T, unpackErr error) error {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptUnpacker(unpacker),
	)

	tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any())
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(0), protocol.PacketNumberLen(0), protocol.KeyPhaseBit(0), nil, unpackErr)
	tc.packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), protocol.Version1).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any())
	tc.conn.handlePacket(getShortHeaderPacket(t, tc.srcConnID, 0x42, nil))

	select {
	case err := <-errChan:
		require.Error(t, err)
		return err
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	return nil
}

func TestConnectionMaxUnprocessedPackets(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(tr))
	done := make(chan struct{})

	for i := protocol.PacketNumber(0); i < protocol.MaxConnUnprocessedPackets; i++ {
		// nothing here should block
		tc.conn.handlePacket(receivedPacket{data: []byte("foobar")})
	}
	tracer.EXPECT().DroppedPacket(logging.PacketTypeNotDetermined, protocol.InvalidPacketNumber, logging.ByteCount(6), logging.PacketDropDOSPrevention).Do(func(logging.PacketType, logging.PacketNumber, logging.ByteCount, logging.PacketDropReason) {
		close(done)
	})
	tc.conn.handlePacket(receivedPacket{data: []byte("foobar")})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionRemoteClose(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockStreamManager := NewMockStreamManager(mockCtrl)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptStreamManager(mockStreamManager),
		connectionOptTracer(tr),
	)
	expectedErr := &qerr.TransportError{ErrorCode: qerr.StreamLimitError, Remote: true}
	tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any())
	streamErrChan := make(chan error, 1)
	mockStreamManager.EXPECT().CloseWithError(gomock.Any()).Do(func(e error) { streamErrChan <- e })
	tracerErrChan := make(chan error, 1)
	tracer.EXPECT().ClosedConnection(gomock.Any()).Do(func(e error) { tracerErrChan <- e })
	tracer.EXPECT().Close()

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	tc.conn.handleFrame(&wire.ConnectionCloseFrame{
		ErrorCode:    uint64(qerr.StreamLimitError),
		ReasonPhrase: "foobar",
	}, protocol.Encryption1RTT, protocol.ConnectionID{}, time.Now())

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, expectedErr)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	select {
	case err := <-tracerErrChan:
		require.ErrorIs(t, err, expectedErr)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	select {
	case err := <-streamErrChan:
		require.ErrorIs(t, err, expectedErr)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionIdleTimeoutDuringHandshake(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		&Config{HandshakeIdleTimeout: scaleDuration(25 * time.Millisecond)},
		false,
		connectionOptTracer(tr),
	)
	tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).AnyTimes()
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	gomock.InOrder(
		tracer.EXPECT().ClosedConnection(&IdleTimeoutError{}),
		tracer.EXPECT().Close(),
	)
	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, &IdleTimeoutError{})
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionHandshakeIdleTimeout(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		&Config{HandshakeIdleTimeout: scaleDuration(25 * time.Millisecond)},
		false,
		connectionOptTracer(tr),
		func(c *connection) { c.creationTime = time.Now().Add(-10 * time.Second) },
	)
	tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).AnyTimes()
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	gomock.InOrder(
		tracer.EXPECT().ClosedConnection(&HandshakeTimeoutError{}),
		tracer.EXPECT().Close(),
	)
	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, &HandshakeTimeoutError{})
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionTransportParameters(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	streamManager := NewMockStreamManager(mockCtrl)
	connFC := mocks.NewMockConnectionFlowController(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(tr),
		connectionOptStreamManager(streamManager),
		connectionOptConnFlowController(connFC),
	)
	tracer.EXPECT().ReceivedTransportParameters(gomock.Any())
	params := &wire.TransportParameters{
		MaxIdleTimeout:                90 * time.Second,
		InitialMaxStreamDataBidiLocal: 0x5000,
		InitialMaxData:                0x5000,
		ActiveConnectionIDLimit:       3,
		// marshaling always sets it to this value
		MaxUDPPayloadSize:               protocol.MaxPacketBufferSize,
		OriginalDestinationConnectionID: tc.destConnID,
	}
	streamManager.EXPECT().UpdateLimits(params)
	connFC.EXPECT().UpdateSendWindow(params.InitialMaxData)
	require.NoError(t, tc.conn.handleTransportParameters(params))
}

func TestConnectionTransportParameterValidationFailureServer(t *testing.T) {
	tc := newServerTestConnection(t, nil, nil, false)
	err := tc.conn.handleTransportParameters(&wire.TransportParameters{
		InitialSourceConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
	})
	assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
	assert.ErrorContains(t, err, "expected initial_source_connection_id to equal")
}

func TestConnectionTransportParameterValidationFailureClient(t *testing.T) {
	t.Run("initial_source_connection_id", func(t *testing.T) {
		tc := newClientTestConnection(t, nil, nil, false)
		err := tc.conn.handleTransportParameters(&wire.TransportParameters{
			InitialSourceConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		})
		assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
		assert.ErrorContains(t, err, "expected initial_source_connection_id to equal")
	})

	t.Run("original_destination_connection_id", func(t *testing.T) {
		tc := newClientTestConnection(t, nil, nil, false)
		err := tc.conn.handleTransportParameters(&wire.TransportParameters{
			InitialSourceConnectionID:       tc.destConnID,
			OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		})
		assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
		assert.ErrorContains(t, err, "expected original_destination_connection_id to equal")
	})

	t.Run("retry_source_connection_id if no retry", func(t *testing.T) {
		tc := newClientTestConnection(t, nil, nil, false)
		rcid := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		params := &wire.TransportParameters{
			InitialSourceConnectionID:       tc.destConnID,
			OriginalDestinationConnectionID: tc.destConnID,
			RetrySourceConnectionID:         &rcid,
		}
		err := tc.conn.handleTransportParameters(params)
		assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
		assert.ErrorContains(t, err, "received retry_source_connection_id, although no Retry was performed")
	})

	t.Run("retry_source_connection_id missing", func(t *testing.T) {
		tc := newClientTestConnection(t,
			nil,
			nil,
			false,
			connectionOptRetrySrcConnID(protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})),
		)
		params := &wire.TransportParameters{
			InitialSourceConnectionID:       tc.destConnID,
			OriginalDestinationConnectionID: tc.destConnID,
		}
		err := tc.conn.handleTransportParameters(params)
		assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
		assert.ErrorContains(t, err, "missing retry_source_connection_id")
	})

	t.Run("retry_source_connection_id incorrect", func(t *testing.T) {
		tc := newClientTestConnection(t,
			nil,
			nil,
			false,
			connectionOptRetrySrcConnID(protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})),
		)
		wrongCID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		params := &wire.TransportParameters{
			InitialSourceConnectionID:       tc.destConnID,
			OriginalDestinationConnectionID: tc.destConnID,
			RetrySourceConnectionID:         &wrongCID,
		}
		err := tc.conn.handleTransportParameters(params)
		assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
		assert.ErrorContains(t, err, "expected retry_source_connection_id to equal")
	})
}

func TestConnectionHandshakeServer(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newServerTestConnection(
		t,
		mockCtrl,
		nil,
		false,
		connectionOptCryptoSetup(cs),
		connectionOptUnpacker(unpacker),
	)

	// the state transition is driven by processing of a CRYPTO frame
	hdr := &wire.ExtendedHeader{
		Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: protocol.Version1},
		PacketNumberLen: protocol.PacketNumberLen2,
	}
	data, err := (&wire.CryptoFrame{Data: []byte("foobar")}).Append(nil, protocol.Version1)
	require.NoError(t, err)

	cs.EXPECT().DiscardInitialKeys()
	tc.connRunner.EXPECT().Retire(gomock.Any())
	gomock.InOrder(
		cs.EXPECT().StartHandshake(gomock.Any()),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
			&unpackedPacket{hdr: hdr, encryptionLevel: protocol.EncryptionHandshake, data: data}, nil,
		),
		cs.EXPECT().HandleMessage([]byte("foobar"), protocol.EncryptionHandshake),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventHandshakeComplete}),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		cs.EXPECT().SetHandshakeConfirmed(),
		cs.EXPECT().GetSessionTicket().Return([]byte("session ticket"), nil),
	)
	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack).AnyTimes()

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	p := getLongHeaderPacket(t, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: time.Now()})

	select {
	case <-tc.conn.HandshakeComplete():
	case <-tc.conn.Context().Done():
		t.Fatal("connection context done")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	var foundSessionTicket, foundHandshakeDone, foundNewToken bool
	frames, _ := tc.conn.framer.AppendControlFrames(nil, protocol.MaxByteCount, time.Now(), protocol.Version1)
	for _, frame := range frames {
		switch f := frame.Frame.(type) {
		case *wire.CryptoFrame:
			assert.Equal(t, []byte("session ticket"), f.Data)
			foundSessionTicket = true
		case *wire.HandshakeDoneFrame:
			foundHandshakeDone = true
		case *wire.NewTokenFrame:
			assert.NotEmpty(t, f.Token)
			foundNewToken = true
		}
	}
	assert.True(t, foundSessionTicket)
	assert.True(t, foundHandshakeDone)
	assert.True(t, foundNewToken)

	// test teardown
	cs.EXPECT().Close()
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.conn.destroy(nil)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionHandshakeClient(t *testing.T) {
	t.Run("without preferred address", func(t *testing.T) {
		testConnectionHandshakeClient(t, false)
	})
	t.Run("with preferred address", func(t *testing.T) {
		testConnectionHandshakeClient(t, true)
	})
}

func testConnectionHandshakeClient(t *testing.T, usePreferredAddress bool) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptCryptoSetup(cs), connectionOptUnpacker(unpacker))
	tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	// the state transition is driven by processing of a CRYPTO frame
	hdr := &wire.ExtendedHeader{
		Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: protocol.Version1},
		PacketNumberLen: protocol.PacketNumberLen2,
	}
	data, err := (&wire.CryptoFrame{Data: []byte("foobar")}).Append(nil, protocol.Version1)
	require.NoError(t, err)

	tp := &wire.TransportParameters{
		OriginalDestinationConnectionID: tc.destConnID,
		MaxIdleTimeout:                  time.Hour,
	}
	preferredAddressConnID := protocol.ParseConnectionID([]byte{10, 8, 6, 4})
	preferredAddressResetToken := protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	if usePreferredAddress {
		tp.PreferredAddress = &wire.PreferredAddress{
			IPv4:                netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 42),
			IPv6:                netip.AddrPortFrom(netip.AddrFrom16([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), 13),
			ConnectionID:        preferredAddressConnID,
			StatelessResetToken: preferredAddressResetToken,
		}
	}

	packedFirstPacket := make(chan struct{})
	gomock.InOrder(
		cs.EXPECT().StartHandshake(gomock.Any()),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).DoAndReturn(
			func(b bool, bc protocol.ByteCount, t time.Time, v protocol.Version) (*coalescedPacket, error) {
				close(packedFirstPacket)
				return &coalescedPacket{buffer: getPacketBuffer(), longHdrPackets: []*longHeaderPacket{{header: hdr}}}, nil
			},
		),
		// initial keys are dropped when the first handshake packet is sent
		cs.EXPECT().DiscardInitialKeys(),
		// no more data to send
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
			&unpackedPacket{hdr: hdr, encryptionLevel: protocol.EncryptionHandshake, data: data}, nil,
		),
		cs.EXPECT().HandleMessage([]byte("foobar"), protocol.EncryptionHandshake),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventReceivedTransportParameters, TransportParameters: tp}),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventHandshakeComplete}),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
	)
	tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).Return(nil, nil).AnyTimes()

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	select {
	case <-packedFirstPacket:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	p := getLongHeaderPacket(t, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: time.Now()})

	select {
	case <-tc.conn.HandshakeComplete():
	case <-tc.conn.Context().Done():
		t.Fatal("connection context done")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	require.True(t, mockCtrl.Satisfied())
	// the handshake isn't confirmed until we receive a HANDSHAKE_DONE frame from the server

	data, err = (&wire.HandshakeDoneFrame{}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	done := make(chan struct{})
	tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).Return(nil, nil).AnyTimes()
	gomock.InOrder(
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
			&unpackedPacket{hdr: hdr, encryptionLevel: protocol.Encryption1RTT, data: data}, nil,
		),
		cs.EXPECT().SetHandshakeConfirmed(),
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(buf *packetBuffer, _ protocol.ByteCount, _ time.Time, _ protocol.Version) (shortHeaderPacket, error) {
				close(done)
				return shortHeaderPacket{}, errNothingToPack
			},
		),
	)
	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack).AnyTimes()
	p = getLongHeaderPacket(t, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: time.Now()})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	if usePreferredAddress {
		tc.connRunner.EXPECT().AddResetToken(preferredAddressResetToken, gomock.Any())
	}
	nextConnID := tc.conn.connIDManager.Get()
	if usePreferredAddress {
		require.Equal(t, preferredAddressConnID, nextConnID)
	}

	// test teardown
	cs.EXPECT().Close()
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	if usePreferredAddress {
		tc.connRunner.EXPECT().RemoveResetToken(preferredAddressResetToken)
	}
	tc.conn.destroy(nil)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnection0RTTTransportParameters(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptCryptoSetup(cs), connectionOptUnpacker(unpacker))
	tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	// the state transition is driven by processing of a CRYPTO frame
	hdr := &wire.ExtendedHeader{
		Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: protocol.Version1},
		PacketNumberLen: protocol.PacketNumberLen2,
	}
	data, err := (&wire.CryptoFrame{Data: []byte("foobar")}).Append(nil, protocol.Version1)
	require.NoError(t, err)

	restored := &wire.TransportParameters{
		ActiveConnectionIDLimit:        3,
		InitialMaxData:                 0x5000,
		InitialMaxStreamDataBidiLocal:  0x5000,
		InitialMaxStreamDataBidiRemote: 1000,
		InitialMaxStreamDataUni:        1000,
		MaxBidiStreamNum:               500,
		MaxUniStreamNum:                500,
	}
	new := *restored
	new.MaxBidiStreamNum-- // the server is not allowed to reduce the limit
	new.OriginalDestinationConnectionID = tc.destConnID

	packedFirstPacket := make(chan struct{})
	gomock.InOrder(
		cs.EXPECT().StartHandshake(gomock.Any()),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventRestoredTransportParameters, TransportParameters: restored}),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).DoAndReturn(
			func(b bool, bc protocol.ByteCount, t time.Time, v protocol.Version) (*coalescedPacket, error) {
				close(packedFirstPacket)
				return &coalescedPacket{buffer: getPacketBuffer(), longHdrPackets: []*longHeaderPacket{{header: hdr}}}, nil
			},
		),
		// initial keys are dropped when the first handshake packet is sent
		cs.EXPECT().DiscardInitialKeys(),
		// no more data to send
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
			&unpackedPacket{hdr: hdr, encryptionLevel: protocol.EncryptionHandshake, data: data}, nil,
		),
		cs.EXPECT().HandleMessage([]byte("foobar"), protocol.EncryptionHandshake),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventReceivedTransportParameters, TransportParameters: &new}),
		cs.EXPECT().ConnectionState().Return(handshake.ConnectionState{Used0RTT: true}),
		// cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		cs.EXPECT().Close(),
	)
	tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).Return(nil, nil).AnyTimes()
	tc.packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), protocol.Version1).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
	tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any())

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	select {
	case <-packedFirstPacket:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	p := getLongHeaderPacket(t, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: time.Now()})

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
		require.ErrorContains(t, err, "server sent reduced limits after accepting 0-RTT data")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionPacketPacing(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
	sender := NewMockSender(mockCtrl)

	// set a fixed RTT, so that the idle timeout doesn't interfere with this test
	var rttStats utils.RTTStats
	rttStats.UpdateRTT(scaleDuration(100*time.Millisecond), 0)

	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptSentPacketHandler(sph),
		connectionOptSender(sender),
		connectionOptHandshakeConfirmed(),
		connectionOptRTTStats(&rttStats),
	)
	sender.EXPECT().Run()

	sph.EXPECT().GetLossDetectionTimeout().Return(time.Now().Add(time.Hour)).AnyTimes()
	gomock.InOrder(
		// 1. allow 2 packets to be sent
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny),
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny),
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited),
		// 2. become pacing limited for 25ms
		sph.EXPECT().TimeUntilSend().DoAndReturn(func() time.Time { return time.Now().Add(scaleDuration(25 * time.Millisecond)) }),
		// 3. send another packet
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny),
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited),
		// 4. become pacing limited for 25ms...
		sph.EXPECT().TimeUntilSend().DoAndReturn(func() time.Time { return time.Now().Add(scaleDuration(25 * time.Millisecond)) }),
		// ... but this time we're still pacing limited when waking up.
		// In this case, we can only send an ACK.
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited),
		// 5. stop the test by becoming pacing limited forever
		sph.EXPECT().TimeUntilSend().Return(time.Now().Add(time.Hour)),
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
	)
	sph.EXPECT().ECNMode(gomock.Any()).AnyTimes()
	for i := 0; i < 3; i++ {
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), Version1).DoAndReturn(
			func(buf *packetBuffer, _ protocol.ByteCount, _ time.Time, _ protocol.Version) (shortHeaderPacket, error) {
				buf.Data = append(buf.Data, []byte("packet"+strconv.Itoa(i+1))...)
				return shortHeaderPacket{PacketNumber: protocol.PacketNumber(i + 1)}, nil
			},
		)
	}
	tc.packer.EXPECT().PackAckOnlyPacket(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ protocol.ByteCount, _ time.Time, _ protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
			buf := getPacketBuffer()
			buf.Data = []byte("ack")
			return shortHeaderPacket{PacketNumber: 1}, buf, nil
		},
	)
	sender.EXPECT().WouldBlock().AnyTimes()

	type sentPacket struct {
		time time.Time
		data []byte
	}
	sendChan := make(chan sentPacket, 10)
	sender.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(b *packetBuffer, _ uint16, _ protocol.ECN) {
		sendChan <- sentPacket{time: time.Now(), data: b.Data}
	}).Times(4)

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	tc.conn.scheduleSending()

	var times []time.Time
	for i := 0; i < 3; i++ {
		select {
		case b := <-sendChan:
			require.Equal(t, []byte("packet"+strconv.Itoa(i+1)), b.data)
			times = append(times, b.time)
		case <-time.After(scaleDuration(time.Second)):
			t.Fatal("timeout")
		}
	}
	select {
	case b := <-sendChan:
		require.Equal(t, []byte("ack"), b.data)
		times = append(times, b.time)
	case <-time.After(scaleDuration(time.Second)):
		t.Fatal("timeout")
	}

	require.WithinDuration(t, times[0], times[1], scaleDuration(5*time.Millisecond))
	require.WithinDuration(t, times[1].Add(scaleDuration(20*time.Millisecond)), times[2], scaleDuration(10*time.Millisecond))
	require.WithinDuration(t, times[2].Add(scaleDuration(20*time.Millisecond)), times[3], scaleDuration(10*time.Millisecond))

	time.Sleep(scaleDuration(25 * time.Millisecond)) // make sure that no more packets are sent
	require.True(t, mockCtrl.Satisfied())

	// test teardown
	sender.EXPECT().Close()
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.conn.destroy(nil)
	select {
	case <-sendChan:
		t.Fatal("should not have sent any more packets")
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionKeepAlive(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		testConnectionKeepAlive(t, true, true)
	})

	t.Run("disabled", func(t *testing.T) {
		testConnectionKeepAlive(t, false, false)
	})
}

func testConnectionKeepAlive(t *testing.T, enable, expectKeepAlive bool) {
	setRemoteIdleTimeout := func(t *testing.T, tc *testConnection, timeout time.Duration) {
		t.Helper()
		require.NoError(t, tc.conn.handleTransportParameters(&wire.TransportParameters{
			MaxIdleTimeout: timeout,
		}))
	}

	var keepAlivePeriod time.Duration
	if enable {
		keepAlivePeriod = time.Second
	}

	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	var rttStats utils.RTTStats
	rttStats.UpdateRTT(time.Millisecond, 0)
	tc := newServerTestConnection(t,
		mockCtrl,
		&Config{MaxIdleTimeout: time.Second, KeepAlivePeriod: keepAlivePeriod},
		false,
		connectionOptUnpacker(unpacker),
		connectionOptHandshakeConfirmed(),
		connectionOptRTTStats(&rttStats),
	)
	idleTimeout := scaleDuration(50 * time.Millisecond)
	setRemoteIdleTimeout(t, tc, idleTimeout)

	// Receive a packet. This starts the keep-alive timer.
	buf := getPacketBuffer()
	var err error
	buf.Data, err = wire.AppendShortHeader(buf.Data, tc.srcConnID, 1, protocol.PacketNumberLen1, protocol.KeyPhaseZero)
	require.NoError(t, err)
	buf.Data = append(buf.Data, []byte("packet")...)

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	var unpackTime, packTime time.Time
	done := make(chan struct{})
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).DoAndReturn(
		func(t time.Time, bytes []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
			unpackTime = time.Now()
			return protocol.PacketNumber(1), protocol.PacketNumberLen1, protocol.KeyPhaseZero, []byte{0} /* PADDING */, nil
		},
	)
	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack)

	switch expectKeepAlive {
	case true:
		// record the time of the keep-alive is sent
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(buffer *packetBuffer, count protocol.ByteCount, t time.Time, version protocol.Version) (shortHeaderPacket, error) {
				packTime = time.Now()
				close(done)
				return shortHeaderPacket{}, errNothingToPack
			},
		)
		tc.conn.handlePacket(receivedPacket{data: buf.Data, buffer: buf, rcvTime: time.Now()})
		select {
		case <-done:
			// the keep-alive packet should be sent after half the idle timeout
			diff := packTime.Sub(unpackTime)
			require.InDelta(t, diff.Seconds(), idleTimeout.Seconds()/2, scaleDuration(10*time.Millisecond).Seconds())
		case <-time.After(idleTimeout):
			t.Fatal("timeout")
		}
	case false: // if keep-alives are disabled, the connection will run into an idle timeout
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.handlePacket(receivedPacket{data: buf.Data, buffer: buf, rcvTime: time.Now()})
		select {
		case <-time.After(3 * time.Second):
			t.Fatal("timeout")
		case <-time.After(idleTimeout):
		}
	}

	// test teardown
	if expectKeepAlive {
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)
	}
	select {
	case err := <-errChan:
		if expectKeepAlive {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, &IdleTimeoutError{})
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

// Send a GSO batch, until we have no more data to send.
func TestConnectionGSOBatch(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		true,
		connectionOptHandshakeConfirmed(),
		connectionOptSentPacketHandler(sph),
	)

	// allow packets to be sent
	sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
	sph.EXPECT().TimeUntilSend().Return(time.Time{}).AnyTimes()
	sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	sph.EXPECT().GetLossDetectionTimeout().Return(time.Time{}).AnyTimes()
	sph.EXPECT().ECNMode(gomock.Any()).Return(protocol.ECT1).AnyTimes()

	maxPacketSize := tc.conn.maxPacketSize()
	var expectedData []byte
	for i := 0; i < 4; i++ {
		data := bytes.Repeat([]byte{byte(i)}, int(maxPacketSize))
		expectedData = append(expectedData, data...)

		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(buffer *packetBuffer, count protocol.ByteCount, t time.Time, version protocol.Version) (shortHeaderPacket, error) {
				buffer.Data = append(buffer.Data, data...)
				return shortHeaderPacket{PacketNumber: protocol.PacketNumber(i)}, nil
			},
		)
	}
	done := make(chan struct{})
	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack)
	tc.sendConn.EXPECT().Write(expectedData, uint16(maxPacketSize), protocol.ECT1).DoAndReturn(
		func([]byte, uint16, protocol.ECN) error { close(done); return nil },
	)

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	tc.conn.scheduleSending()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// test teardown
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.conn.destroy(nil)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

// Send a GSO batch, until a packet smaller than the maximum size is packed
func TestConnectionGSOBatchPacketSize(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		true,
		connectionOptHandshakeConfirmed(),
		connectionOptSentPacketHandler(sph),
	)

	// allow packets to be sent
	sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
	sph.EXPECT().TimeUntilSend().Return(time.Time{}).AnyTimes()
	sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	sph.EXPECT().GetLossDetectionTimeout().Return(time.Time{}).AnyTimes()
	sph.EXPECT().ECNMode(gomock.Any()).Return(protocol.ECT1).AnyTimes()

	maxPacketSize := tc.conn.maxPacketSize()
	var expectedData []byte
	var calls []any
	for i := 0; i < 4; i++ {
		var data []byte
		if i == 3 {
			data = bytes.Repeat([]byte{byte(i)}, int(maxPacketSize-1))
		} else {
			data = bytes.Repeat([]byte{byte(i)}, int(maxPacketSize))
		}
		expectedData = append(expectedData, data...)

		calls = append(calls, tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(buffer *packetBuffer, count protocol.ByteCount, t time.Time, version protocol.Version) (shortHeaderPacket, error) {
				buffer.Data = append(buffer.Data, data...)
				return shortHeaderPacket{PacketNumber: protocol.PacketNumber(10 + i)}, nil
			},
		))
	}
	// The smaller (fourth) packet concluded this GSO batch, but the send loop will immediately start composing the next batch.
	// We therefore send a "foobar", so we can check that we're actually generating two GSO batches.
	calls = append(calls,
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(buffer *packetBuffer, count protocol.ByteCount, t time.Time, version protocol.Version) (shortHeaderPacket, error) {
				buffer.Data = append(buffer.Data, []byte("foobar")...)
				return shortHeaderPacket{PacketNumber: protocol.PacketNumber(14)}, nil
			},
		),
	)
	calls = append(calls,
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack),
	)
	gomock.InOrder(calls...)

	done := make(chan struct{})
	gomock.InOrder(
		tc.sendConn.EXPECT().Write(expectedData, uint16(maxPacketSize), protocol.ECT1),
		tc.sendConn.EXPECT().Write([]byte("foobar"), uint16(maxPacketSize), protocol.ECT1).DoAndReturn(
			func([]byte, uint16, protocol.ECN) error { close(done); return nil },
		),
	)
	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	tc.conn.scheduleSending()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// test teardown
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.conn.destroy(nil)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionGSOBatchECN(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		true,
		connectionOptHandshakeConfirmed(),
		connectionOptSentPacketHandler(sph),
	)

	// allow packets to be sent
	ecnMode := protocol.ECT1
	sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
	sph.EXPECT().TimeUntilSend().Return(time.Time{}).AnyTimes()
	sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	sph.EXPECT().GetLossDetectionTimeout().Return(time.Time{}).AnyTimes()
	sph.EXPECT().ECNMode(gomock.Any()).DoAndReturn(func(bool) protocol.ECN { return ecnMode }).AnyTimes()

	// 3. Send a GSO batch, until the ECN marking changes.
	var expectedData []byte
	var calls []any
	maxPacketSize := tc.conn.maxPacketSize()
	for i := 0; i < 3; i++ {
		data := bytes.Repeat([]byte{byte(i)}, int(maxPacketSize))
		expectedData = append(expectedData, data...)

		calls = append(calls, tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(buffer *packetBuffer, count protocol.ByteCount, t time.Time, version protocol.Version) (shortHeaderPacket, error) {
				buffer.Data = append(buffer.Data, data...)
				if i == 2 {
					ecnMode = protocol.ECNCE
				}
				return shortHeaderPacket{PacketNumber: protocol.PacketNumber(20 + i)}, nil
			},
		))
	}
	// The smaller (fourth) packet concluded this GSO batch, but the send loop will immediately start composing the next batch.
	// We therefore send a "foobar", so we can check that we're actually generating two GSO batches.
	calls = append(calls,
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(buffer *packetBuffer, count protocol.ByteCount, t time.Time, version protocol.Version) (shortHeaderPacket, error) {
				buffer.Data = append(buffer.Data, []byte("foobar")...)
				return shortHeaderPacket{PacketNumber: protocol.PacketNumber(24)}, nil
			},
		),
	)
	calls = append(calls,
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack),
	)
	gomock.InOrder(calls...)

	done3 := make(chan struct{})
	tc.sendConn.EXPECT().Write(expectedData, uint16(maxPacketSize), protocol.ECT1)
	// TODO(#4829): check that the correct ECN marking is used
	tc.sendConn.EXPECT().Write([]byte("foobar"), uint16(maxPacketSize), gomock.Any()).DoAndReturn(
		func([]byte, uint16, protocol.ECN) error { close(done3); return nil },
	)

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	tc.conn.scheduleSending()

	select {
	case <-done3:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// test teardown
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.conn.destroy(nil)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionPTOProbePackets(t *testing.T) {
	t.Run("Initial", func(t *testing.T) {
		testConnectionPTOProbePackets(t, protocol.EncryptionInitial)
	})
	t.Run("Handshake", func(t *testing.T) {
		testConnectionPTOProbePackets(t, protocol.EncryptionHandshake)
	})
	t.Run("1-RTT", func(t *testing.T) {
		testConnectionPTOProbePackets(t, protocol.Encryption1RTT)
	})
}

func testConnectionPTOProbePackets(t *testing.T, encLevel protocol.EncryptionLevel) {
	mockCtrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptSentPacketHandler(sph),
	)

	var sendMode ackhandler.SendMode
	switch encLevel {
	case protocol.EncryptionInitial:
		sendMode = ackhandler.SendPTOInitial
	case protocol.EncryptionHandshake:
		sendMode = ackhandler.SendPTOHandshake
	case protocol.Encryption1RTT:
		sendMode = ackhandler.SendPTOAppData
	}

	sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
	sph.EXPECT().TimeUntilSend().AnyTimes()
	sph.EXPECT().SendMode(gomock.Any()).Return(sendMode)
	sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendNone)
	sph.EXPECT().ECNMode(gomock.Any())
	sph.EXPECT().QueueProbePacket(encLevel).Return(false)
	sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

	tc.packer.EXPECT().MaybePackProbePacket(encLevel, gomock.Any(), gomock.Any(), protocol.Version1).DoAndReturn(
		func(encLevel protocol.EncryptionLevel, maxSize protocol.ByteCount, t time.Time, version protocol.Version) (*coalescedPacket, error) {
			return &coalescedPacket{
				buffer:         getPacketBuffer(),
				shortHdrPacket: &shortHeaderPacket{PacketNumber: 1},
			}, nil
		},
	)
	done := make(chan struct{})
	tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).Do(
		func([]byte, uint16, protocol.ECN) error { close(done); return nil },
	)

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	tc.conn.scheduleSending()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// test teardown
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.conn.destroy(nil)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionCongestionControl(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptHandshakeConfirmed(),
		connectionOptSentPacketHandler(sph),
	)

	sph.EXPECT().TimeUntilSend().AnyTimes()
	sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
	sph.EXPECT().ECNMode(true).AnyTimes()
	sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).Times(2)
	sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAck)
	sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
	// Since we're already sending out packets, we don't expect any calls to PackAckOnlyPacket
	for i := 0; i < 2; i++ {
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(buffer *packetBuffer, count protocol.ByteCount, t time.Time, version protocol.Version) (shortHeaderPacket, error) {
				buffer.Data = append(buffer.Data, []byte("foobar")...)
				return shortHeaderPacket{PacketNumber: protocol.PacketNumber(i)}, nil
			},
		)
	}
	tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any())
	done1 := make(chan struct{})
	tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).Do(
		func([]byte, uint16, protocol.ECN) error { close(done1); return nil },
	)

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	tc.conn.scheduleSending()
	select {
	case <-done1:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	require.True(t, mockCtrl.Satisfied())

	// Now that we're congestion limited, we can only send an ack-only packet
	done2 := make(chan struct{})
	sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAck)
	tc.packer.EXPECT().PackAckOnlyPacket(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(protocol.ByteCount, time.Time, protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
			close(done2)
			return shortHeaderPacket{}, nil, errNothingToPack
		},
	)
	tc.conn.scheduleSending()
	select {
	case <-done2:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	require.True(t, mockCtrl.Satisfied())

	// If the send mode is "none", we can't even send an ack-only packet
	sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendNone)
	tc.conn.scheduleSending()
	time.Sleep(scaleDuration(10 * time.Millisecond)) // make sure there are no calls to the packer

	// test teardown
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.conn.destroy(nil)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionSendQueue(t *testing.T) {
	t.Run("with GSO", func(t *testing.T) {
		testConnectionSendQueue(t, true)
	})
	t.Run("without GSO", func(t *testing.T) {
		testConnectionSendQueue(t, false)
	})
}

func testConnectionSendQueue(t *testing.T, enableGSO bool) {
	mockCtrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
	sender := NewMockSender(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		enableGSO,
		connectionOptSender(sender),
		connectionOptHandshakeConfirmed(),
		connectionOptSentPacketHandler(sph),
	)

	sender.EXPECT().Run().MaxTimes(1)
	sender.EXPECT().WouldBlock()
	sender.EXPECT().WouldBlock().Return(true).Times(2)
	available := make(chan struct{})
	blocked := make(chan struct{})
	sender.EXPECT().Available().DoAndReturn(
		func() <-chan struct{} {
			close(blocked)
			return available
		},
	)
	sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
	sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
	sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
	sph.EXPECT().ECNMode(gomock.Any()).AnyTimes()
	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
		shortHeaderPacket{PacketNumber: protocol.PacketNumber(1)}, nil,
	)
	sender.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any())

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	tc.conn.scheduleSending()

	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	require.True(t, mockCtrl.Satisfied())

	// now make room in the send queue
	sender.EXPECT().WouldBlock().AnyTimes()
	unblocked := make(chan struct{})
	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(*packetBuffer, protocol.ByteCount, time.Time, protocol.Version) (shortHeaderPacket, error) {
			close(unblocked)
			return shortHeaderPacket{}, errNothingToPack
		},
	)
	available <- struct{}{}
	select {
	case <-unblocked:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// test teardown
	sender.EXPECT().Close()
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.conn.destroy(nil)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

func getVersionNegotiationPacket(src, dest protocol.ConnectionID, versions []protocol.Version) receivedPacket {
	b := wire.ComposeVersionNegotiation(
		protocol.ArbitraryLenConnectionID(src.Bytes()),
		protocol.ArbitraryLenConnectionID(dest.Bytes()),
		versions,
	)
	return receivedPacket{
		rcvTime: time.Now(),
		data:    b,
		buffer:  getPacketBuffer(),
	}
}

func TestConnectionVersionNegotiation(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	tc := newClientTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(tr),
	)

	tc.packer.EXPECT().PackCoalescedPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	var tracerVersions []logging.Version
	gomock.InOrder(
		tracer.EXPECT().ReceivedVersionNegotiationPacket(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_, _ protocol.ArbitraryLenConnectionID, versions []logging.Version) {
			tracerVersions = versions
		}),
		tracer.EXPECT().NegotiatedVersion(protocol.Version2, gomock.Any(), gomock.Any()),
		tc.connRunner.EXPECT().Remove(gomock.Any()),
	)

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	tc.conn.handlePacket(getVersionNegotiationPacket(
		tc.destConnID,
		tc.srcConnID,
		[]protocol.Version{1234, protocol.Version2},
	))

	select {
	case err := <-errChan:
		var rerr *errCloseForRecreating
		require.ErrorAs(t, err, &rerr)
		require.Equal(t, rerr.nextVersion, protocol.Version2)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	require.Contains(t, tracerVersions, protocol.Version(1234))
	require.Contains(t, tracerVersions, protocol.Version2)
}

func TestConnectionVersionNegotiationNoMatch(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	tc := newClientTestConnection(t,
		mockCtrl,
		&Config{Versions: []protocol.Version{protocol.Version1}},
		false,
		connectionOptTracer(tr),
	)

	tc.packer.EXPECT().PackCoalescedPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	var tracerVersions []logging.Version
	tracer.EXPECT().ReceivedVersionNegotiationPacket(gomock.Any(), gomock.Any(), gomock.Any()).Do(
		func(_, _ protocol.ArbitraryLenConnectionID, versions []logging.Version) { tracerVersions = versions },
	)
	tracer.EXPECT().ClosedConnection(gomock.Any())
	tracer.EXPECT().Close()
	tc.connRunner.EXPECT().Remove(gomock.Any())

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	tc.conn.handlePacket(getVersionNegotiationPacket(
		tc.destConnID,
		tc.srcConnID,
		[]protocol.Version{protocol.Version2},
	))

	select {
	case err := <-errChan:
		var verr *VersionNegotiationError
		require.ErrorAs(t, err, &verr)
		require.Contains(t, verr.Theirs, protocol.Version2)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	require.Contains(t, tracerVersions, protocol.Version2)
}

func TestConnectionVersionNegotiationInvalidPackets(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	tc := newClientTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(tr),
	)

	// offers the current version
	tracer.EXPECT().DroppedPacket(logging.PacketTypeVersionNegotiation, gomock.Any(), gomock.Any(), logging.PacketDropUnexpectedVersion)
	vnp := getVersionNegotiationPacket(
		tc.destConnID,
		tc.srcConnID,
		[]protocol.Version{1234, protocol.Version1},
	)
	require.False(t, tc.conn.handlePacketImpl(vnp))
	require.True(t, mockCtrl.Satisfied())

	// unparseable, since it's missing 2 bytes
	tracer.EXPECT().DroppedPacket(logging.PacketTypeVersionNegotiation, gomock.Any(), gomock.Any(), logging.PacketDropHeaderParseError)
	vnp.data = vnp.data[:len(vnp.data)-2]
	require.False(t, tc.conn.handlePacketImpl(vnp))
}

func getRetryPacket(t *testing.T, src, dest, origDest protocol.ConnectionID, token []byte) receivedPacket {
	hdr := wire.Header{
		Type:             protocol.PacketTypeRetry,
		SrcConnectionID:  src,
		DestConnectionID: dest,
		Token:            token,
		Version:          protocol.Version1,
	}
	b, err := (&wire.ExtendedHeader{Header: hdr}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	tag := handshake.GetRetryIntegrityTag(b, origDest, protocol.Version1)
	b = append(b, tag[:]...)
	return receivedPacket{
		rcvTime: time.Now(),
		data:    b,
		buffer:  getPacketBuffer(),
	}
}

func TestConnectionRetryDrops(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newClientTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(tr),
		connectionOptUnpacker(unpacker),
	)

	newConnID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})

	// invalid integrity tag
	tracer.EXPECT().DroppedPacket(logging.PacketTypeRetry, gomock.Any(), gomock.Any(), logging.PacketDropPayloadDecryptError)
	retry := getRetryPacket(t, newConnID, tc.srcConnID, tc.destConnID, []byte("foobar"))
	retry.data[len(retry.data)-1]++
	require.False(t, tc.conn.handlePacketImpl(retry))
	require.True(t, mockCtrl.Satisfied())

	// receive a retry that doesn't change the connection ID
	tracer.EXPECT().DroppedPacket(logging.PacketTypeRetry, gomock.Any(), gomock.Any(), logging.PacketDropUnexpectedPacket)
	retry = getRetryPacket(t, tc.destConnID, tc.srcConnID, tc.destConnID, []byte("foobar"))
	require.False(t, tc.conn.handlePacketImpl(retry))
}

func TestConnectionRetryAfterReceivedPacket(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newClientTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(tr),
		connectionOptUnpacker(unpacker),
	)

	// receive a regular packet
	tracer.EXPECT().NegotiatedVersion(gomock.Any(), gomock.Any(), gomock.Any())
	tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
	regular := getPacketWithPacketType(t, tc.srcConnID, protocol.PacketTypeInitial, 200)
	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
		&unpackedPacket{
			hdr:             &wire.ExtendedHeader{Header: wire.Header{Type: protocol.PacketTypeInitial}},
			encryptionLevel: protocol.EncryptionInitial,
		}, nil,
	)
	require.True(t, tc.conn.handlePacketImpl(receivedPacket{
		data:    regular,
		buffer:  getPacketBuffer(),
		rcvTime: time.Now(),
	}))

	// receive a retry
	retry := getRetryPacket(t, tc.destConnID, tc.srcConnID, tc.destConnID, []byte("foobar"))
	tracer.EXPECT().DroppedPacket(logging.PacketTypeRetry, gomock.Any(), gomock.Any(), logging.PacketDropUnexpectedPacket)
	require.False(t, tc.conn.handlePacketImpl(retry))
}

// When the connection is closed before sending the first packet,
// we don't send a CONNECTION_CLOSE.
// This can happen if there's something wrong the tls.Config, and
// crypto/tls refuses to start the handshake.
func TestConnectionEarlyClose(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	cryptoSetup := mocks.NewMockCryptoSetup(mockCtrl)
	tc := newClientTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(tr),
		connectionOptCryptoSetup(cryptoSetup),
	)

	tc.conn.sentFirstPacket = false
	tracer.EXPECT().ClosedConnection(gomock.Any())
	tracer.EXPECT().Close()
	cryptoSetup.EXPECT().StartHandshake(gomock.Any()).Do(func(context.Context) error {
		tc.conn.closeLocal(errors.New("early error"))
		return nil
	})
	cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
	cryptoSetup.EXPECT().Close()
	tc.connRunner.EXPECT().Remove(gomock.Any())

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	select {
	case err := <-errChan:
		require.Error(t, err)
		require.ErrorContains(t, err, "early error")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}
