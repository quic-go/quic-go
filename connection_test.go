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
	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/mocks"
	mockackhandler "github.com/quic-go/quic-go/internal/mocks/ackhandler"
	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/synctest"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type testConnectionOpt func(*Conn)

func connectionOptCryptoSetup(cs *mocks.MockCryptoSetup) testConnectionOpt {
	return func(conn *Conn) { conn.cryptoStreamHandler = cs }
}

func connectionOptConnFlowController(cfc flowcontrol.ConnectionFlowController) testConnectionOpt {
	return func(conn *Conn) { conn.connFlowController = cfc }
}

func connectionOptTracer(tr *logging.ConnectionTracer) testConnectionOpt {
	return func(conn *Conn) { conn.tracer = tr }
}

func connectionOptSentPacketHandler(sph ackhandler.SentPacketHandler) testConnectionOpt {
	return func(conn *Conn) { conn.sentPacketHandler = sph }
}

func connectionOptReceivedPacketHandler(rph ackhandler.ReceivedPacketHandler) testConnectionOpt {
	return func(conn *Conn) { conn.receivedPacketHandler = rph }
}

func connectionOptUnpacker(u unpacker) testConnectionOpt {
	return func(conn *Conn) { conn.unpacker = u }
}

func connectionOptSender(s sender) testConnectionOpt {
	return func(conn *Conn) { conn.sendQueue = s }
}

func connectionOptHandshakeConfirmed() testConnectionOpt {
	return func(conn *Conn) {
		conn.handshakeComplete = true
		conn.handshakeConfirmed = true
	}
}

func connectionOptRTT(rtt time.Duration) testConnectionOpt {
	var rttStats utils.RTTStats
	rttStats.UpdateRTT(rtt, 0)
	return func(conn *Conn) { conn.rttStats = &rttStats }
}

func connectionOptRetrySrcConnID(rcid protocol.ConnectionID) testConnectionOpt {
	return func(conn *Conn) { conn.retrySrcConnID = &rcid }
}

type testConnection struct {
	conn       *Conn
	connRunner *MockConnRunner
	sendConn   *MockSendConn
	packer     *MockPacker
	destConnID protocol.ConnectionID
	srcConnID  protocol.ConnectionID
	remoteAddr *net.UDPAddr
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
	wc := newConnection(
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
		newStatelessResetter(nil),
		populateConfig(config),
		&tls.Config{},
		handshake.NewTokenGenerator(handshake.TokenProtectorKey{}),
		false,
		1337*time.Millisecond,
		nil,
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.Nil(t, wc.testHooks)
	conn := wc.Conn
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
		remoteAddr: remoteAddr,
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
		newStatelessResetter(nil),
		populateConfig(config),
		&tls.Config{ServerName: "quic-go.net"},
		0,
		enable0RTT,
		false,
		nil,
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.Nil(t, conn.testHooks)
	conn.packer = packer
	for _, opt := range opts {
		opt(conn.Conn)
	}
	return &testConnection{
		conn:       conn.Conn,
		connRunner: connRunner,
		sendConn:   sendConn,
		packer:     packer,
		destConnID: destConnID,
		srcConnID:  srcConnID,
	}
}

func TestConnectionHandleStreamRelatedFrames(t *testing.T) {
	const id protocol.StreamID = 5
	connID := protocol.ConnectionID{}

	tests := []struct {
		name  string
		frame wire.Frame
	}{
		{name: "RESET_STREAM", frame: &wire.ResetStreamFrame{StreamID: id, ErrorCode: 42, FinalSize: 1337}},
		{name: "STOP_SENDING", frame: &wire.StopSendingFrame{StreamID: id, ErrorCode: 42}},
		{name: "MAX_STREAM_DATA", frame: &wire.MaxStreamDataFrame{StreamID: id, MaximumStreamData: 1337}},
		{name: "STREAM_DATA_BLOCKED", frame: &wire.StreamDataBlockedFrame{StreamID: id, MaximumStreamData: 42}},
		{name: "STREAM_FRAME", frame: &wire.StreamFrame{StreamID: id, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}, Offset: 1337}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tc := newServerTestConnection(t, gomock.NewController(t), nil, false)
			data, err := test.frame.Append(nil, protocol.Version1)
			require.NoError(t, err)
			_, _, _, err = tc.conn.handleFrames(data, connID, protocol.Encryption1RTT, nil, monotime.Now())
			require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
		})
	}
}

func TestConnectionHandleConnectionFlowControlFrames(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	connFC := flowcontrol.NewConnectionFlowController(0, 0, nil, &utils.RTTStats{}, utils.DefaultLogger)
	require.Zero(t, connFC.SendWindowSize())
	tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptConnFlowController(connFC))
	now := monotime.Now()
	connID := protocol.ConnectionID{}
	// MAX_DATA frame
	_, err := tc.conn.handleFrame(&wire.MaxDataFrame{MaximumData: 1337}, protocol.Encryption1RTT, connID, now)
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(1337), connFC.SendWindowSize())
	// DATA_BLOCKED frame
	_, err = tc.conn.handleFrame(&wire.DataBlockedFrame{MaximumData: 1337}, protocol.Encryption1RTT, connID, now)
	require.NoError(t, err)
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
			_, err := tc.conn.handleFrame(test.Frame, protocol.Encryption1RTT, protocol.ConnectionID{}, monotime.Now())
			require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
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
		ErrorMessage: "foobar",
	}
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	b := getPacketBuffer()
	b.Data = append(b.Data, []byte("connection close")...)
	tc.packer.EXPECT().PackConnectionClose(expectedErr, gomock.Any(), protocol.Version1).Return(&coalescedPacket{buffer: b}, nil)
	tc.sendConn.EXPECT().Write([]byte("connection close"), gomock.Any(), gomock.Any())
	tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
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
		ErrorMessage: "foobar",
	}
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	b := getPacketBuffer()
	b.Data = append(b.Data, []byte("connection close")...)
	tc.packer.EXPECT().PackApplicationClose(expectedErr, gomock.Any(), protocol.Version1).Return(&coalescedPacket{buffer: b}, nil)
	tc.sendConn.EXPECT().Write([]byte("connection close"), gomock.Any(), gomock.Any())
	tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	gomock.InOrder(
		tracer.EXPECT().ClosedConnection(expectedErr),
		tracer.EXPECT().Close(),
	)

	go func() { errChan <- tc.conn.run() }()
	tc.conn.CloseWithError(1337, "foobar")

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

func getLongHeaderPacket(t *testing.T, remoteAddr net.Addr, extHdr *wire.ExtendedHeader, data []byte) receivedPacket {
	t.Helper()
	b, err := extHdr.Append(nil, protocol.Version1)
	require.NoError(t, err)
	return receivedPacket{
		remoteAddr: remoteAddr,
		data:       append(b, data...),
		buffer:     getPacketBuffer(),
		rcvTime:    monotime.Now(),
	}
}

func getShortHeaderPacket(t *testing.T, remoteAddr net.Addr, connID protocol.ConnectionID, pn protocol.PacketNumber, data []byte) receivedPacket {
	t.Helper()
	b, err := wire.AppendShortHeader(nil, connID, pn, protocol.PacketNumberLen2, protocol.KeyPhaseOne)
	require.NoError(t, err)
	return receivedPacket{
		remoteAddr: remoteAddr,
		data:       append(b, data...),
		buffer:     getPacketBuffer(),
		rcvTime:    monotime.Now(),
	}
}

func TestConnectionServerInvalidPackets(t *testing.T) {
	t.Run("Retry", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(tr))

		p := getLongHeaderPacket(t,
			tc.remoteAddr,
			&wire.ExtendedHeader{Header: wire.Header{
				Type:             protocol.PacketTypeRetry,
				DestConnectionID: tc.conn.origDestConnID,
				SrcConnectionID:  tc.srcConnID,
				Version:          tc.conn.version,
				Token:            []byte("foobar"),
			}},
			make([]byte, 16), /* Retry integrity tag */
		)
		tracer.EXPECT().DroppedPacket(logging.PacketTypeRetry, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropUnexpectedPacket)
		wasProcessed, err := tc.conn.handleOnePacket(p)
		require.NoError(t, err)
		require.False(t, wasProcessed)
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
		wasProcessed, err := tc.conn.handleOnePacket(receivedPacket{data: b, buffer: getPacketBuffer()})
		require.NoError(t, err)
		require.False(t, wasProcessed)
	})

	t.Run("unsupported version", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(tr))

		p := getLongHeaderPacket(t,
			tc.remoteAddr,
			&wire.ExtendedHeader{
				Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: 1234},
				PacketNumberLen: protocol.PacketNumberLen2,
			},
			nil,
		)
		tracer.EXPECT().DroppedPacket(logging.PacketTypeNotDetermined, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropUnsupportedVersion)
		wasProcessed, err := tc.conn.handleOnePacket(p)
		require.NoError(t, err)
		require.False(t, wasProcessed)
	})

	t.Run("invalid header", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(tr))

		p := getLongHeaderPacket(t,
			tc.remoteAddr,
			&wire.ExtendedHeader{
				Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: Version1},
				PacketNumberLen: protocol.PacketNumberLen2,
			},
			nil,
		)
		p.data[0] ^= 0x40 // unset the QUIC bit
		tracer.EXPECT().DroppedPacket(logging.PacketTypeNotDetermined, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropHeaderParseError)
		wasProcessed, err := tc.conn.handleOnePacket(p)
		require.NoError(t, err)
		require.False(t, wasProcessed)
	})
}

func TestConnectionClientDrop0RTT(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptTracer(tr))

	p := getLongHeaderPacket(t,
		tc.remoteAddr,
		&wire.ExtendedHeader{
			Header:          wire.Header{Type: protocol.PacketType0RTT, Length: 2, Version: protocol.Version1},
			PacketNumberLen: protocol.PacketNumberLen2,
		},
		nil,
	)
	tracer.EXPECT().DroppedPacket(logging.PacketType0RTT, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropUnexpectedPacket)
	wasProcessed, err := tc.conn.handleOnePacket(p)
	require.NoError(t, err)
	require.False(t, wasProcessed)
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
	packet := getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	packet.ecn = protocol.ECNCE
	rcvTime := monotime.Now().Add(-10 * time.Second)
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
	wasProcessed, err := tc.conn.handleOnePacket(packet)
	require.NoError(t, err)
	require.True(t, wasProcessed)
	require.True(t, mockCtrl.Satisfied())

	// receive a duplicate of this packet
	packet = getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	rph.EXPECT().IsPotentiallyDuplicate(protocol.PacketNumber(0x1337), protocol.EncryptionInitial).Return(true)
	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(&unpackedPacket{
		encryptionLevel: protocol.EncryptionInitial,
		hdr:             &unpackedHdr,
		data:            []byte{0}, // one PADDING frame
	}, nil)
	tracer.EXPECT().DroppedPacket(logging.PacketTypeInitial, protocol.PacketNumber(0x1337), protocol.ByteCount(len(packet.data)), logging.PacketDropDuplicate)
	wasProcessed, err = tc.conn.handleOnePacket(packet)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.True(t, mockCtrl.Satisfied())

	// receive a short header packet
	packet = getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, 0x37, nil)
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
	wasProcessed, err = tc.conn.handleOnePacket(packet)
	require.NoError(t, err)
	require.True(t, wasProcessed)
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

	packet := getLongHeaderPacket(t, tc.remoteAddr, hdr1, nil)
	packet2 := getLongHeaderPacket(t, tc.remoteAddr, hdr2, nil)
	packet3 := getLongHeaderPacket(t, tc.remoteAddr, hdr3, nil)
	packet.data = append(packet.data, packet2.data...)
	packet.data = append(packet.data, packet3.data...)
	packet.ecn = protocol.ECT1
	rcvTime := monotime.Now()
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
	wasProcessed, err := tc.conn.handleOnePacket(packet)
	require.NoError(t, err)
	require.True(t, wasProcessed)
}

func TestConnectionUnpackFailuresFatal(t *testing.T) {
	t.Run("other errors", func(t *testing.T) {
		require.ErrorIs(t,
			testConnectionUnpackFailureFatal(t, &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError}),
			&qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError},
		)
	})

	t.Run("invalid reserved bits", func(t *testing.T) {
		require.ErrorIs(t,
			testConnectionUnpackFailureFatal(t, wire.ErrInvalidReservedBits),
			&qerr.TransportError{ErrorCode: qerr.ProtocolViolation},
		)
	})
}

func testConnectionUnpackFailureFatal(t *testing.T, unpackErr error) error {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptUnpacker(unpacker),
	)

	tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any())
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(0), protocol.PacketNumberLen(0), protocol.KeyPhaseBit(0), nil, unpackErr)
	tc.packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), protocol.Version1).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any())
	tc.conn.handlePacket(getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, 0x42, nil))

	select {
	case err := <-errChan:
		require.Error(t, err)
		return err
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	return nil
}

func TestConnectionUnpackFailureDropped(t *testing.T) {
	t.Run("keys dropped", func(t *testing.T) {
		testConnectionUnpackFailureDropped(t, handshake.ErrKeysDropped, logging.PacketDropKeyUnavailable)
	})

	t.Run("decryption failed", func(t *testing.T) {
		testConnectionUnpackFailureDropped(t, handshake.ErrDecryptionFailed, logging.PacketDropPayloadDecryptError)
	})

	t.Run("header parse error", func(t *testing.T) {
		testConnectionUnpackFailureDropped(t, &headerParseError{err: assert.AnError}, logging.PacketDropHeaderParseError)
	})
}

func testConnectionUnpackFailureDropped(t *testing.T, unpackErr error, packetDropReason logging.PacketDropReason) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptUnpacker(unpacker),
		connectionOptTracer(tr),
	)

	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(0), protocol.PacketNumberLen(0), protocol.KeyPhaseBit(0), nil, unpackErr)
	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	done := make(chan struct{})
	tracer.EXPECT().DroppedPacket(gomock.Any(), protocol.InvalidPacketNumber, gomock.Any(), packetDropReason).Do(
		func(logging.PacketType, protocol.PacketNumber, protocol.ByteCount, logging.PacketDropReason) {
			close(done)
		},
	)
	tc.conn.handlePacket(getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, 0x42, nil))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// test teardown
	tracer.EXPECT().ClosedConnection(gomock.Any())
	tracer.EXPECT().Close()
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.conn.destroy(nil)
	select {
	case <-errChan:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
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
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(tr),
		connectionOptUnpacker(unpacker),
	)
	ccf, err := (&wire.ConnectionCloseFrame{
		ErrorCode:    uint64(qerr.StreamLimitError),
		ReasonPhrase: "foobar",
	}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(1), protocol.PacketNumberLen2, protocol.KeyPhaseBit(0), ccf, nil)
	tracer.EXPECT().ReceivedShortHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

	expectedErr := &qerr.TransportError{ErrorCode: qerr.StreamLimitError, Remote: true}
	tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any())
	tracerErrChan := make(chan error, 1)
	tracer.EXPECT().ClosedConnection(gomock.Any()).Do(func(e error) { tracerErrChan <- e })
	tracer.EXPECT().Close()

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	p := getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, 1, []byte("encrypted"))
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: monotime.Now()})

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
}

func TestConnectionIdleTimeoutDuringHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const timeout = 7 * time.Second
		mockCtrl := gomock.NewController(t)
		tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			&Config{HandshakeIdleTimeout: timeout},
			false,
			connectionOptTracer(tr),
		)
		tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).AnyTimes()
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		gomock.InOrder(
			tracer.EXPECT().ClosedConnection(&IdleTimeoutError{}),
			tracer.EXPECT().Close(),
		)
		start := monotime.Now()
		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, &IdleTimeoutError{})
			require.Equal(t, timeout, monotime.Since(start))
		case <-time.After(timeout + time.Nanosecond):
			t.Fatal("timeout")
		}
	})
}

func TestConnectionHandshakeIdleTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			&Config{HandshakeIdleTimeout: 7 * time.Second},
			false,
			connectionOptTracer(tr),
			func(c *Conn) { c.creationTime = monotime.Now().Add(-20 * time.Second) },
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
	})
}

func TestConnectionTransportParameters(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tr, tracer := mocklogging.NewMockConnectionTracer(mockCtrl)
	connFC := flowcontrol.NewConnectionFlowController(0, 0, nil, &utils.RTTStats{}, utils.DefaultLogger)
	require.Zero(t, connFC.SendWindowSize())
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(tr),
		connectionOptConnFlowController(connFC),
	)
	_, err := tc.conn.OpenStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})
	_, err = tc.conn.OpenUniStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})
	tracer.EXPECT().ReceivedTransportParameters(gomock.Any())
	params := &wire.TransportParameters{
		MaxIdleTimeout:                90 * time.Second,
		InitialMaxStreamDataBidiLocal: 0x5000,
		InitialMaxData:                1337,
		ActiveConnectionIDLimit:       3,
		// marshaling always sets it to this value
		MaxUDPPayloadSize:               protocol.MaxPacketBufferSize,
		OriginalDestinationConnectionID: tc.destConnID,
		MaxBidiStreamNum:                1,
		MaxUniStreamNum:                 1,
	}
	require.NoError(t, tc.conn.handleTransportParameters(params))
	require.Equal(t, protocol.ByteCount(1337), connFC.SendWindowSize())
	_, err = tc.conn.OpenStream()
	require.NoError(t, err)
	_, err = tc.conn.OpenUniStream()
	require.NoError(t, err)
}

func TestConnectionHandleMaxStreamsFrame(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		connFC := flowcontrol.NewConnectionFlowController(0, 0, nil, &utils.RTTStats{}, utils.DefaultLogger)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptConnFlowController(connFC))
		tc.conn.handleTransportParameters(&wire.TransportParameters{})

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		uniStreamChan := make(chan error)
		go func() {
			_, err := tc.conn.OpenUniStreamSync(ctx)
			uniStreamChan <- err
		}()
		bidiStreamChan := make(chan error)
		go func() {
			_, err := tc.conn.OpenStreamSync(ctx)
			bidiStreamChan <- err
		}()

		synctest.Wait()
		select {
		case <-uniStreamChan:
			t.Fatal("uni stream should be blocked")
		case <-bidiStreamChan:
			t.Fatal("bidi stream should be blocked")
		default:
		}

		// MAX_STREAMS frame for bidirectional stream
		_, err := tc.conn.handleFrame(
			&wire.MaxStreamsFrame{Type: protocol.StreamTypeBidi, MaxStreamNum: 10},
			protocol.Encryption1RTT,
			protocol.ConnectionID{},
			monotime.Now(),
		)
		require.NoError(t, err)

		synctest.Wait()

		select {
		case <-uniStreamChan:
			t.Fatal("uni stream should be blocked")
		default:
		}
		select {
		case err := <-bidiStreamChan:
			require.NoError(t, err)
		default:
			t.Fatal("bidi stream should be unblocked")
		}

		// MAX_STREAMS frame for bidirectional stream
		_, err = tc.conn.handleFrame(
			&wire.MaxStreamsFrame{Type: protocol.StreamTypeUni, MaxStreamNum: 10},
			protocol.Encryption1RTT,
			protocol.ConnectionID{},
			monotime.Now(),
		)
		require.NoError(t, err)

		synctest.Wait()
		select {
		case err := <-uniStreamChan:
			require.NoError(t, err)
		default:
			t.Fatal("timeout")
		}
	})
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

	cs.EXPECT().DiscardInitialKeys().Times(2)
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
	p := getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: monotime.Now()})

	select {
	case <-tc.conn.HandshakeComplete():
	case <-tc.conn.Context().Done():
		t.Fatal("connection context done")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	var foundSessionTicket, foundHandshakeDone, foundNewToken bool
	frames, _, _ := tc.conn.framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
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
			func(b bool, bc protocol.ByteCount, t monotime.Time, v protocol.Version) (*coalescedPacket, error) {
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

	p := getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: monotime.Now()})

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
		cs.EXPECT().DiscardInitialKeys(),
		cs.EXPECT().SetHandshakeConfirmed(),
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(buf *packetBuffer, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version) (shortHeaderPacket, error) {
				close(done)
				return shortHeaderPacket{}, errNothingToPack
			},
		),
	)
	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack).AnyTimes()
	p = getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: monotime.Now()})

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
			func(b bool, bc protocol.ByteCount, t monotime.Time, v protocol.Version) (*coalescedPacket, error) {
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
	tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any())

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	select {
	case <-packedFirstPacket:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	p := getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: monotime.Now()})

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
		require.ErrorContains(t, err, "server sent reduced limits after accepting 0-RTT data")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionReceivePrioritization(t *testing.T) {
	t.Run("handshake complete", func(t *testing.T) {
		events := testConnectionReceivePrioritization(t, true, 5)
		require.Equal(t, []string{"unpack", "unpack", "unpack", "unpack", "unpack", "pack"}, events)
	})

	// before handshake completion, we trigger packing of a new packet every time we receive a packet
	t.Run("handshake not complete", func(t *testing.T) {
		events := testConnectionReceivePrioritization(t, false, 5)
		require.Equal(t, []string{
			"unpack", "pack",
			"unpack", "pack",
			"unpack", "pack",
			"unpack", "pack",
			"unpack", "pack",
		}, events)
	})
}

func testConnectionReceivePrioritization(t *testing.T, handshakeComplete bool, numPackets int) []string {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	opts := []testConnectionOpt{connectionOptUnpacker(unpacker)}
	if handshakeComplete {
		opts = append(opts, connectionOptHandshakeConfirmed())
	}
	tc := newServerTestConnection(t, mockCtrl, nil, false, opts...)

	var events []string
	var counter int
	var testDone bool
	done := make(chan struct{})
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).DoAndReturn(
		func(rcvTime monotime.Time, data []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
			counter++
			if counter == numPackets {
				testDone = true
			}
			events = append(events, "unpack")
			return protocol.PacketNumber(counter), protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{0, 1} /* PADDING, PING */, nil
		},
	).Times(numPackets)
	switch handshakeComplete {
	case false:
		tc.packer.EXPECT().PackCoalescedPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(b bool, bc protocol.ByteCount, t monotime.Time, v protocol.Version) (*coalescedPacket, error) {
				events = append(events, "pack")
				if testDone {
					close(done)
				}
				return nil, nil
			},
		).AnyTimes()
	case true:
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(b *packetBuffer, bc protocol.ByteCount, t monotime.Time, v protocol.Version) (shortHeaderPacket, error) {
				events = append(events, "pack")
				if testDone {
					close(done)
				}
				return shortHeaderPacket{}, errNothingToPack
			},
		).AnyTimes()
	}

	for i := range numPackets {
		tc.conn.handlePacket(getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, protocol.PacketNumber(i), []byte("foobar")))
	}

	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

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
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	return events
}

func TestConnectionPacketBuffering(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	tracer, tr := mocklogging.NewMockConnectionTracer(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptUnpacker(unpacker),
		connectionOptCryptoSetup(cs),
		connectionOptTracer(tracer),
	)

	tr.EXPECT().NegotiatedVersion(gomock.Any(), gomock.Any(), gomock.Any())
	tr.EXPECT().StartedConnection(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
	tr.EXPECT().DroppedEncryptionLevel(gomock.Any())
	cs.EXPECT().DiscardInitialKeys()

	hdr1 := wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeHandshake,
			DestConnectionID: tc.srcConnID,
			SrcConnectionID:  tc.destConnID,
			Length:           8,
			Version:          protocol.Version1,
		},
		PacketNumberLen: protocol.PacketNumberLen1,
		PacketNumber:    1,
	}
	hdr2 := hdr1
	hdr2.PacketNumber = 2
	cs.EXPECT().StartHandshake(gomock.Any())
	buffered := make(chan struct{})
	gomock.InOrder(
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(nil, handshake.ErrKeysNotYetAvailable),
		tr.EXPECT().BufferedPacket(logging.PacketTypeHandshake, gomock.Any()),
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(nil, handshake.ErrKeysNotYetAvailable),
		tr.EXPECT().BufferedPacket(logging.PacketTypeHandshake, gomock.Any()).Do(
			func(logging.PacketType, logging.ByteCount) { close(buffered) },
		),
	)

	tc.conn.handlePacket(getLongHeaderPacket(t, tc.remoteAddr, &hdr1, []byte("packet1")))
	tc.conn.handlePacket(getLongHeaderPacket(t, tc.remoteAddr, &hdr2, []byte("packet2")))

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	select {
	case <-buffered:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// Now send another packet.
	// In reality, this packet would contain a CRYPTO frame that advances the TLS handshake
	// such that new keys become available.
	var packets []string
	hdr3 := hdr1
	hdr3.PacketNumber = 3
	tc.packer.EXPECT().PackCoalescedPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	unpacked := make(chan struct{})
	cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventReceivedReadKeys})
	cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})

	gomock.InOrder(
		// packet 3 contains a CRYPTO frame and triggers the keys to become available
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).DoAndReturn(
			func(hdr *wire.Header, data []byte) (*unpackedPacket, error) {
				packets = append(packets, string(data[len(data)-7:]))
				cf := &wire.CryptoFrame{Data: []byte("foobar")}
				b, _ := cf.Append(nil, protocol.Version1)
				return &unpackedPacket{hdr: &hdr3, encryptionLevel: protocol.EncryptionHandshake, data: b}, nil
			},
		),
		cs.EXPECT().HandleMessage(gomock.Any(), gomock.Any()),
		tr.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
		// packet 1 dequeued from the buffer
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).DoAndReturn(
			func(hdr *wire.Header, data []byte) (*unpackedPacket, error) {
				packets = append(packets, string(data[len(data)-7:]))
				return &unpackedPacket{hdr: &hdr1, encryptionLevel: protocol.EncryptionHandshake, data: []byte{0} /* PADDING */}, nil
			},
		),
		tr.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
		// packet 2 dequeued from the buffer
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).DoAndReturn(
			func(hdr *wire.Header, data []byte) (*unpackedPacket, error) {
				packets = append(packets, string(data[len(data)-7:]))
				close(unpacked)
				return &unpackedPacket{hdr: &hdr2, encryptionLevel: protocol.EncryptionHandshake, data: []byte{0} /* PADDING */}, nil
			},
		),
		tr.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
	)

	tc.conn.handlePacket(getLongHeaderPacket(t, tc.remoteAddr, &hdr3, []byte("packet3")))

	select {
	case <-unpacked:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// packet3 triggered the keys to become available
	// packet1 and packet2 are processed from the buffer in order
	require.Equal(t, []string{"packet3", "packet1", "packet2"}, packets)

	// test teardown
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	cs.EXPECT().Close()
	tr.EXPECT().ClosedConnection(gomock.Any())
	tr.EXPECT().Close()
	tc.conn.destroy(nil)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionPacketPacing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		sender := NewMockSender(mockCtrl)

		tc := newServerTestConnection(t,
			mockCtrl,
			nil,
			false,
			connectionOptSentPacketHandler(sph),
			connectionOptSender(sender),
			connectionOptHandshakeConfirmed(),
		)
		sender.EXPECT().Run()

		const step = 50 * time.Millisecond

		sph.EXPECT().GetLossDetectionTimeout().Return(monotime.Now().Add(time.Hour)).AnyTimes()
		gomock.InOrder(
			// 1. allow 2 packets to be sent
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny),
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny),
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited),
			// 2. become pacing limited for 25ms
			sph.EXPECT().TimeUntilSend().DoAndReturn(func() monotime.Time { return monotime.Now().Add(step) }),
			// 3. send another packet
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny),
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited),
			// 4. become pacing limited for 25ms...
			sph.EXPECT().TimeUntilSend().DoAndReturn(func() monotime.Time { return monotime.Now().Add(step) }),
			// ... but this time we're still pacing limited when waking up.
			// In this case, we can only send an ACK.
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited),
			// 5. stop the test by becoming pacing limited forever
			sph.EXPECT().TimeUntilSend().Return(monotime.Now().Add(time.Hour)),
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
		)
		sph.EXPECT().ECNMode(gomock.Any()).AnyTimes()
		for i := range 3 {
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), Version1).DoAndReturn(
				func(buf *packetBuffer, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version) (shortHeaderPacket, error) {
					buf.Data = append(buf.Data, []byte("packet"+strconv.Itoa(i+1))...)
					return shortHeaderPacket{PacketNumber: protocol.PacketNumber(i + 1)}, nil
				},
			)
		}
		tc.packer.EXPECT().PackAckOnlyPacket(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ protocol.ByteCount, _ monotime.Time, _ protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
				buf := getPacketBuffer()
				buf.Data = []byte("ack")
				return shortHeaderPacket{PacketNumber: 1}, buf, nil
			},
		)
		sender.EXPECT().WouldBlock().AnyTimes()

		type sentPacket struct {
			time monotime.Time
			data []byte
		}
		sendChan := make(chan sentPacket, 10)
		sender.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(b *packetBuffer, _ uint16, _ protocol.ECN) {
			sendChan <- sentPacket{time: monotime.Now(), data: b.Data}
		}).Times(4)

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		synctest.Wait()

		var times []monotime.Time
		for i := range 3 {
			select {
			case b := <-sendChan:
				require.Equal(t, []byte("packet"+strconv.Itoa(i+1)), b.data)
				times = append(times, b.time)
			case <-time.After(time.Hour):
				t.Fatal("should have sent a packet")
			}
		}
		select {
		case b := <-sendChan:
			require.Equal(t, []byte("ack"), b.data)
			times = append(times, b.time)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}

		require.Equal(t, times[0], times[1])
		require.Equal(t, times[2], times[1].Add(step))
		require.Equal(t, times[3], times[2].Add(step))

		synctest.Wait() // make sure that no more packets are sent
		require.True(t, mockCtrl.Satisfied())

		// test teardown
		sender.EXPECT().Close()
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case <-sendChan:
			t.Fatal("should not have sent any more packets")
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have timed out")
		}
	})
}

// When the send queue blocks, we need to reset the pacing timer, otherwise the run loop might busy-loop.
// See https://github.com/quic-go/quic-go/pull/4943 for more details.
func TestConnectionPacingAndSendQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		sender := NewMockSender(mockCtrl)

		tc := newServerTestConnection(t,
			mockCtrl,
			nil,
			false,
			connectionOptSentPacketHandler(sph),
			connectionOptSender(sender),
			connectionOptHandshakeConfirmed(),
		)
		sender.EXPECT().Run()

		sendQueueAvailable := make(chan struct{})
		pacingDeadline := monotime.Now().Add(-time.Millisecond)
		var counter int
		// allow exactly one packet to be sent, then become blocked
		sender.EXPECT().WouldBlock().Return(false)
		sender.EXPECT().WouldBlock().DoAndReturn(func() bool { counter++; return true }).AnyTimes()
		sender.EXPECT().Available().Return(sendQueueAvailable).AnyTimes()
		sph.EXPECT().GetLossDetectionTimeout().Return(monotime.Now().Add(time.Hour)).AnyTimes()
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited).AnyTimes()
		sph.EXPECT().TimeUntilSend().Return(pacingDeadline).AnyTimes()
		sph.EXPECT().ECNMode(gomock.Any()).Return(protocol.ECNNon).AnyTimes()
		tc.packer.EXPECT().PackAckOnlyPacket(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			shortHeaderPacket{}, nil, errNothingToPack,
		)

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		synctest.Wait()

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		sender.EXPECT().Close()
		tc.conn.destroy(nil)

		synctest.Wait()
		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have timed out")
		}

		// make sure the run loop didn't do too many iterations
		require.Less(t, counter, 3)
	})
}

func TestConnectionIdleTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			&Config{MaxIdleTimeout: time.Minute},
			false,
			connectionOptHandshakeConfirmed(),
			connectionOptSentPacketHandler(sph),
			connectionOptRTT(time.Millisecond),
		)
		// the idle timeout is set when the transport parameters are received
		const idleTimeout = 500 * time.Millisecond
		require.NoError(t, tc.conn.handleTransportParameters(&wire.TransportParameters{
			MaxIdleTimeout: idleTimeout,
		}))

		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		sph.EXPECT().ECNMode(gomock.Any()).AnyTimes()
		var lastSendTime monotime.Time
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(buf *packetBuffer, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version) (shortHeaderPacket, error) {
				buf.Data = append(buf.Data, []byte("foobar")...)
				lastSendTime = monotime.Now()
				return shortHeaderPacket{Frames: []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, Length: 6}, nil
			},
		)
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack)
		tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any())
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, &IdleTimeoutError{})
			require.NotZero(t, lastSendTime)
			require.Equal(t, idleTimeout, monotime.Since(lastSendTime))
		case <-time.After(time.Hour):
			t.Fatal("should have timed out")
		}
	})
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
	synctest.Test(t, func(t *testing.T) {
		var keepAlivePeriod time.Duration
		if enable {
			keepAlivePeriod = time.Second
		}

		mockCtrl := gomock.NewController(t)
		unpacker := NewMockUnpacker(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			&Config{MaxIdleTimeout: time.Second, KeepAlivePeriod: keepAlivePeriod},
			false,
			connectionOptUnpacker(unpacker),
			connectionOptHandshakeConfirmed(),
			connectionOptRTT(time.Millisecond),
		)
		// the idle timeout is set when the transport parameters are received
		const idleTimeout = 50 * time.Millisecond
		require.NoError(t, tc.conn.handleTransportParameters(&wire.TransportParameters{
			MaxIdleTimeout: idleTimeout,
		}))

		// Receive a packet. This starts the keep-alive timer.
		buf := getPacketBuffer()
		var err error
		buf.Data, err = wire.AppendShortHeader(buf.Data, tc.srcConnID, 1, protocol.PacketNumberLen1, protocol.KeyPhaseZero)
		require.NoError(t, err)
		buf.Data = append(buf.Data, []byte("packet")...)

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		var unpackTime, packTime monotime.Time
		done := make(chan struct{})
		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).DoAndReturn(
			func(t monotime.Time, bytes []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
				unpackTime = monotime.Now()
				return protocol.PacketNumber(1), protocol.PacketNumberLen1, protocol.KeyPhaseZero, []byte{0} /* PADDING */, nil
			},
		)
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack)

		switch expectKeepAlive {
		case true:
			// record the time of the keep-alive is sent
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buffer *packetBuffer, count protocol.ByteCount, t monotime.Time, version protocol.Version) (shortHeaderPacket, error) {
					packTime = monotime.Now()
					close(done)
					return shortHeaderPacket{}, errNothingToPack
				},
			)
			tc.conn.handlePacket(receivedPacket{data: buf.Data, buffer: buf, rcvTime: monotime.Now(), remoteAddr: tc.remoteAddr})
			select {
			case <-done:
				// the keep-alive packet should be sent after half the idle timeout
				require.Equal(t, unpackTime.Add(idleTimeout/2), packTime)
			case <-time.After(idleTimeout):
				t.Fatal("timeout")
			}
		case false: // if keep-alives are disabled, the connection will run into an idle timeout
			tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
			tc.conn.handlePacket(receivedPacket{data: buf.Data, buffer: buf, rcvTime: monotime.Now(), remoteAddr: tc.remoteAddr})
		}

		// test teardown
		if expectKeepAlive {
			tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
			tc.conn.destroy(nil)
		}

		synctest.Wait()

		select {
		case err := <-errChan:
			if expectKeepAlive {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, &IdleTimeoutError{})
			}
		case <-time.After(time.Hour):
			t.Fatal("timeout")
		}
	})
}

func TestConnectionACKTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		tc := newServerTestConnection(t,
			mockCtrl,
			&Config{MaxIdleTimeout: time.Second},
			false,
			connectionOptHandshakeConfirmed(),
			connectionOptReceivedPacketHandler(rph),
			connectionOptSentPacketHandler(sph),
		)
		const alarmTimeout = 500 * time.Millisecond

		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		sph.EXPECT().ECNMode(gomock.Any()).AnyTimes()
		rph.EXPECT().GetAlarmTimeout().Return(monotime.Now().Add(time.Hour))
		tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		var times []monotime.Time
		done := make(chan struct{}, 5)
		var calls []any
		for i := range 2 {
			calls = append(calls, tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buf *packetBuffer, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version) (shortHeaderPacket, error) {
					buf.Data = append(buf.Data, []byte("foobar")...)
					times = append(times, monotime.Now())
					return shortHeaderPacket{Frames: []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, Length: 6}, nil
				},
			))
			calls = append(calls, tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(*packetBuffer, protocol.ByteCount, monotime.Time, protocol.Version) (shortHeaderPacket, error) {
					done <- struct{}{}
					return shortHeaderPacket{}, errNothingToPack
				},
			))
			if i == 0 {
				calls = append(calls, rph.EXPECT().GetAlarmTimeout().Return(monotime.Now().Add(alarmTimeout)))
			} else {
				calls = append(calls, rph.EXPECT().GetAlarmTimeout().Return(monotime.Now().Add(time.Hour)))
			}
		}
		gomock.InOrder(calls...)
		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		for range 2 {
			synctest.Wait()

			select {
			case <-done:
			case <-time.After(time.Hour):
				t.Fatal("timeout")
			}
		}

		assert.Len(t, times, 2)
		require.Equal(t, times[0].Add(alarmTimeout), times[1])

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()
		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have timed out")
		}
	})
}

// Send a GSO batch, until we have no more data to send.
func TestConnectionGSOBatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
		sph.EXPECT().TimeUntilSend().AnyTimes()
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().ECNMode(gomock.Any()).Return(protocol.ECT1).AnyTimes()

		maxPacketSize := tc.conn.maxPacketSize()
		var expectedData []byte
		for i := range 4 {
			data := bytes.Repeat([]byte{byte(i)}, int(maxPacketSize))
			expectedData = append(expectedData, data...)

			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buffer *packetBuffer, count protocol.ByteCount, t monotime.Time, version protocol.Version) (shortHeaderPacket, error) {
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

		synctest.Wait()

		select {
		case <-done:
		default:
			t.Fatal("should have sent a packet")
		}

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have timed out")
		}
	})
}

// Send a GSO batch, until a packet smaller than the maximum size is packed
func TestConnectionGSOBatchPacketSize(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
		sph.EXPECT().TimeUntilSend().AnyTimes()
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().ECNMode(gomock.Any()).Return(protocol.ECT1).AnyTimes()

		maxPacketSize := tc.conn.maxPacketSize()
		var expectedData []byte
		var calls []any
		for i := range 4 {
			var data []byte
			if i == 3 {
				data = bytes.Repeat([]byte{byte(i)}, int(maxPacketSize-1))
			} else {
				data = bytes.Repeat([]byte{byte(i)}, int(maxPacketSize))
			}
			expectedData = append(expectedData, data...)

			calls = append(calls, tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buffer *packetBuffer, count protocol.ByteCount, t monotime.Time, version protocol.Version) (shortHeaderPacket, error) {
					buffer.Data = append(buffer.Data, data...)
					return shortHeaderPacket{PacketNumber: protocol.PacketNumber(10 + i)}, nil
				},
			))
		}
		// The smaller (fourth) packet concluded this GSO batch, but the send loop will immediately start composing the next batch.
		// We therefore send a "foobar", so we can check that we're actually generating two GSO batches.
		calls = append(calls,
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buffer *packetBuffer, count protocol.ByteCount, t monotime.Time, version protocol.Version) (shortHeaderPacket, error) {
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

		synctest.Wait()

		select {
		case <-done:
		default:
			t.Fatal("should have sent a packet")
		}

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have timed out")
		}
	})
}

func TestConnectionGSOBatchECN(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
		sph.EXPECT().TimeUntilSend().AnyTimes()
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().ECNMode(gomock.Any()).DoAndReturn(func(bool) protocol.ECN { return ecnMode }).AnyTimes()

		// 3. Send a GSO batch, until the ECN marking changes.
		var expectedData []byte
		var calls []any
		maxPacketSize := tc.conn.maxPacketSize()
		for i := range 3 {
			data := bytes.Repeat([]byte{byte(i)}, int(maxPacketSize))
			expectedData = append(expectedData, data...)

			calls = append(calls, tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buffer *packetBuffer, count protocol.ByteCount, t monotime.Time, version protocol.Version) (shortHeaderPacket, error) {
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
				func(buffer *packetBuffer, count protocol.ByteCount, t monotime.Time, version protocol.Version) (shortHeaderPacket, error) {
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
		tc.sendConn.EXPECT().Write([]byte("foobar"), uint16(maxPacketSize), protocol.ECNCE).DoAndReturn(
			func([]byte, uint16, protocol.ECN) error { close(done3); return nil },
		)

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		synctest.Wait()

		select {
		case <-done3:
		default:
			t.Fatal("should have sent a packet")
		}

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have timed out")
		}
	})
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
	synctest.Test(t, func(t *testing.T) {
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
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		tc.packer.EXPECT().PackPTOProbePacket(encLevel, gomock.Any(), true, gomock.Any(), protocol.Version1).DoAndReturn(
			func(protocol.EncryptionLevel, protocol.ByteCount, bool, monotime.Time, protocol.Version) (*coalescedPacket, error) {
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

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have timed out")
		}
	})
}

func TestConnectionCongestionControl(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAck).MaxTimes(1)
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
		// Since we're already sending out packets, we don't expect any calls to PackAckOnlyPacket
		for i := range 2 {
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buffer *packetBuffer, count protocol.ByteCount, t monotime.Time, version protocol.Version) (shortHeaderPacket, error) {
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

		synctest.Wait()

		select {
		case <-done1:
		default:
			t.Fatal("should have sent a packet")
		}
		require.True(t, mockCtrl.Satisfied())

		// Now that we're congestion limited, we can only send an ack-only packet
		done2 := make(chan struct{})
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAck)
		tc.packer.EXPECT().PackAckOnlyPacket(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(protocol.ByteCount, monotime.Time, protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
				close(done2)
				return shortHeaderPacket{}, nil, errNothingToPack
			},
		)
		tc.conn.scheduleSending()

		synctest.Wait()

		select {
		case <-done2:
		default:
			t.Fatal("should have sent an ack-only packet")
		}
		require.True(t, mockCtrl.Satisfied())

		// If the send mode is "none", we can't even send an ack-only packet
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendNone)
		tc.conn.scheduleSending()
		synctest.Wait() // make sure there are no calls to the packer

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)
		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("timeout")
		}
	})
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
	synctest.Test(t, func(t *testing.T) {
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
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
		sph.EXPECT().ECNMode(gomock.Any()).AnyTimes()
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
			shortHeaderPacket{PacketNumber: protocol.PacketNumber(1)}, nil,
		)
		sender.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any())

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()

		synctest.Wait()

		select {
		case <-blocked:
		default:
			t.Fatal("should have blocked")
		}
		require.True(t, mockCtrl.Satisfied())

		// now make room in the send queue
		sender.EXPECT().WouldBlock().AnyTimes()
		unblocked := make(chan struct{})
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(*packetBuffer, protocol.ByteCount, monotime.Time, protocol.Version) (shortHeaderPacket, error) {
				close(unblocked)
				return shortHeaderPacket{}, errNothingToPack
			},
		)
		available <- struct{}{}

		synctest.Wait()

		select {
		case <-unblocked:
		default:
			t.Fatal("should have unblocked")
		}

		// test teardown
		sender.EXPECT().Close()
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("timeout")
		}
	})
}

func getVersionNegotiationPacket(src, dest protocol.ConnectionID, versions []protocol.Version) receivedPacket {
	b := wire.ComposeVersionNegotiation(
		protocol.ArbitraryLenConnectionID(src.Bytes()),
		protocol.ArbitraryLenConnectionID(dest.Bytes()),
		versions,
	)
	return receivedPacket{
		rcvTime: monotime.Now(),
		data:    b,
		buffer:  getPacketBuffer(),
	}
}

func TestConnectionVersionNegotiation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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

		synctest.Wait()

		select {
		case err := <-errChan:
			var rerr *errCloseForRecreating
			require.ErrorAs(t, err, &rerr)
			require.Equal(t, rerr.nextVersion, protocol.Version2)
		default:
			t.Fatal("should have received a Version Negotiation packet")
		}
		require.Contains(t, tracerVersions, protocol.Version(1234))
		require.Contains(t, tracerVersions, protocol.Version2)
	})
}

func TestConnectionVersionNegotiationNoMatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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

		synctest.Wait()

		select {
		case err := <-errChan:
			var verr *VersionNegotiationError
			require.ErrorAs(t, err, &verr)
			require.Contains(t, verr.Theirs, protocol.Version2)
		default:
			t.Fatal("should have received a Version Negotiation packet")
		}
		require.Contains(t, tracerVersions, protocol.Version2)
	})
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
	wasProcessed, err := tc.conn.handleOnePacket(vnp)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.True(t, mockCtrl.Satisfied())

	// unparseable, since it's missing 2 bytes
	tracer.EXPECT().DroppedPacket(logging.PacketTypeVersionNegotiation, gomock.Any(), gomock.Any(), logging.PacketDropHeaderParseError)
	vnp.data = vnp.data[:len(vnp.data)-2]
	wasProcessed, err = tc.conn.handleOnePacket(vnp)
	require.NoError(t, err)
	require.False(t, wasProcessed)
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
		rcvTime: monotime.Now(),
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
	wasProcessed, err := tc.conn.handleOnePacket(retry)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.True(t, mockCtrl.Satisfied())

	// receive a retry that doesn't change the connection ID
	tracer.EXPECT().DroppedPacket(logging.PacketTypeRetry, gomock.Any(), gomock.Any(), logging.PacketDropUnexpectedPacket)
	retry = getRetryPacket(t, tc.destConnID, tc.srcConnID, tc.destConnID, []byte("foobar"))
	wasProcessed, err = tc.conn.handleOnePacket(retry)
	require.NoError(t, err)
	require.False(t, wasProcessed)
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
	wasProcessed, err := tc.conn.handleOnePacket(receivedPacket{
		data:       regular,
		buffer:     getPacketBuffer(),
		rcvTime:    monotime.Now(),
		remoteAddr: tc.remoteAddr,
	})
	require.NoError(t, err)
	require.True(t, wasProcessed)

	// receive a retry
	retry := getRetryPacket(t, tc.destConnID, tc.srcConnID, tc.destConnID, []byte("foobar"))
	tracer.EXPECT().DroppedPacket(logging.PacketTypeRetry, gomock.Any(), gomock.Any(), logging.PacketDropUnexpectedPacket)
	wasProcessed, err = tc.conn.handleOnePacket(retry)
	require.NoError(t, err)
	require.False(t, wasProcessed)
}

func TestConnectionConnectionIDChanges(t *testing.T) {
	t.Run("with retry", func(t *testing.T) {
		testConnectionConnectionIDChanges(t, true)
	})
	t.Run("without retry", func(t *testing.T) {
		testConnectionConnectionIDChanges(t, false)
	})
}

func testConnectionConnectionIDChanges(t *testing.T, sendRetry bool) {
	synctest.Test(t, func(t *testing.T) {
		makeInitialPacket := func(t *testing.T, hdr *wire.ExtendedHeader) []byte {
			t.Helper()
			data, err := hdr.Append(nil, protocol.Version1)
			require.NoError(t, err)
			data = append(data, make([]byte, hdr.Length-protocol.ByteCount(hdr.PacketNumberLen))...)
			return data
		}

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

		dstConnID := tc.destConnID
		b := make([]byte, 3*10)
		rand.Read(b)
		newConnID := protocol.ParseConnectionID(b[:11])
		newConnID2 := protocol.ParseConnectionID(b[11:20])

		tracer.EXPECT().NegotiatedVersion(gomock.Any(), gomock.Any(), gomock.Any())
		tc.packer.EXPECT().PackCoalescedPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		require.Equal(t, dstConnID, tc.conn.connIDManager.Get())

		var retryConnID protocol.ConnectionID
		if sendRetry {
			retryConnID = protocol.ParseConnectionID(b[20:30])
			hdrChan := make(chan *wire.Header)
			tracer.EXPECT().ReceivedRetry(gomock.Any()).Do(func(hdr *wire.Header) { hdrChan <- hdr })
			tc.packer.EXPECT().SetToken([]byte("foobar"))

			tc.conn.handlePacket(getRetryPacket(t, retryConnID, tc.srcConnID, tc.destConnID, []byte("foobar")))

			synctest.Wait()

			select {
			case hdr := <-hdrChan:
				assert.Equal(t, retryConnID, hdr.SrcConnectionID)
				assert.Equal(t, []byte("foobar"), hdr.Token)
				require.Equal(t, retryConnID, tc.conn.connIDManager.Get())
			default:
				t.Fatal("should have received the retry packet")
			}
		}

		// Send the first packet. The server changes the connection ID to newConnID.
		hdr1 := wire.ExtendedHeader{
			Header: wire.Header{
				SrcConnectionID:  newConnID,
				DestConnectionID: tc.srcConnID,
				Type:             protocol.PacketTypeInitial,
				Length:           200,
				Version:          protocol.Version1,
			},
			PacketNumber:    1,
			PacketNumberLen: protocol.PacketNumberLen2,
		}
		hdr2 := hdr1
		hdr2.SrcConnectionID = newConnID2

		receivedFirst := make(chan struct{})
		gomock.InOrder(
			unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
				&unpackedPacket{
					hdr:             &hdr1,
					encryptionLevel: protocol.EncryptionInitial,
				}, nil,
			),
			tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(
				func(*wire.ExtendedHeader, protocol.ByteCount, protocol.ECN, []logging.Frame) { close(receivedFirst) },
			),
		)

		tc.conn.handlePacket(receivedPacket{data: makeInitialPacket(t, &hdr1), buffer: getPacketBuffer(), rcvTime: monotime.Now(), remoteAddr: tc.remoteAddr})

		synctest.Wait()

		select {
		case <-receivedFirst:
			require.Equal(t, newConnID, tc.conn.connIDManager.Get())
		default:
			t.Fatal("should have received the first packet")
		}

		// Send the second packet. We refuse to accept it, because the connection ID is changed again.
		dropped := make(chan struct{})
		tracer.EXPECT().DroppedPacket(logging.PacketTypeInitial, gomock.Any(), gomock.Any(), logging.PacketDropUnknownConnectionID).Do(
			func(logging.PacketType, protocol.PacketNumber, protocol.ByteCount, logging.PacketDropReason) {
				close(dropped)
			},
		)

		tc.conn.handlePacket(receivedPacket{data: makeInitialPacket(t, &hdr2), buffer: getPacketBuffer(), rcvTime: monotime.Now(), remoteAddr: tc.remoteAddr})

		synctest.Wait()

		select {
		case <-dropped:
			// the connection ID should not have changed
			require.Equal(t, newConnID, tc.conn.connIDManager.Get())
		default:
			t.Fatal("should have dropped the packet")
		}

		// test teardown
		tracer.EXPECT().ClosedConnection(gomock.Any())
		tracer.EXPECT().Close()
		tc.connRunner.EXPECT().Remove(gomock.Any())
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have shut down")
		}
	})
}

// When the connection is closed before sending the first packet,
// we don't send a CONNECTION_CLOSE.
// This can happen if there's something wrong the tls.Config, and
// crypto/tls refuses to start the handshake.
func TestConnectionEarlyClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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

		synctest.Wait()

		select {
		case err := <-errChan:
			require.Error(t, err)
			require.ErrorContains(t, err, "early error")
		default:
			t.Fatal("should have shut down")
		}
	})
}

func TestConnectionPathValidation(t *testing.T) {
	t.Run("NAT rebinding", func(t *testing.T) {
		testConnectionPathValidation(t, true)
	})

	t.Run("intentional migration", func(t *testing.T) {
		testConnectionPathValidation(t, false)
	})
}

func testConnectionPathValidation(t *testing.T, isNATRebinding bool) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		unpacker := NewMockUnpacker(mockCtrl)
		tc := newServerTestConnection(
			t,
			mockCtrl,
			nil,
			false,
			connectionOptUnpacker(unpacker),
			connectionOptHandshakeConfirmed(),
			connectionOptRTT(time.Second),
		)
		require.NoError(t, tc.conn.handleTransportParameters(&wire.TransportParameters{MaxUDPPayloadSize: 1456}))

		newRemoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 1234}
		require.NotEqual(t, tc.remoteAddr, newRemoteAddr)

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()

		probeSent := make(chan struct{})
		var pathChallenge *wire.PathChallengeFrame
		payload := []byte{0} // PADDING frame
		if isNATRebinding {
			payload = []byte{1} // PING frame
		}
		gomock.InOrder(
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(
				protocol.PacketNumber(10), protocol.PacketNumberLen2, protocol.KeyPhaseZero, payload, nil,
			),
			tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ protocol.ConnectionID, frames []ackhandler.Frame, _ protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
					pathChallenge = frames[0].Frame.(*wire.PathChallengeFrame)
					return shortHeaderPacket{IsPathProbePacket: true}, getPacketBuffer(), nil
				},
			),
			tc.sendConn.EXPECT().WriteTo(gomock.Any(), newRemoteAddr).DoAndReturn(
				func([]byte, net.Addr) error { close(probeSent); return nil },
			),
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
				shortHeaderPacket{}, errNothingToPack,
			),
		)

		tc.conn.handlePacket(receivedPacket{
			data:       make([]byte, 10),
			buffer:     getPacketBuffer(),
			remoteAddr: newRemoteAddr,
			rcvTime:    monotime.Now(),
		})

		synctest.Wait()

		select {
		case <-probeSent:
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}

		// Receive a packed containing a PATH_RESPONSE frame.
		// Only if the first packet received on the path was a probing packet
		// (i.e. we're dealing with a NAT rebinding), this makes us switch to the new path.
		migrated := make(chan struct{})
		data, err := (&wire.PathResponseFrame{Data: pathChallenge.Data}).Append(nil, protocol.Version1)
		require.NoError(t, err)
		calls := []any{
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(
				protocol.PacketNumber(11), protocol.PacketNumberLen2, protocol.KeyPhaseZero, data, nil,
			),
		}
		if isNATRebinding {
			calls = append(calls,
				tc.sendConn.EXPECT().ChangeRemoteAddr(newRemoteAddr, gomock.Any()).Do(
					func(net.Addr, packetInfo) { close(migrated) },
				),
			)
		}
		calls = append(calls,
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
				shortHeaderPacket{}, errNothingToPack,
			).MaxTimes(1),
		)
		gomock.InOrder(calls...)
		require.Equal(t, tc.remoteAddr, tc.conn.RemoteAddr())
		// the PATH_RESPONSE can be sent on the old path, if the client is just probing the new path
		addr := tc.remoteAddr
		if isNATRebinding {
			addr = newRemoteAddr
		}
		tc.conn.handlePacket(receivedPacket{
			data:       make([]byte, 100),
			buffer:     getPacketBuffer(),
			remoteAddr: addr,
			rcvTime:    monotime.Now(),
		})

		synctest.Wait()

		if !isNATRebinding {
			// If the first packet was a probing packet, we only switch to the new path when we
			// receive a non-probing packet on that path.
			select {
			case <-migrated:
				t.Fatal("didn't expect a migration yet")
			default:
			}

			payload := []byte{1} // PING frame
			payload, err = (&wire.PathResponseFrame{Data: pathChallenge.Data}).Append(payload, protocol.Version1)
			require.NoError(t, err)
			gomock.InOrder(
				unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(
					protocol.PacketNumber(12), protocol.PacketNumberLen2, protocol.KeyPhaseZero, payload, nil,
				),
				tc.sendConn.EXPECT().ChangeRemoteAddr(newRemoteAddr, gomock.Any()).Do(
					func(net.Addr, packetInfo) { close(migrated) },
				),
				tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
					shortHeaderPacket{}, errNothingToPack,
				).MaxTimes(1),
			)
			tc.conn.handlePacket(receivedPacket{
				data:       make([]byte, 100),
				buffer:     getPacketBuffer(),
				remoteAddr: newRemoteAddr,
				rcvTime:    monotime.Now(),
			})
		}

		synctest.Wait()

		select {
		case <-migrated:
		default:
			t.Fatal("should have migrated")
		}

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have shut down")
		}
	})
}

func TestConnectionMigrationServer(t *testing.T) {
	tc := newServerTestConnection(t, nil, nil, false)
	_, err := tc.conn.AddPath(&Transport{})
	require.Error(t, err)
	require.ErrorContains(t, err, "server cannot initiate connection migration")
}

func TestConnectionMigration(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		testConnectionMigration(t, false)
	})

	t.Run("enabled", func(t *testing.T) {
		testConnectionMigration(t, true)
	})
}

func testConnectionMigration(t *testing.T, enabled bool) {
	tc := newClientTestConnection(t, nil, nil, false, connectionOptHandshakeConfirmed())
	require.NoError(t, tc.conn.handleTransportParameters(&wire.TransportParameters{
		InitialSourceConnectionID:       tc.destConnID,
		OriginalDestinationConnectionID: tc.destConnID,
		DisableActiveMigration:          !enabled,
	}))

	tr := &Transport{
		Conn:              newUDPConnLocalhost(t),
		StatelessResetKey: &StatelessResetKey{},
	}
	defer tr.Close()
	path, err := tc.conn.AddPath(tr)
	if !enabled {
		require.Error(t, err)
		require.ErrorContains(t, err, "server disabled connection migration")
		return
	}
	require.NoError(t, err)
	require.NotNil(t, path)

	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
		shortHeaderPacket{}, errNothingToPack,
	).AnyTimes()
	packedProbe := make(chan struct{})
	tc.packer.EXPECT().PackPathProbePacket(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(protocol.ConnectionID, []ackhandler.Frame, protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
			defer close(packedProbe)
			return shortHeaderPacket{IsPathProbePacket: true}, getPacketBuffer(), nil
		},
	).AnyTimes()
	tc.connRunner.EXPECT().AddResetToken(gomock.Any(), gomock.Any())
	// add a new connection ID, so the path can be probed
	_, err = tc.conn.handleFrame(&wire.NewConnectionIDFrame{
		SequenceNumber: 1,
		ConnectionID:   protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
	}, protocol.EncryptionInitial, tc.destConnID, monotime.Now())
	require.NoError(t, err)
	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	// Adding the path initialized the transport.
	// We can test this by triggering a stateless reset.
	conn := newUDPConnLocalhost(t)
	_, err = conn.WriteTo(append([]byte{0x40}, make([]byte, 100)...), tr.Conn.LocalAddr())
	require.NoError(t, err)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err = conn.ReadFrom(make([]byte, 100))
	require.NoError(t, err)

	go func() { path.Probe(context.Background()) }()
	select {
	case <-packedProbe:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// teardown
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.connRunner.EXPECT().RemoveResetToken(gomock.Any()).MaxTimes(1)
	tc.conn.destroy(nil)
	select {
	case <-errChan:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionDatagrams(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		testConnectionDatagrams(t, false)
	})
	t.Run("enabled", func(t *testing.T) {
		testConnectionDatagrams(t, true)
	})
}

func testConnectionDatagrams(t *testing.T, enabled bool) {
	tc := newServerTestConnection(t, nil, &Config{EnableDatagrams: enabled}, false)

	data, err := (&wire.DatagramFrame{Data: []byte("foo"), DataLenPresent: true}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	data, err = (&wire.DatagramFrame{Data: []byte("bar")}).Append(data, protocol.Version1)
	require.NoError(t, err)
	_, _, _, err = tc.conn.handleFrames(data, protocol.ConnectionID{}, protocol.Encryption1RTT, nil, monotime.Now())

	if !enabled {
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.FrameEncodingError, FrameType: uint64(wire.FrameTypeDatagramWithLength)})
		return
	}

	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d, err := tc.conn.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), d)
	d, err = tc.conn.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), d)
}
