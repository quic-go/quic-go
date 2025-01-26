package quic

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/mocks"
	mockackhandler "github.com/quic-go/quic-go/internal/mocks/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const testPackerConnIDLen = 4

type testPacketPacker struct {
	packer                         *packetPacker
	initialStream, handshakeStream *cryptoStream
	datagramQueue                  *datagramQueue
	pnManager                      *mockackhandler.MockSentPacketHandler
	sealingManager                 *MockSealingManager
	framer                         *MockFrameSource
	ackFramer                      *MockAckFrameSource
	retransmissionQueue            *retransmissionQueue
}

func newTestPacketPacker(t *testing.T, mockCtrl *gomock.Controller, pers protocol.Perspective) *testPacketPacker {
	destConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	require.Equal(t, testPackerConnIDLen, destConnID.Len())
	initialStream := newCryptoStream()
	handshakeStream := newCryptoStream()
	pnManager := mockackhandler.NewMockSentPacketHandler(mockCtrl)
	framer := NewMockFrameSource(mockCtrl)
	ackFramer := NewMockAckFrameSource(mockCtrl)
	sealingManager := NewMockSealingManager(mockCtrl)
	datagramQueue := newDatagramQueue(func() {}, utils.DefaultLogger)
	retransmissionQueue := newRetransmissionQueue()
	return &testPacketPacker{
		pnManager:           pnManager,
		initialStream:       initialStream,
		handshakeStream:     handshakeStream,
		sealingManager:      sealingManager,
		framer:              framer,
		ackFramer:           ackFramer,
		datagramQueue:       datagramQueue,
		retransmissionQueue: retransmissionQueue,
		packer: newPacketPacker(
			protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
			func() protocol.ConnectionID { return destConnID },
			initialStream,
			handshakeStream,
			pnManager,
			retransmissionQueue,
			sealingManager,
			framer,
			ackFramer,
			datagramQueue,
			pers,
		),
	}
}

// newMockShortHeaderSealer returns a mock short header sealer that seals a short header packet
func newMockShortHeaderSealer(mockCtrl *gomock.Controller) *mocks.MockShortHeaderSealer {
	sealer := mocks.NewMockShortHeaderSealer(mockCtrl)
	sealer.EXPECT().KeyPhase().Return(protocol.KeyPhaseOne).AnyTimes()
	sealer.EXPECT().Overhead().Return(7).AnyTimes()
	sealer.EXPECT().EncryptHeader(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	sealer.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(dst, src []byte, pn protocol.PacketNumber, associatedData []byte) []byte {
		return append(src, bytes.Repeat([]byte{'s'}, sealer.Overhead())...)
	}).AnyTimes()
	return sealer
}

func parsePacket(t *testing.T, data []byte) (hdrs []*wire.ExtendedHeader, more []byte) {
	t.Helper()
	for len(data) > 0 {
		if !wire.IsLongHeaderPacket(data[0]) {
			break
		}
		hdr, _, more, err := wire.ParsePacket(data)
		require.NoError(t, err)
		extHdr, err := hdr.ParseExtended(data)
		require.NoError(t, err)
		require.GreaterOrEqual(t, extHdr.Length+protocol.ByteCount(extHdr.PacketNumberLen), protocol.ByteCount(4))
		data = more
		hdrs = append(hdrs, extHdr)
	}
	return hdrs, data
}

func parseShortHeaderPacket(t *testing.T, data []byte, connIDLen int) {
	t.Helper()
	l, _, pnLen, _, err := wire.ParseShortHeader(data, connIDLen)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(data)-l+int(pnLen), 4)
}

func expectAppendFrames(framer *MockFrameSource, controlFrames []ackhandler.Frame, streamFrames []ackhandler.StreamFrame) {
	framer.EXPECT().Append(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(cf []ackhandler.Frame, sf []ackhandler.StreamFrame, _ protocol.ByteCount, _ time.Time, v protocol.Version) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
			var length protocol.ByteCount
			for _, f := range controlFrames {
				length += f.Frame.Length(v)
			}
			for _, f := range streamFrames {
				length += f.Frame.Length(v)
			}
			return append(cf, controlFrames...), append(sf, streamFrames...), length
		},
	)
}

func TestPackLongHeaders(t *testing.T) {
	const maxPacketSize protocol.ByteCount = 1234
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	token := make([]byte, 20)
	rand.Read(token)
	tp.packer.SetToken(token)
	now := time.Now()

	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24), protocol.PacketNumberLen3)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x24))
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen4)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, now, false)
	// don't EXPECT any calls for a Handshake ACK frame
	tp.initialStream.Write([]byte("initial"))
	tp.packer.retransmissionQueue.addHandshake(&wire.PingFrame{})

	p, err := tp.packer.PackCoalescedPacket(false, maxPacketSize, now, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, maxPacketSize, p.buffer.Len())
	require.Len(t, p.longHdrPackets, 2)
	require.Nil(t, p.shortHdrPacket)
	require.Equal(t, protocol.EncryptionInitial, p.longHdrPackets[0].EncryptionLevel())
	require.Len(t, p.longHdrPackets[0].frames, 1)
	require.Equal(t, []byte("initial"), p.longHdrPackets[0].frames[0].Frame.(*wire.CryptoFrame).Data)
	require.Equal(t, protocol.EncryptionHandshake, p.longHdrPackets[1].EncryptionLevel())
	require.Len(t, p.longHdrPackets[1].frames, 1)
	require.IsType(t, &wire.PingFrame{}, p.longHdrPackets[1].frames[0].Frame)

	hdrs, more := parsePacket(t, p.buffer.Data)
	require.Len(t, hdrs, 2)
	require.Equal(t, protocol.PacketTypeInitial, hdrs[0].Type)
	require.Equal(t, token, hdrs[0].Token)
	require.Equal(t, protocol.PacketNumber(0x24), hdrs[0].PacketNumber)
	require.Equal(t, protocol.PacketNumberLen3, hdrs[0].PacketNumberLen)
	require.Equal(t, protocol.PacketTypeHandshake, hdrs[1].Type)
	require.Nil(t, hdrs[1].Token)
	require.Equal(t, protocol.PacketNumber(0x42), hdrs[1].PacketNumber)
	require.Equal(t, protocol.PacketNumberLen4, hdrs[1].PacketNumberLen)
	require.Empty(t, more)
}

func TestPackCoalescedAckOnlyPacketNothingToSend(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	// the packet number is not popped
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, gomock.Any(), true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true)
	p, err := tp.packer.PackCoalescedPacket(true, 1234, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Nil(t, p)
}

func TestPackInitialAckOnlyPacket(t *testing.T) {
	t.Run("client", func(t *testing.T) { testPackInitialAckOnlyPacket(t, protocol.PerspectiveClient) })
	t.Run("server", func(t *testing.T) { testPackInitialAckOnlyPacket(t, protocol.PerspectiveServer) })
}

func testPackInitialAckOnlyPacket(t *testing.T, pers protocol.Perspective) {
	const maxPacketSize protocol.ByteCount = 1234
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, pers)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}}
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), true).Return(ack)
	p, err := tp.packer.PackCoalescedPacket(true, maxPacketSize, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Len(t, p.longHdrPackets, 1)
	require.Equal(t, protocol.EncryptionInitial, p.longHdrPackets[0].EncryptionLevel())
	require.Equal(t, ack, p.longHdrPackets[0].ack)
	require.Empty(t, p.longHdrPackets[0].frames)
	// only the client needs to pad Initial packets
	switch pers {
	case protocol.PerspectiveClient:
		require.Equal(t, maxPacketSize, p.buffer.Len())
	case protocol.PerspectiveServer:
		require.Less(t, p.buffer.Len(), protocol.ByteCount(100))
	}
	hdrs, more := parsePacket(t, p.buffer.Data)
	require.Empty(t, more)
	require.Len(t, hdrs, 1)
	require.Equal(t, protocol.PacketTypeInitial, hdrs[0].Type)
}

func TestPack1RTTAckOnlyPacket(t *testing.T) {
	const maxPacketSize protocol.ByteCount = 1300
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}}
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true).Return(ack)
	p, buffer, err := tp.packer.PackAckOnlyPacket(maxPacketSize, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, ack, p.Ack)
	require.Empty(t, p.Frames)
	parsePacket(t, buffer.Data)
}

func TestPack0RTTPacket(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().Get0RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), true)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption0RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption0RTT).Return(protocol.PacketNumber(0x42))
	cf := ackhandler.Frame{Frame: &wire.MaxDataFrame{MaximumData: 0x1337}}
	tp.framer.EXPECT().HasData().Return(true)
	// TODO: check sizes
	tp.framer.EXPECT().Append(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(fs []ackhandler.Frame, sf []ackhandler.StreamFrame, _ protocol.ByteCount, _ time.Time, _ protocol.Version) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
			return append(fs, cf), sf, cf.Frame.Length(protocol.Version1)
		},
	)
	p, err := tp.packer.PackCoalescedPacket(false, protocol.MaxByteCount, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Len(t, p.longHdrPackets, 1)
	require.Equal(t, protocol.PacketType0RTT, p.longHdrPackets[0].header.Type)
	require.Equal(t, protocol.Encryption0RTT, p.longHdrPackets[0].EncryptionLevel())
	require.Len(t, p.longHdrPackets[0].frames, 1)
	require.Equal(t, cf.Frame, p.longHdrPackets[0].frames[0].Frame)
	require.NotNil(t, p.longHdrPackets[0].frames[0].Handler)
}

// ACK frames can't be sent in 0-RTT packets
func TestPack0RTTPacketNoACK(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), true)
	// no further calls to get an ACK frame
	p, err := tp.packer.PackCoalescedPacket(true, protocol.MaxByteCount, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Nil(t, p)
}

func TestPackCoalescedAppData(t *testing.T) {
	const maxPacketSize protocol.ByteCount = 1234

	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x24), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x24))
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, gomock.Any(), false)
	// don't expect any calls for a 1-RTT ACK frame
	tp.handshakeStream.Write([]byte("handshake"))
	expectAppendFrames(tp.framer, nil, []ackhandler.StreamFrame{{Frame: &wire.StreamFrame{Data: []byte("foobar")}}})

	p, err := tp.packer.PackCoalescedPacket(false, maxPacketSize, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Less(t, p.buffer.Len(), protocol.ByteCount(100))
	require.Len(t, p.longHdrPackets, 1)
	require.Equal(t, protocol.EncryptionHandshake, p.longHdrPackets[0].EncryptionLevel())
	require.Len(t, p.longHdrPackets[0].frames, 1)
	require.Equal(t, []byte("handshake"), p.longHdrPackets[0].frames[0].Frame.(*wire.CryptoFrame).Data)
	require.NotNil(t, p.shortHdrPacket)
	require.Empty(t, p.shortHdrPacket.Frames)
	require.Len(t, p.shortHdrPacket.StreamFrames, 1)
	require.Equal(t, []byte("foobar"), p.shortHdrPacket.StreamFrames[0].Frame.Data)

	hdrs, more := parsePacket(t, p.buffer.Data)
	require.Len(t, hdrs, 1)
	require.Equal(t, protocol.PacketTypeHandshake, hdrs[0].Type)
	require.NotEmpty(t, more)
	parseShortHeaderPacket(t, more, testPackerConnIDLen)
}

func TestPackConnectionCloseCoalesced(t *testing.T) {
	t.Run("client", func(t *testing.T) { testPackConnectionCloseCoalesced(t, protocol.PerspectiveClient) })
	t.Run("server", func(t *testing.T) { testPackConnectionCloseCoalesced(t, protocol.PerspectiveServer) })
}

func testPackConnectionCloseCoalesced(t *testing.T, pers protocol.Perspective) {
	const maxPacketSize protocol.ByteCount = 1234
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, pers)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(1), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(1))
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(2), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(2))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	switch pers {
	case protocol.PerspectiveClient:
		tp.sealingManager.EXPECT().Get0RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
		tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
		tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption0RTT).Return(protocol.PacketNumber(3), protocol.PacketNumberLen2)
		tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption0RTT).Return(protocol.PacketNumber(3))
	case protocol.PerspectiveServer:
		tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
		tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(3), protocol.PacketNumberLen2)
		tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(3))
	}
	p, err := tp.packer.PackApplicationClose(&qerr.ApplicationError{
		ErrorCode:    0x1337,
		ErrorMessage: "test error",
	}, maxPacketSize, protocol.Version1)
	require.NoError(t, err)
	switch pers {
	case protocol.PerspectiveClient:
		require.Len(t, p.longHdrPackets, 3)
		require.Nil(t, p.shortHdrPacket)
	case protocol.PerspectiveServer:
		require.Len(t, p.longHdrPackets, 2)
		require.NotNil(t, p.shortHdrPacket)
	}
	// for Initial packets, the error code is replace with a transport error of type APPLICATION_ERROR
	require.Equal(t, protocol.PacketTypeInitial, p.longHdrPackets[0].header.Type)
	require.Equal(t, protocol.PacketNumber(1), p.longHdrPackets[0].header.PacketNumber)
	require.Len(t, p.longHdrPackets[0].frames, 1)
	require.IsType(t, &wire.ConnectionCloseFrame{}, p.longHdrPackets[0].frames[0].Frame)
	ccf := p.longHdrPackets[0].frames[0].Frame.(*wire.ConnectionCloseFrame)
	require.False(t, ccf.IsApplicationError)
	require.Equal(t, uint64(qerr.ApplicationErrorErrorCode), ccf.ErrorCode)
	require.Empty(t, ccf.ReasonPhrase)
	// for Handshake packets, the error code is replace with a transport error of type APPLICATION_ERROR
	require.Equal(t, protocol.PacketTypeHandshake, p.longHdrPackets[1].header.Type)
	require.Equal(t, protocol.PacketNumber(2), p.longHdrPackets[1].header.PacketNumber)
	require.Len(t, p.longHdrPackets[1].frames, 1)
	require.IsType(t, &wire.ConnectionCloseFrame{}, p.longHdrPackets[1].frames[0].Frame)
	ccf = p.longHdrPackets[1].frames[0].Frame.(*wire.ConnectionCloseFrame)
	require.False(t, ccf.IsApplicationError)
	require.Equal(t, uint64(qerr.ApplicationErrorErrorCode), ccf.ErrorCode)
	require.Empty(t, ccf.ReasonPhrase)

	// for application-data packet number space (1-RTT for the server, 0-RTT for the client),
	// the application-level error code is sent

	switch pers {
	case protocol.PerspectiveClient:
		require.Equal(t, protocol.PacketNumber(3), p.longHdrPackets[2].header.PacketNumber)
		require.Len(t, p.longHdrPackets[2].frames, 1)
		require.IsType(t, &wire.ConnectionCloseFrame{}, p.longHdrPackets[2].frames[0].Frame)
		ccf = p.longHdrPackets[2].frames[0].Frame.(*wire.ConnectionCloseFrame)
	case protocol.PerspectiveServer:
		require.Equal(t, protocol.PacketNumber(3), p.shortHdrPacket.PacketNumber)
		require.Len(t, p.shortHdrPacket.Frames, 1)
		require.IsType(t, &wire.ConnectionCloseFrame{}, p.shortHdrPacket.Frames[0].Frame)
		ccf = p.shortHdrPacket.Frames[0].Frame.(*wire.ConnectionCloseFrame)
	}
	require.True(t, ccf.IsApplicationError)
	require.Equal(t, uint64(0x1337), ccf.ErrorCode)
	require.Equal(t, "test error", ccf.ReasonPhrase)

	// the client needs to pad this packet to the max packet size
	switch pers {
	case protocol.PerspectiveClient:
		require.Equal(t, maxPacketSize, p.buffer.Len())
	case protocol.PerspectiveServer:
		require.Less(t, p.buffer.Len(), protocol.ByteCount(100))
	}
}

func TestPackConnectionCloseCryptoError(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	quicErr := qerr.NewLocalCryptoError(0x42, errors.New("crypto error"))
	quicErr.FrameType = 0x1234
	p, err := tp.packer.PackConnectionClose(quicErr, protocol.MaxByteCount, protocol.Version1)
	require.NoError(t, err)
	require.Len(t, p.longHdrPackets, 1)
	require.Equal(t, protocol.PacketTypeHandshake, p.longHdrPackets[0].header.Type)
	require.Len(t, p.longHdrPackets[0].frames, 1)
	require.IsType(t, &wire.ConnectionCloseFrame{}, p.longHdrPackets[0].frames[0].Frame)
	ccf := p.longHdrPackets[0].frames[0].Frame.(*wire.ConnectionCloseFrame)
	require.False(t, ccf.IsApplicationError)
	require.Equal(t, uint64(0x100+0x42), ccf.ErrorCode)
	require.Equal(t, uint64(0x1234), ccf.FrameType)
	// for crypto errors, the reason phrase is cleared
	require.Empty(t, ccf.ReasonPhrase)
}

func TestPackConnectionClose1RTT(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysDropped)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	// expect no framer.PopStreamFrames
	p, err := tp.packer.PackConnectionClose(&qerr.TransportError{
		ErrorCode:    qerr.CryptoBufferExceeded,
		ErrorMessage: "test error",
	}, protocol.MaxByteCount, protocol.Version1)
	require.NoError(t, err)
	require.Empty(t, p.longHdrPackets)
	require.Len(t, p.shortHdrPacket.Frames, 1)
	require.IsType(t, &wire.ConnectionCloseFrame{}, p.shortHdrPacket.Frames[0].Frame)
	ccf := p.shortHdrPacket.Frames[0].Frame.(*wire.ConnectionCloseFrame)
	require.False(t, ccf.IsApplicationError)
	require.Equal(t, uint64(qerr.CryptoBufferExceeded), ccf.ErrorCode)
	require.Equal(t, "test error", ccf.ReasonPhrase)
}

func TestPack1RTTPacketNothingToSend(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	// don't expect any calls to PopPacketNumber
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true)
	tp.framer.EXPECT().HasData()
	_, err := tp.packer.AppendPacket(getPacketBuffer(), protocol.MaxByteCount, time.Now(), protocol.Version1)
	require.ErrorIs(t, err, errNothingToPack)
}

func TestPack1RTTPacketWithData(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false)
	f := &wire.StreamFrame{
		StreamID: 5,
		Data:     []byte{0xde, 0xca, 0xfb, 0xad},
	}
	expectAppendFrames(
		tp.framer,
		[]ackhandler.Frame{
			{Frame: &wire.ResetStreamFrame{}, Handler: &mtuFinderAckHandler{}}, // set any non-nil ackhandler.FrameHandler
			{Frame: &wire.MaxDataFrame{}},
		},
		[]ackhandler.StreamFrame{{Frame: f}},
	)
	buffer := getPacketBuffer()
	buffer.Data = append(buffer.Data, []byte("foobar")...)
	p, err := tp.packer.AppendPacket(buffer, protocol.MaxByteCount, time.Now(), protocol.Version1)
	require.NoError(t, err)
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Len(t, p.StreamFrames, 1)
	var sawResetStream, sawMaxData bool
	for _, frame := range p.Frames {
		switch frame.Frame.(type) {
		case *wire.ResetStreamFrame:
			sawResetStream = true
			require.Equal(t, frame.Handler, &mtuFinderAckHandler{})
		case *wire.MaxDataFrame:
			sawMaxData = true
			require.NotNil(t, frame.Handler)
			require.NotEqual(t, frame.Handler, &mtuFinderAckHandler{})
		}
	}
	require.True(t, sawResetStream)
	require.True(t, sawMaxData)
	require.Equal(t, f.StreamID, p.StreamFrames[0].Frame.StreamID)
	require.Equal(t, buffer.Data[:6], []byte("foobar")) // make sure the packet was actually appended
	require.Contains(t, string(buffer.Data), string(b))
}

func TestPack1RTTPacketWithACK(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 42, Smallest: 1}}}
	tp.framer.EXPECT().HasData()
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true).Return(ack)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	p, err := tp.packer.AppendPacket(getPacketBuffer(), protocol.MaxByteCount, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, ack, p.Ack)
}

func TestPackPathChallengeAndPathResponse(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false)
	frames := []ackhandler.Frame{
		{Frame: &wire.PathChallengeFrame{}},
		{Frame: &wire.PathResponseFrame{}},
		{Frame: &wire.DataBlockedFrame{}},
	}
	expectAppendFrames(tp.framer, frames, nil)
	buffer := getPacketBuffer()
	p, err := tp.packer.AppendPacket(buffer, protocol.MaxByteCount, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Len(t, p.Frames, 3)
	var sawPathChallenge, sawPathResponse bool
	for _, f := range p.Frames {
		switch f.Frame.(type) {
		case *wire.PathChallengeFrame:
			sawPathChallenge = true
			// this means that the frame won't be retransmitted.
			require.Nil(t, f.Handler)
		case *wire.PathResponseFrame:
			sawPathResponse = true
			// this means that the frame won't be retransmitted.
			require.Nil(t, f.Handler)
		default:
			require.NotNil(t, f.Handler)
		}
	}
	require.True(t, sawPathChallenge)
	require.True(t, sawPathResponse)
	require.NotZero(t, buffer.Len())
}

func TestPackDatagramFrames(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)

	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.datagramQueue.Add(&wire.DatagramFrame{
		DataLenPresent: true,
		Data:           []byte("foobar"),
	})
	tp.framer.EXPECT().HasData()
	buffer := getPacketBuffer()
	p, err := tp.packer.AppendPacket(buffer, protocol.MaxByteCount, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Len(t, p.Frames, 1)
	require.IsType(t, &wire.DatagramFrame{}, p.Frames[0].Frame)
	require.Equal(t, []byte("foobar"), p.Frames[0].Frame.(*wire.DatagramFrame).Data)
	require.NotEmpty(t, buffer.Data)
}

func TestPackLargeDatagramFrame(t *testing.T) {
	// If a packet contains an ACK, and doesn't have enough space for the DATAGRAM frame,
	// it should be skipped. It will be packed in the next packet.
	const maxPacketSize = 1000
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Largest: 100}}})
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	f := &wire.DatagramFrame{DataLenPresent: true, Data: make([]byte, maxPacketSize-10)}
	tp.datagramQueue.Add(f)
	tp.framer.EXPECT().HasData()
	buffer := getPacketBuffer()
	p, err := tp.packer.AppendPacket(buffer, maxPacketSize, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, p.Ack)
	require.Empty(t, p.Frames)
	require.NotEmpty(t, buffer.Data)
	require.Equal(t, f, tp.datagramQueue.Peek()) // make sure the frame is still there

	// Now try packing again, but with a smaller packet size.
	// The DATAGRAM frame should now be dropped, as we can't expect to ever be able tosend it out.
	const newMaxPacketSize = maxPacketSize - 10
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x43), protocol.PacketNumberLen2)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData()
	buffer = getPacketBuffer()
	p, err = tp.packer.AppendPacket(buffer, newMaxPacketSize, time.Now(), protocol.Version1)
	require.ErrorIs(t, err, errNothingToPack)
	require.Nil(t, tp.datagramQueue.Peek()) // make sure the frame is gone
}

func TestPackRetransmissions(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	f := &wire.CryptoFrame{Data: []byte("Initial")}
	tp.retransmissionQueue.addInitial(f)
	tp.retransmissionQueue.addHandshake(&wire.CryptoFrame{Data: []byte("Handshake")})
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), false)
	p, err := tp.packer.PackCoalescedPacket(false, 1000, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Len(t, p.longHdrPackets, 1)
	require.Equal(t, protocol.EncryptionInitial, p.longHdrPackets[0].EncryptionLevel())
	require.Len(t, p.longHdrPackets[0].frames, 1)
	require.Equal(t, f, p.longHdrPackets[0].frames[0].Frame)
	require.NotNil(t, p.longHdrPackets[0].frames[0].Handler)
}

func packMaxNumNonAckElicitingAcks(t *testing.T, tp *testPacketPacker, mockCtrl *gomock.Controller, maxPacketSize protocol.ByteCount) {
	t.Helper()
	for i := 0; i < protocol.MaxNonAckElicitingAcks; i++ {
		tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
		tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
		tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
		tp.framer.EXPECT().HasData().Return(true)
		tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false).Return(
			&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}},
		)
		expectAppendFrames(tp.framer, nil, nil)
		p, err := tp.packer.AppendPacket(getPacketBuffer(), maxPacketSize, time.Now(), protocol.Version1)
		require.NoError(t, err)
		require.NotNil(t, p.Ack)
		require.Empty(t, p.Frames)
	}
}

func TestPackEvery20thPacketAckEliciting(t *testing.T) {
	const maxPacketSize = 1000
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)

	// send the maximum number of non-ACK-eliciting packets
	packMaxNumNonAckElicitingAcks(t, tp, mockCtrl, maxPacketSize)

	// Now there's nothing to send, so we shouldn't generate a packet just to send a PING
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false)
	tp.framer.EXPECT().HasData().Return(true)
	expectAppendFrames(tp.framer, nil, nil)
	_, err := tp.packer.AppendPacket(getPacketBuffer(), maxPacketSize, time.Now(), protocol.Version1)
	require.ErrorIs(t, err, errNothingToPack)

	// Now we have an ACK to send. We should bundle a PING to make the packet ack-eliciting.
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false).Return(
		&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}},
	)
	expectAppendFrames(tp.framer, nil, nil)
	p, err := tp.packer.AppendPacket(getPacketBuffer(), maxPacketSize, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Len(t, p.Frames, 1)
	require.Equal(t, &wire.PingFrame{}, p.Frames[0].Frame)
	require.Nil(t, p.Frames[0].Handler) // make sure the PING is not retransmitted if lost

	// make sure the next packet doesn't contain another PING
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false).Return(
		&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}},
	)
	expectAppendFrames(tp.framer, nil, nil)
	p, err = tp.packer.AppendPacket(getPacketBuffer(), maxPacketSize, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, p.Ack)
	require.Empty(t, p.Frames)
}

func TestPackLongHeaderPadToAtLeast4Bytes(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen1)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(0x42))

	sealer := newMockShortHeaderSealer(mockCtrl)
	tp.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(sealer, nil)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.retransmissionQueue.addHandshake(&wire.PingFrame{})
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionHandshake, gomock.Any(), false)

	packet, err := tp.packer.PackCoalescedPacket(false, protocol.MaxByteCount, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, packet)
	require.Len(t, packet.longHdrPackets, 1)
	require.Nil(t, packet.shortHdrPacket)

	hdr, _, _, err := wire.ParsePacket(packet.buffer.Data)
	require.NoError(t, err)
	data := packet.buffer.Data
	extHdr, err := hdr.ParseExtended(data)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumberLen1, extHdr.PacketNumberLen)

	data = data[extHdr.ParsedLen():]
	require.Len(t, data, 4-1 /* packet number length */ +sealer.Overhead())
	// first bytes should be 2 PADDING frames...
	require.Equal(t, []byte{0, 0}, data[:2])
	// ...followed by the PING frame
	frameParser := wire.NewFrameParser(false)
	l, frame, err := frameParser.ParseNext(data[2:], protocol.EncryptionHandshake, protocol.Version1)
	require.NoError(t, err)
	require.IsType(t, &wire.PingFrame{}, frame)
	require.Equal(t, sealer.Overhead(), len(data)-2-l)
}

func TestPackShortHeaderPadToAtLeast4Bytes(t *testing.T) {
	// small stream ID, such that only a single byte is consumed
	f := &wire.StreamFrame{StreamID: 0x10, Fin: true}
	require.Equal(t, protocol.ByteCount(2), f.Length(protocol.Version1))

	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen1)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	sealer := newMockShortHeaderSealer(mockCtrl)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(sealer, nil)
	tp.framer.EXPECT().HasData().Return(true)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false)
	expectAppendFrames(tp.framer, nil, []ackhandler.StreamFrame{{Frame: f}})

	buffer := getPacketBuffer()
	_, err := tp.packer.AppendPacket(buffer, protocol.MaxByteCount, time.Now(), protocol.Version1)
	require.NoError(t, err)
	// cut off the tag that the mock sealer added
	buffer.Data = buffer.Data[:buffer.Len()-protocol.ByteCount(sealer.Overhead())]
	data := buffer.Data

	l, _, pnLen, _, err := wire.ParseShortHeader(data, testPackerConnIDLen)
	require.NoError(t, err)
	payload := data[l:]
	require.Equal(t, protocol.PacketNumberLen1, pnLen)
	require.Equal(t, 4-1 /* packet number length */, len(payload))
	// the first byte of the payload should be a PADDING frame...
	require.Equal(t, byte(0), payload[0])

	// ... followed by the STREAM frame
	frameParser := wire.NewFrameParser(true)
	frameLen, frame, err := frameParser.ParseNext(payload[1:], protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(payload)-1, frameLen)
}

func TestPackInitialProbePacket(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testPackProbePacket(t, protocol.EncryptionInitial, protocol.PerspectiveClient)
	})
	t.Run("server", func(t *testing.T) {
		testPackProbePacket(t, protocol.EncryptionInitial, protocol.PerspectiveServer)
	})
}

func TestPackHandshakeProbePacket(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testPackProbePacket(t, protocol.EncryptionHandshake, protocol.PerspectiveClient)
	})
	t.Run("server", func(t *testing.T) {
		testPackProbePacket(t, protocol.EncryptionHandshake, protocol.PerspectiveServer)
	})
}

func testPackProbePacket(t *testing.T, encLevel protocol.EncryptionLevel, perspective protocol.Perspective) {
	const maxPacketSize protocol.ByteCount = 1234
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, perspective)

	switch encLevel {
	case protocol.EncryptionInitial:
		tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
		tp.packer.initialStream.Write([]byte("foobar"))
	case protocol.EncryptionHandshake:
		tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
		tp.packer.handshakeStream.Write([]byte("foobar"))
	}
	tp.ackFramer.EXPECT().GetAckFrame(encLevel, gomock.Any(), false)
	tp.pnManager.EXPECT().PeekPacketNumber(encLevel).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(encLevel).Return(protocol.PacketNumber(0x42))

	p, err := tp.packer.MaybePackPTOProbePacket(encLevel, maxPacketSize, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Len(t, p.longHdrPackets, 1)
	packet := p.longHdrPackets[0]
	require.Equal(t, encLevel, packet.EncryptionLevel())
	if encLevel == protocol.EncryptionInitial {
		require.GreaterOrEqual(t, p.buffer.Len(), protocol.ByteCount(protocol.MinInitialPacketSize))
		require.Equal(t, maxPacketSize, p.buffer.Len())
	}
	require.Len(t, packet.frames, 1)
	require.Equal(t, &wire.CryptoFrame{Data: []byte("foobar")}, packet.frames[0].Frame)
	hdrs, more := parsePacket(t, p.buffer.Data)
	require.Len(t, hdrs, 1)
	switch encLevel {
	case protocol.EncryptionInitial:
		require.Equal(t, protocol.PacketTypeInitial, hdrs[0].Type)
	case protocol.EncryptionHandshake:
		require.Equal(t, protocol.PacketTypeHandshake, hdrs[0].Type)
	}
	require.Empty(t, more)
}

func TestPackProbePacketNothingToSend(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), true)

	p, err := tp.packer.MaybePackPTOProbePacket(protocol.EncryptionInitial, protocol.MaxByteCount, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Nil(t, p)
}

func TestPack1RTTProbePacket(t *testing.T) {
	const maxPacketSize protocol.ByteCount = 999

	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	tp.framer.EXPECT().HasData().Return(true)
	tp.framer.EXPECT().Append(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), protocol.Version1).DoAndReturn(
		func(cf []ackhandler.Frame, sf []ackhandler.StreamFrame, size protocol.ByteCount, _ time.Time, v protocol.Version) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
			f, split := (&wire.StreamFrame{Data: make([]byte, 2*maxPacketSize)}).MaybeSplitOffFrame(size, v)
			require.True(t, split)
			return cf, append(sf, ackhandler.StreamFrame{Frame: f}), f.Length(v)
		},
	)

	p, err := tp.packer.MaybePackPTOProbePacket(protocol.Encryption1RTT, maxPacketSize, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.True(t, p.IsOnlyShortHeaderPacket())
	require.Empty(t, p.longHdrPackets)
	require.NotNil(t, p.shortHdrPacket)
	packet := p.shortHdrPacket
	require.Empty(t, packet.Frames)
	require.Len(t, packet.StreamFrames, 1)
	require.Equal(t, maxPacketSize, packet.Length)
}

func TestPackProbePacketNothingToPack(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)

	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true)
	tp.framer.EXPECT().HasData()

	packet, err := tp.packer.MaybePackPTOProbePacket(protocol.Encryption1RTT, protocol.MaxByteCount, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Nil(t, packet)
}

func TestPackMTUProbePacket(t *testing.T) {
	const (
		maxPacketSize   protocol.ByteCount = 1000
		probePacketSize                    = maxPacketSize + 42
	)

	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x43), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x43))
	ping := ackhandler.Frame{Frame: &wire.PingFrame{}}
	p, buffer, err := tp.packer.PackMTUProbePacket(ping, probePacketSize, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, probePacketSize, p.Length)
	require.Equal(t, protocol.PacketNumber(0x43), p.PacketNumber)
	require.Len(t, buffer.Data, int(probePacketSize))
	require.True(t, p.IsPathMTUProbePacket)
	require.False(t, p.IsPathProbePacket)
}

func TestPackPathProbePacket(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveServer)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x43), protocol.PacketNumberLen2)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x43))

	p, buf, err := tp.packer.PackPathProbePacket(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		ackhandler.Frame{Frame: &wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}},
		protocol.Version1,
	)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(0x43), p.PacketNumber)
	require.Nil(t, p.Ack)
	require.Empty(t, p.StreamFrames)
	require.Equal(t, &wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}, p.Frames[0].Frame)
	require.Len(t, buf.Data, protocol.MinInitialPacketSize)
	require.True(t, p.IsPathProbePacket)
	require.False(t, p.IsPathMTUProbePacket)
}
