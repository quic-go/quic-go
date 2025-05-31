package ackhandler

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestGenerateACKsForPacketNumberSpaces(t *testing.T) {
	ctrl := gomock.NewController(t)
	sentPackets := NewMockSentPacketTracker(ctrl)
	handler := newReceivedPacketHandler(sentPackets, utils.DefaultLogger)

	now := time.Now()
	sendTime := now.Add(-time.Second)
	sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().AnyTimes()
	sentPackets.EXPECT().ReceivedPacket(protocol.EncryptionInitial, sendTime).Times(2)
	sentPackets.EXPECT().ReceivedPacket(protocol.EncryptionHandshake, sendTime).Times(2)
	sentPackets.EXPECT().ReceivedPacket(protocol.Encryption1RTT, sendTime).Times(2)

	require.NoError(t, handler.ReceivedPacket(2, protocol.ECT0, protocol.EncryptionInitial, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECT1, protocol.EncryptionHandshake, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(5, protocol.ECNCE, protocol.Encryption1RTT, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(3, protocol.ECT0, protocol.EncryptionInitial, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(2, protocol.ECT1, protocol.EncryptionHandshake, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(4, protocol.ECNCE, protocol.Encryption1RTT, sendTime, true))

	// Initial
	initialAck := handler.GetAckFrame(protocol.EncryptionInitial, now, true)
	require.NotNil(t, initialAck)
	require.Equal(t, []wire.AckRange{{Smallest: 2, Largest: 3}}, initialAck.AckRanges)
	require.Zero(t, initialAck.DelayTime)
	require.EqualValues(t, 2, initialAck.ECT0)
	require.Zero(t, initialAck.ECT1)
	require.Zero(t, initialAck.ECNCE)

	// Handshake
	handshakeAck := handler.GetAckFrame(protocol.EncryptionHandshake, now, true)
	require.NotNil(t, handshakeAck)
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 2}}, handshakeAck.AckRanges)
	require.Zero(t, handshakeAck.DelayTime)
	require.Zero(t, handshakeAck.ECT0)
	require.EqualValues(t, 2, handshakeAck.ECT1)
	require.Zero(t, handshakeAck.ECNCE)

	// 1-RTT
	oneRTTAck := handler.GetAckFrame(protocol.Encryption1RTT, now, true)
	require.NotNil(t, oneRTTAck)
	require.Equal(t, []wire.AckRange{{Smallest: 4, Largest: 5}}, oneRTTAck.AckRanges)
	require.Equal(t, time.Second, oneRTTAck.DelayTime)
	require.Zero(t, oneRTTAck.ECT0)
	require.Zero(t, oneRTTAck.ECT1)
	require.EqualValues(t, 2, oneRTTAck.ECNCE)
}

func TestReceive0RTTAnd1RTT(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sentPackets := NewMockSentPacketTracker(mockCtrl)
	handler := newReceivedPacketHandler(sentPackets, utils.DefaultLogger)

	sendTime := time.Now().Add(-time.Second)
	sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().AnyTimes()
	sentPackets.EXPECT().ReceivedPacket(protocol.Encryption0RTT, sendTime).AnyTimes()
	sentPackets.EXPECT().ReceivedPacket(protocol.Encryption1RTT, sendTime)

	require.NoError(t, handler.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption0RTT, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(3, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true))

	ack := handler.GetAckFrame(protocol.Encryption1RTT, time.Now(), true)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 2, Largest: 3}}, ack.AckRanges)

	// 0-RTT packets with higher packet numbers than 1-RTT packets are rejected...
	require.Error(t, handler.ReceivedPacket(4, protocol.ECNNon, protocol.Encryption0RTT, sendTime, true))
	// ... but reordered 0-RTT packets are allowed
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.Encryption0RTT, sendTime, true))
}

func TestDropPackets(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sentPackets := NewMockSentPacketTracker(mockCtrl)
	sentPackets.EXPECT().ReceivedPacket(gomock.Any(), gomock.Any()).AnyTimes()
	sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().AnyTimes()
	handler := newReceivedPacketHandler(sentPackets, utils.DefaultLogger)

	sendTime := time.Now().Add(-time.Second)

	require.NoError(t, handler.ReceivedPacket(2, protocol.ECNNon, protocol.EncryptionInitial, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.EncryptionHandshake, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true))

	// Initial
	require.NotNil(t, handler.GetAckFrame(protocol.EncryptionInitial, time.Now(), true))
	handler.DropPackets(protocol.EncryptionInitial)
	require.Nil(t, handler.GetAckFrame(protocol.EncryptionInitial, time.Now(), true))

	// Handshake
	require.NotNil(t, handler.GetAckFrame(protocol.EncryptionHandshake, time.Now(), true))
	handler.DropPackets(protocol.EncryptionHandshake)
	require.Nil(t, handler.GetAckFrame(protocol.EncryptionHandshake, time.Now(), true))

	// 1-RTT
	require.NotNil(t, handler.GetAckFrame(protocol.Encryption1RTT, time.Now(), true))

	// 0-RTT is a no-op
	handler.DropPackets(protocol.Encryption0RTT)
}

func TestAckRangePruning(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sentPackets := NewMockSentPacketTracker(mockCtrl)
	sentPackets.EXPECT().ReceivedPacket(gomock.Any(), gomock.Any()).AnyTimes()
	sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().Times(3)
	handler := newReceivedPacketHandler(sentPackets, utils.DefaultLogger)

	sendTime := time.Now()
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true))

	ack := handler.GetAckFrame(protocol.Encryption1RTT, time.Now(), true)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 2}}, ack.AckRanges)

	require.NoError(t, handler.ReceivedPacket(3, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true))
	sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().Return(protocol.PacketNumber(2))
	require.NoError(t, handler.ReceivedPacket(4, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true))

	ack = handler.GetAckFrame(protocol.Encryption1RTT, time.Now(), true)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 2, Largest: 4}}, ack.AckRanges)
}

func TestPacketDuplicateDetection(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sentPackets := NewMockSentPacketTracker(mockCtrl)
	sentPackets.EXPECT().ReceivedPacket(gomock.Any(), gomock.Any()).AnyTimes()
	sentPackets.EXPECT().GetLowestPacketNotConfirmedAcked().AnyTimes()

	handler := newReceivedPacketHandler(sentPackets, utils.DefaultLogger)
	sendTime := time.Now()

	// 1-RTT is tested separately at the end
	encLevels := []protocol.EncryptionLevel{
		protocol.EncryptionInitial,
		protocol.EncryptionHandshake,
		protocol.Encryption0RTT,
	}

	for _, encLevel := range encLevels {
		// first, packet 3 is not a duplicate
		require.False(t, handler.IsPotentiallyDuplicate(3, encLevel))
		require.NoError(t, handler.ReceivedPacket(3, protocol.ECNNon, encLevel, sendTime, true))
		// now packet 3 is considered a duplicate
		require.True(t, handler.IsPotentiallyDuplicate(3, encLevel))
	}

	// 1-RTT
	require.True(t, handler.IsPotentiallyDuplicate(3, protocol.Encryption1RTT))
	require.False(t, handler.IsPotentiallyDuplicate(4, protocol.Encryption1RTT))
	require.NoError(t, handler.ReceivedPacket(4, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true))
	require.True(t, handler.IsPotentiallyDuplicate(4, protocol.Encryption1RTT))
}
