package quic

import (
	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

type qmuxSentPacketHandler struct {
	connStats *utils.ConnectionStats
}

var _ ackhandler.SentPacketHandler = &qmuxSentPacketHandler{}

func (h *qmuxSentPacketHandler) SentPacket(
	_ monotime.Time,
	_, _ protocol.PacketNumber,
	_ []ackhandler.StreamFrame,
	_ []ackhandler.Frame,
	_ protocol.EncryptionLevel,
	_ protocol.ECN,
	size protocol.ByteCount,
	_, _ bool,
) {
	if h.connStats != nil {
		h.connStats.BytesSent.Add(uint64(size))
		h.connStats.PacketsSent.Add(1)
	}
}

func (h *qmuxSentPacketHandler) ReceivedAck(*wire.AckFrame, protocol.EncryptionLevel, monotime.Time) (bool, error) {
	return false, nil
}

func (h *qmuxSentPacketHandler) ReceivedPacket(protocol.EncryptionLevel, monotime.Time) {
	if h.connStats != nil {
		h.connStats.PacketsReceived.Add(1)
	}
}

func (h *qmuxSentPacketHandler) ReceivedBytes(size protocol.ByteCount, _ monotime.Time) {
	if h.connStats != nil {
		h.connStats.BytesReceived.Add(uint64(size))
	}
}

func (h *qmuxSentPacketHandler) DropPackets(protocol.EncryptionLevel, monotime.Time) {}

func (h *qmuxSentPacketHandler) ResetForRetry(monotime.Time) {}

func (h *qmuxSentPacketHandler) SendMode(monotime.Time) ackhandler.SendMode {
	return ackhandler.SendAny
}

func (h *qmuxSentPacketHandler) TimeUntilSend() monotime.Time { return 0 }

func (h *qmuxSentPacketHandler) SetMaxDatagramSize(protocol.ByteCount) {}

func (h *qmuxSentPacketHandler) QueueProbePacket(protocol.EncryptionLevel) bool { return false }

func (h *qmuxSentPacketHandler) ECNMode(bool) protocol.ECN { return protocol.ECNUnsupported }

func (h *qmuxSentPacketHandler) PeekPacketNumber(protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	return 0, protocol.PacketNumberLen1
}

func (h *qmuxSentPacketHandler) PopPacketNumber(protocol.EncryptionLevel) protocol.PacketNumber {
	return 0
}

func (h *qmuxSentPacketHandler) GetLossDetectionTimeout() monotime.Time { return 0 }

func (h *qmuxSentPacketHandler) OnLossDetectionTimeout(monotime.Time) error { return nil }

func (h *qmuxSentPacketHandler) MigratedPath(monotime.Time, protocol.ByteCount) {}
