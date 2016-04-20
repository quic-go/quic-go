package ackhandler

import (
	"errors"
	"sync"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

type outgoingPacketAckHandler struct {
	lastSentPacketNumber protocol.PacketNumber
	packetHistory        map[protocol.PacketNumber]*Packet
	packetHistoryMutex   sync.Mutex
}

// NewOutgoingPacketAckHandler creates a new outgoingPacketAckHandler
func NewOutgoingPacketAckHandler() OutgoingPacketAckHandler {
	return &outgoingPacketAckHandler{
		packetHistory: make(map[protocol.PacketNumber]*Packet),
	}
}

func (h *outgoingPacketAckHandler) SentPacket(packet *Packet) error {
	h.packetHistoryMutex.Lock()
	defer h.packetHistoryMutex.Unlock()
	_, ok := h.packetHistory[packet.PacketNumber]
	if ok {
		return errors.New("Packet number already exists in Packet History")
	}
	if h.lastSentPacketNumber+1 != packet.PacketNumber {
		return errors.New("Packet number must be increased by exactly 1")
	}
	h.lastSentPacketNumber = packet.PacketNumber
	h.packetHistory[packet.PacketNumber] = packet
	return nil
}

func (h *outgoingPacketAckHandler) ReceivedAck(ackFrame *frames.AckFrame) {
	return
}

func (h *outgoingPacketAckHandler) DequeuePacketForRetransmission() (packet *Packet) {
	return nil
}
