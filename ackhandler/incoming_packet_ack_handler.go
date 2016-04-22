package ackhandler

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// The AckHandler handles ACKs
type incomingPacketAckHandler struct {
	largestObserved protocol.PacketNumber
	observed        map[protocol.PacketNumber]bool
}

// NewIncomingPacketAckHandler creates a new outgoingPacketAckHandler
func NewIncomingPacketAckHandler() IncomingPacketAckHandler {
	return &incomingPacketAckHandler{
		observed: make(map[protocol.PacketNumber]bool),
	}
}

func (h *incomingPacketAckHandler) ReceivedPacket(packetNumber protocol.PacketNumber, entropyBit bool) {
	if packetNumber > h.largestObserved {
		h.largestObserved = packetNumber
	}
	h.observed[packetNumber] = true
}

// GetNackRanges gets all the NACK ranges
func (h *incomingPacketAckHandler) GetNackRanges() []*frames.NackRange {
	// ToDo: improve performance
	var ranges []*frames.NackRange
	inRange := false
	// ToDo: fix types
	for i := 0; i < int(h.largestObserved); i++ {
		packetNumber := protocol.PacketNumber(i)
		_, ok := h.observed[packetNumber]
		if !ok {
			if !inRange {
				r := &frames.NackRange{
					FirstPacketNumber: packetNumber,
					LastPacketNumber:  packetNumber,
				}
				ranges = append(ranges, r)
				inRange = true
			} else {
				ranges[len(ranges)-1].LastPacketNumber++
			}
		} else {
			inRange = false
		}
	}
	return ranges
}

func (h *incomingPacketAckHandler) DequeueAckFrame() *frames.AckFrame {
	return nil
}
