package ackhandler

import (
	"errors"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

var ErrDuplicatePacket = errors.New("Duplicate Packet")

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

func (h *incomingPacketAckHandler) ReceivedPacket(packetNumber protocol.PacketNumber, entropyBit bool) error {
	if packetNumber == 0 {
		return errors.New("Invalid packet number")
	}
	if h.observed[packetNumber] {
		return ErrDuplicatePacket
	}

	if packetNumber > h.largestObserved {
		h.largestObserved = packetNumber
	}
	h.observed[packetNumber] = true
	return nil
}

// getNackRanges gets all the NACK ranges
func (h *incomingPacketAckHandler) getNackRanges() []frames.NackRange {
	// ToDo: improve performance
	var ranges []frames.NackRange
	inRange := false
	for i := protocol.PacketNumber(1); i < h.largestObserved; i++ {
		_, ok := h.observed[i]
		if !ok {
			if !inRange {
				r := frames.NackRange{
					FirstPacketNumber: i,
					LastPacketNumber:  i,
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
