package ackhandler

import (
	"errors"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

var ErrDuplicatePacket = errors.New("Duplicate Packet")

// The AckHandler handles ACKs
type incomingPacketAckHandler struct {
	highestInOrderObserved        protocol.PacketNumber
	highestInOrderObservedEntropy EntropyAccumulator
	largestObserved               protocol.PacketNumber
	packetHistory                 map[protocol.PacketNumber]bool
}

// NewIncomingPacketAckHandler creates a new outgoingPacketAckHandler
func NewIncomingPacketAckHandler() IncomingPacketAckHandler {
	return &incomingPacketAckHandler{
		packetHistory: make(map[protocol.PacketNumber]bool),
	}
}

func (h *incomingPacketAckHandler) ReceivedPacket(packetNumber protocol.PacketNumber, entropyBit bool) error {
	if packetNumber == 0 {
		return errors.New("Invalid packet number")
	}
	if packetNumber <= h.highestInOrderObserved || h.packetHistory[packetNumber] {
		return ErrDuplicatePacket
	}

	if packetNumber > h.largestObserved {
		h.largestObserved = packetNumber
	}

	if packetNumber == h.highestInOrderObserved+1 {
		h.highestInOrderObserved = packetNumber
		h.highestInOrderObservedEntropy.Add(packetNumber, entropyBit)
	}

	h.packetHistory[packetNumber] = true
	return nil
}

// getNackRanges gets all the NACK ranges
func (h *incomingPacketAckHandler) getNackRanges() []frames.NackRange {
	// ToDo: improve performance
	var ranges []frames.NackRange
	inRange := false
	for i := h.highestInOrderObserved; i < h.largestObserved; i++ {
		_, ok := h.packetHistory[i]
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
	nackRanges := h.getNackRanges()
	entropy := byte(0)
	return &frames.AckFrame{
		LargestObserved: h.largestObserved,
		Entropy:         entropy,
		NackRanges:      nackRanges,
	}
}
