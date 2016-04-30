package ackhandler

import (
	"errors"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

var ErrDuplicatePacket = errors.New("ReceivedPacketHandler: Duplicate Packet")

type receivedPacketHandler struct {
	highestInOrderObserved        protocol.PacketNumber
	highestInOrderObservedEntropy EntropyAccumulator
	largestObserved               protocol.PacketNumber
	packetHistory                 map[protocol.PacketNumber]bool // the bool is the EntropyBit of the packet
	stateChanged                  bool                           // has an ACK for this state already been sent? Will be set to false every time a new packet arrives, and to false every time an ACK is sent
}

// NewReceivedPacketHandler creates a new receivedPacketHandler
func NewReceivedPacketHandler() ReceivedPacketHandler {
	return &receivedPacketHandler{
		packetHistory: make(map[protocol.PacketNumber]bool),
	}
}

func (h *receivedPacketHandler) ReceivedPacket(packetNumber protocol.PacketNumber, entropyBit bool) error {
	if packetNumber == 0 {
		return errors.New("Invalid packet number")
	}
	if packetNumber <= h.highestInOrderObserved || h.packetHistory[packetNumber] {
		return ErrDuplicatePacket
	}

	h.stateChanged = true

	if packetNumber > h.largestObserved {
		h.largestObserved = packetNumber
	}

	if packetNumber == h.highestInOrderObserved+1 {
		h.highestInOrderObserved = packetNumber
		h.highestInOrderObservedEntropy.Add(packetNumber, entropyBit)
	}

	h.packetHistory[packetNumber] = entropyBit
	return nil
}

func (h *receivedPacketHandler) ReceivedStopWaiting(f *frames.StopWaitingFrame) error {
	// Ignore if STOP_WAITING is unneeded
	if h.highestInOrderObserved >= f.LeastUnacked {
		return nil
	}

	// the LeastUnacked is the smallest packet number of any packet for which the sender is still awaiting an ack. So the highestInOrderObserved is one less than that
	h.highestInOrderObserved = f.LeastUnacked - 1
	h.highestInOrderObservedEntropy = EntropyAccumulator(f.Entropy)

	return nil
}

// getNackRanges gets all the NACK ranges
func (h *receivedPacketHandler) getNackRanges() ([]frames.NackRange, EntropyAccumulator) {
	// ToDo: use a better data structure here
	var ranges []frames.NackRange
	inRange := false
	entropy := h.highestInOrderObservedEntropy
	for i := h.highestInOrderObserved + 1; i <= h.largestObserved; i++ {
		entropyBit, ok := h.packetHistory[i]
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
			entropy.Add(i, entropyBit)
		}
	}
	return ranges, entropy
}

func (h *receivedPacketHandler) DequeueAckFrame() *frames.AckFrame {
	if !h.stateChanged {
		return nil
	}

	h.stateChanged = false

	nackRanges, entropy := h.getNackRanges()
	return &frames.AckFrame{
		LargestObserved: h.largestObserved,
		Entropy:         byte(entropy),
		NackRanges:      nackRanges,
	}
}
