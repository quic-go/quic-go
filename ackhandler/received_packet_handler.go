package ackhandler

import (
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// ErrDuplicatePacket occurres when a duplicate packet is received
var ErrDuplicatePacket = errors.New("ReceivedPacketHandler: Duplicate Packet")

type packetHistoryEntry struct {
	EntropyBit   bool
	TimeReceived time.Time
}

type receivedPacketHandler struct {
	highestInOrderObserved        protocol.PacketNumber
	highestInOrderObservedEntropy EntropyAccumulator
	largestObserved               protocol.PacketNumber
	packetHistory                 map[protocol.PacketNumber]packetHistoryEntry
	stateChanged                  bool // has an ACK for this state already been sent? Will be set to false every time a new packet arrives, and to false every time an ACK is sent
}

// NewReceivedPacketHandler creates a new receivedPacketHandler
func NewReceivedPacketHandler() ReceivedPacketHandler {
	return &receivedPacketHandler{
		packetHistory: make(map[protocol.PacketNumber]packetHistoryEntry),
	}
}

func (h *receivedPacketHandler) ReceivedPacket(packetNumber protocol.PacketNumber, entropyBit bool) error {
	if packetNumber == 0 {
		return errors.New("Invalid packet number")
	}
	_, ok := h.packetHistory[packetNumber]
	if packetNumber <= h.highestInOrderObserved || ok {
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

	h.packetHistory[packetNumber] = packetHistoryEntry{
		EntropyBit:   entropyBit,
		TimeReceived: time.Now(),
	}
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
	for i := h.largestObserved; i > h.highestInOrderObserved; i-- {
		p, ok := h.packetHistory[i]
		if !ok {
			if !inRange {
				r := frames.NackRange{
					FirstPacketNumber: i,
					LastPacketNumber:  i,
				}
				ranges = append(ranges, r)
				inRange = true
			} else {
				ranges[len(ranges)-1].FirstPacketNumber--
			}
		} else {
			inRange = false
			entropy.Add(i, p.EntropyBit)
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
