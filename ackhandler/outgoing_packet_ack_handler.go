package ackhandler

import (
	"errors"
	"sync"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

type outgoingPacketAckHandler struct {
	lastSentPacketNumber            protocol.PacketNumber
	highestInOrderAckedPacketNumber protocol.PacketNumber
	highestInOrderAckedEntropy      EntropyAccumulator
	LargestObserved                 protocol.PacketNumber
	packetHistory                   map[protocol.PacketNumber]*Packet
	packetHistoryMutex              sync.Mutex
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

	var lastPacketEntropy EntropyAccumulator
	if packet.PacketNumber == 1 {
		lastPacketEntropy = EntropyAccumulator(0)
	} else {
		if h.highestInOrderAckedPacketNumber == packet.PacketNumber-1 {
			lastPacketEntropy = h.highestInOrderAckedEntropy
		} else {
			lastPacketEntropy = h.packetHistory[packet.PacketNumber-1].Entropy
		}
	}
	lastPacketEntropy.Add(packet.PacketNumber, packet.EntropyBit)
	packet.Entropy = lastPacketEntropy
	h.lastSentPacketNumber = packet.PacketNumber
	h.packetHistory[packet.PacketNumber] = packet
	return nil
}

func (h *outgoingPacketAckHandler) ReceivedAck(ackFrame *frames.AckFrame) error {
	if ackFrame.LargestObserved > h.lastSentPacketNumber {
		return errors.New("OutgoingPacketAckHandler: Received ACK for an unsent package")
	}

	if ackFrame.LargestObserved <= h.LargestObserved { // duplicate or out-of-order AckFrame
		return nil
	}

	entropyError := errors.New("OutgoingPacketAckHandler: Wrong entropy")
	mapAccessError := errors.New("OutgoingPacketAckHandler: Packet does not exist in PacketHistory")

	h.packetHistoryMutex.Lock()
	defer h.packetHistoryMutex.Unlock()

	highestInOrderAckedEntropy := h.highestInOrderAckedEntropy
	highestInOrderAckedPacketNumber := ackFrame.GetHighestInOrderPacketNumber()
	for i := h.highestInOrderAckedPacketNumber + 1; i <= highestInOrderAckedPacketNumber; i++ {
		packet, ok := h.packetHistory[i]
		if !ok {
			return mapAccessError
		}
		highestInOrderAckedEntropy.Add(packet.PacketNumber, packet.EntropyBit)
	}

	var expectedEntropy EntropyAccumulator

	if !ackFrame.HasNACK() {
		packet, ok := h.packetHistory[ackFrame.LargestObserved]
		if !ok {
			return mapAccessError
		}
		expectedEntropy = packet.Entropy
	} else {
		if highestInOrderAckedPacketNumber == h.highestInOrderAckedPacketNumber {
			expectedEntropy = h.highestInOrderAckedEntropy
		} else {
			packet, ok := h.packetHistory[highestInOrderAckedPacketNumber]
			if !ok {
				return mapAccessError
			}
			expectedEntropy = packet.Entropy
		}

		nackRangeIndex := len(ackFrame.NackRanges) - 1
		nackRange := ackFrame.NackRanges[nackRangeIndex]
		for i := highestInOrderAckedPacketNumber + 1; i <= ackFrame.LargestObserved; i++ {
			if i > nackRange.LastPacketNumber {
				nackRangeIndex--
				if nackRangeIndex >= 0 {
					nackRange = ackFrame.NackRanges[nackRangeIndex]
				}
			}
			if i >= nackRange.FirstPacketNumber && i <= nackRange.LastPacketNumber {
				continue
			}
			packet, ok := h.packetHistory[i]
			if !ok {
				return mapAccessError
			}
			expectedEntropy.Add(i, packet.EntropyBit)
		}
	}

	if ackFrame.Entropy != byte(expectedEntropy) {
		return entropyError
	}

	// Entropy ok. Now actually process the ACK packet
	for i := h.highestInOrderAckedPacketNumber; i <= highestInOrderAckedPacketNumber; i++ {
		delete(h.packetHistory, i)
	}

	if ackFrame.HasNACK() {
		nackRangeIndex := len(ackFrame.NackRanges) - 1
		nackRange := ackFrame.NackRanges[nackRangeIndex]
		for i := highestInOrderAckedPacketNumber + 1; i <= ackFrame.LargestObserved; i++ {
			if i > nackRange.LastPacketNumber {
				nackRangeIndex--
				if nackRangeIndex >= 0 {
					nackRange = ackFrame.NackRanges[nackRangeIndex]
				}
			}
			if i >= nackRange.FirstPacketNumber && i <= nackRange.LastPacketNumber {
				continue
			}
			delete(h.packetHistory, i)
		}
	}

	h.highestInOrderAckedPacketNumber = highestInOrderAckedPacketNumber
	h.highestInOrderAckedEntropy = highestInOrderAckedEntropy
	return nil
}

func (h *outgoingPacketAckHandler) DequeuePacketForRetransmission() (packet *Packet) {
	return nil
}
