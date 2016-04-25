package ackhandler

import (
	"errors"
	"sync"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

var (
	errEntropy              = errors.New("OutgoingPacketAckHandler: Wrong entropy")
	errMapAccess            = errors.New("OutgoingPacketAckHandler: Packet does not exist in PacketHistory")
	retransmissionThreshold = uint8(3)
)

type outgoingPacketAckHandler struct {
	lastSentPacketNumber            protocol.PacketNumber
	highestInOrderAckedPacketNumber protocol.PacketNumber
	highestInOrderAckedEntropy      EntropyAccumulator
	LargestObserved                 protocol.PacketNumber
	packetHistory                   map[protocol.PacketNumber]*Packet
	packetHistoryMutex              sync.Mutex
	retransmissionQueue             []*Packet // ToDo: use better data structure
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

func (h *outgoingPacketAckHandler) calculateExpectedEntropy(ackFrame *frames.AckFrame) (EntropyAccumulator, error) {
	h.packetHistoryMutex.Lock()
	defer h.packetHistoryMutex.Unlock()

	highestInOrderAckedPacketNumber := ackFrame.GetHighestInOrderPacketNumber()

	var expectedEntropy EntropyAccumulator

	// get the entropy for the highestInOrderAckedPacketNumber
	// There are two cases:
	// 1. the packet with highestInOrderAckedPacketNumber has already been ACKed, then it doesn't exist in the packetHistory map anymore, but the value was saved as h.highestInOrderAckedEntropy
	// 2. the packet with highestInOrderAckedPacketNumber has not yet been ACKed, then it should exist in the packetHistory map, and can just be read from there
	if highestInOrderAckedPacketNumber == h.highestInOrderAckedPacketNumber {
		expectedEntropy = h.highestInOrderAckedEntropy
	} else {
		packet, ok := h.packetHistory[highestInOrderAckedPacketNumber]
		if !ok {
			return 0, errMapAccess
		}
		expectedEntropy = packet.Entropy
	}

	if ackFrame.HasNACK() { // if the packet has NACKs, the entropy value has to be calculated
		nackRangeIndex := len(ackFrame.NackRanges) - 1
		nackRange := ackFrame.NackRanges[nackRangeIndex]
		for i := highestInOrderAckedPacketNumber + 1; i <= ackFrame.LargestObserved; i++ {
			// select correct NACK range
			if i > nackRange.LastPacketNumber {
				nackRangeIndex--
				if nackRangeIndex >= 0 {
					nackRange = ackFrame.NackRanges[nackRangeIndex]
				}
			}
			if i >= nackRange.FirstPacketNumber && i <= nackRange.LastPacketNumber { // PacketNumber i is contained in a NACK range, it's entropyBit is irrelevant
				continue
			}
			// PacketNumber i is not contained in a NACK range, it's entropyBit has to be considered
			packet, ok := h.packetHistory[i]
			if !ok {
				return 0, errMapAccess
			}
			expectedEntropy.Add(i, packet.EntropyBit)
		}
	}

	return expectedEntropy, nil
}

func (h *outgoingPacketAckHandler) ReceivedAck(ackFrame *frames.AckFrame) error {
	if ackFrame.LargestObserved > h.lastSentPacketNumber {
		return errors.New("OutgoingPacketAckHandler: Received ACK for an unsent package")
	}

	if ackFrame.LargestObserved <= h.LargestObserved { // duplicate or out-of-order AckFrame
		return nil
	}

	expectedEntropy, err := h.calculateExpectedEntropy(ackFrame)
	if err != nil {
		return err
	}

	if byte(expectedEntropy) != ackFrame.Entropy {
		return errEntropy
	}

	// Entropy ok. Now actually process the ACK packet
	h.packetHistoryMutex.Lock()
	defer h.packetHistoryMutex.Unlock()

	highestInOrderAckedPacketNumber := ackFrame.GetHighestInOrderPacketNumber()
	highestInOrderAckedEntropy := h.highestInOrderAckedEntropy

	// if this ACK increases the highestInOrderAckedPacketNumber, the packet will be deleted from the packetHistory map, thus we need to save it's Entropy before doing so
	if highestInOrderAckedPacketNumber > h.highestInOrderAckedPacketNumber {
		packet, ok := h.packetHistory[highestInOrderAckedPacketNumber]
		if !ok {
			return errMapAccess
		}
		highestInOrderAckedEntropy = packet.Entropy
	}

	// delete all packets below the highestInOrderAckedPacketNumber
	for i := h.highestInOrderAckedPacketNumber; i <= highestInOrderAckedPacketNumber; i++ {
		delete(h.packetHistory, i)
	}

	// increase MissingReports counter of NACKed packets
	// this is the case if the PacketNumber is *not* contained in any of the NACK ranges
	if ackFrame.HasNACK() {
		nackRangeIndex := len(ackFrame.NackRanges) - 1
		nackRange := ackFrame.NackRanges[nackRangeIndex]
		for i := highestInOrderAckedPacketNumber + 1; i <= ackFrame.LargestObserved; i++ {
			// select correct NACK range
			if i > nackRange.LastPacketNumber {
				nackRangeIndex--
				if nackRangeIndex >= 0 {
					nackRange = ackFrame.NackRanges[nackRangeIndex]
				}
			}
			// PacketNumber i is not contained in a NACK range, increase it's missingReports counter
			if i >= nackRange.FirstPacketNumber && i <= nackRange.LastPacketNumber {
				packet, ok := h.packetHistory[i]
				if !ok {
					return errMapAccess
				}
				packet.MissingReports++
				// send out the packet again when it has been NACK more than retransmissionThreshold times
				if packet.MissingReports > retransmissionThreshold {
					h.retransmissionQueue = append(h.retransmissionQueue, packet)
					// ToDo: delete the packet from the history, as if it had been acked
				}
			}
			// ToDo: delete packet from history, since it already has been ACKed
		}
	}

	h.highestInOrderAckedPacketNumber = highestInOrderAckedPacketNumber
	h.highestInOrderAckedEntropy = highestInOrderAckedEntropy

	return nil
}

func (h *outgoingPacketAckHandler) DequeuePacketForRetransmission() (packet *Packet) {
	if len(h.retransmissionQueue) == 0 {
		return nil
	}
	packet = h.retransmissionQueue[0]
	h.retransmissionQueue = h.retransmissionQueue[1:]
	return packet
}
