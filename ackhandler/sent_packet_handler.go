package ackhandler

import (
	"errors"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

var (
	// ErrDuplicateOrOutOfOrderAck occurs when a duplicate or an out-of-order ACK is received
	ErrDuplicateOrOutOfOrderAck = errors.New("SentPacketHandler: Duplicate or out-of-order ACK")
	// ErrEntropy occurs when an ACK with incorrect entropy is received
	ErrEntropy = errors.New("SentPacketHandler: Wrong entropy")
	// ErrMapAccess occurs when a NACK contains invalid NACK ranges
	ErrMapAccess = errors.New("SentPacketHandler: Packet does not exist in PacketHistory")
)

var (
	errAckForUnsentPacket   = errors.New("SentPacketHandler: Received ACK for an unsent package")
	retransmissionThreshold = uint8(3)
)

type sentPacketHandler struct {
	lastSentPacketNumber            protocol.PacketNumber
	lastSentPacketEntropy           EntropyAccumulator
	highestInOrderAckedPacketNumber protocol.PacketNumber
	LargestObserved                 protocol.PacketNumber
	LargestObservedEntropy          EntropyAccumulator

	packetHistory map[protocol.PacketNumber]*Packet

	retransmissionQueue []*Packet // ToDo: use better data structure
}

// NewSentPacketHandler creates a new sentPacketHandler
func NewSentPacketHandler() SentPacketHandler {
	return &sentPacketHandler{
		packetHistory: make(map[protocol.PacketNumber]*Packet),
	}
}

func (h *sentPacketHandler) ackPacket(packetNumber protocol.PacketNumber) {
	delete(h.packetHistory, packetNumber)
}

func (h *sentPacketHandler) nackPacket(packetNumber protocol.PacketNumber) error {
	packet, ok := h.packetHistory[packetNumber]
	if !ok {
		return ErrMapAccess
	}

	packet.MissingReports++

	if packet.MissingReports > retransmissionThreshold {
		h.queuePacketForRetransmission(packet)
	}
	return nil
}

func (h *sentPacketHandler) recalculateHighestInOrderAckedPacketNumberFromPacketHistory() {
	for i := h.highestInOrderAckedPacketNumber; i <= h.lastSentPacketNumber; i++ {
		_, ok := h.packetHistory[i]
		if ok {
			break
		}
		h.highestInOrderAckedPacketNumber = i
	}
}

func (h *sentPacketHandler) queuePacketForRetransmission(packet *Packet) {
	h.retransmissionQueue = append(h.retransmissionQueue, packet)
	h.ackPacket(packet.PacketNumber)
	h.recalculateHighestInOrderAckedPacketNumberFromPacketHistory()
}

func (h *sentPacketHandler) SentPacket(packet *Packet) error {
	_, ok := h.packetHistory[packet.PacketNumber]
	if ok {
		return errors.New("Packet number already exists in Packet History")
	}
	if h.lastSentPacketNumber+1 != packet.PacketNumber {
		return errors.New("Packet number must be increased by exactly 1")
	}

	h.lastSentPacketEntropy.Add(packet.PacketNumber, packet.EntropyBit)
	packet.Entropy = h.lastSentPacketEntropy
	h.lastSentPacketNumber = packet.PacketNumber
	h.packetHistory[packet.PacketNumber] = packet
	return nil
}

func (h *sentPacketHandler) calculateExpectedEntropy(ackFrame *frames.AckFrame) (EntropyAccumulator, error) {
	packet, ok := h.packetHistory[ackFrame.LargestObserved]
	if !ok {
		return 0, ErrMapAccess
	}
	expectedEntropy := packet.Entropy

	if ackFrame.HasNACK() { // if the packet has NACKs, the entropy value has to be calculated
		nackRangeIndex := 0
		nackRange := ackFrame.NackRanges[nackRangeIndex]
		for i := ackFrame.LargestObserved; i > ackFrame.GetHighestInOrderPacketNumber(); i-- {
			if i < nackRange.FirstPacketNumber {
				nackRangeIndex++
				if nackRangeIndex < len(ackFrame.NackRanges) {
					nackRange = ackFrame.NackRanges[nackRangeIndex]
				}
			}
			if i >= nackRange.FirstPacketNumber && i <= nackRange.LastPacketNumber {
				packet, ok := h.packetHistory[i]
				if !ok {
					return 0, ErrMapAccess
				}
				expectedEntropy.Substract(i, packet.EntropyBit)
			}
		}
	}
	return expectedEntropy, nil
}

func (h *sentPacketHandler) ReceivedAck(ackFrame *frames.AckFrame) error {
	if ackFrame.LargestObserved > h.lastSentPacketNumber {
		return errAckForUnsentPacket
	}

	if ackFrame.LargestObserved <= h.LargestObserved { // duplicate or out-of-order AckFrame
		return ErrDuplicateOrOutOfOrderAck
	}

	expectedEntropy, err := h.calculateExpectedEntropy(ackFrame)
	if err != nil {
		return err
	}

	if byte(expectedEntropy) != ackFrame.Entropy {
		return ErrEntropy
	}

	// Entropy ok. Now actually process the ACK packet
	h.LargestObserved = ackFrame.LargestObserved
	highestInOrderAckedPacketNumber := ackFrame.GetHighestInOrderPacketNumber()

	// ACK all packets below the highestInOrderAckedPacketNumber
	for i := h.highestInOrderAckedPacketNumber; i <= highestInOrderAckedPacketNumber; i++ {
		h.ackPacket(i)
	}

	if ackFrame.HasNACK() {
		nackRangeIndex := 0
		nackRange := ackFrame.NackRanges[nackRangeIndex]
		for i := ackFrame.LargestObserved; i > ackFrame.GetHighestInOrderPacketNumber(); i-- {
			if i < nackRange.FirstPacketNumber {
				nackRangeIndex++
				if nackRangeIndex < len(ackFrame.NackRanges) {
					nackRange = ackFrame.NackRanges[nackRangeIndex]
				}
			}
			if i >= nackRange.FirstPacketNumber && i <= nackRange.LastPacketNumber {
				h.nackPacket(i)
			} else {
				h.ackPacket(i)
			}
		}
	}

	h.highestInOrderAckedPacketNumber = highestInOrderAckedPacketNumber

	return nil
}

func (h *sentPacketHandler) DequeuePacketForRetransmission() (packet *Packet) {
	if len(h.retransmissionQueue) == 0 {
		return nil
	}
	packet = h.retransmissionQueue[0]
	h.retransmissionQueue = h.retransmissionQueue[1:]
	return packet
}
