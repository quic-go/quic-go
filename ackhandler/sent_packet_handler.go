package ackhandler

import (
	"errors"
	"time"

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

	// TODO: Move into separate class as in chromium
	packetHistory map[protocol.PacketNumber]*Packet

	retransmissionQueue []*Packet // ToDo: use better data structure
	stopWaitingManager  StopWaitingManager

	bytesInFlight uint64
}

// NewSentPacketHandler creates a new sentPacketHandler
func NewSentPacketHandler(stopWaitingManager StopWaitingManager) SentPacketHandler {
	return &sentPacketHandler{
		packetHistory:      make(map[protocol.PacketNumber]*Packet),
		stopWaitingManager: stopWaitingManager,
	}
}

func (h *sentPacketHandler) ackPacket(packetNumber protocol.PacketNumber) {
	if packet, ok := h.packetHistory[packetNumber]; ok && !packet.Retransmitted {
		h.bytesInFlight -= packet.Length
	}
	delete(h.packetHistory, packetNumber)

	// TODO: add tests
	h.stopWaitingManager.ReceivedAckForPacketNumber(packetNumber)
}

func (h *sentPacketHandler) nackPacket(packetNumber protocol.PacketNumber) error {
	packet, ok := h.packetHistory[packetNumber]
	if !ok {
		return ErrMapAccess
	}

	// if the packet has already been retransmit, do nothing
	// we're probably only receiving another NACK for this packet because the retransmission has not yet arrived at the client
	if packet.Retransmitted {
		return nil
	}

	packet.MissingReports++

	if packet.MissingReports > retransmissionThreshold {
		h.queuePacketForRetransmission(packet)
	}
	return nil
}

func (h *sentPacketHandler) queuePacketForRetransmission(packet *Packet) {
	h.bytesInFlight -= packet.Length
	h.retransmissionQueue = append(h.retransmissionQueue, packet)
	packet.Retransmitted = true
}

func (h *sentPacketHandler) SentPacket(packet *Packet) error {
	_, ok := h.packetHistory[packet.PacketNumber]
	if ok {
		return errors.New("Packet number already exists in Packet History")
	}
	if h.lastSentPacketNumber+1 != packet.PacketNumber {
		return errors.New("Packet number must be increased by exactly 1")
	}
	packet.sendTime = time.Now()
	if packet.Length == 0 {
		panic("SentPacketHandler: packet cannot be empty")
	}
	h.bytesInFlight += packet.Length

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
			if nackRange.ContainsPacketNumber(i) {
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

func (h *sentPacketHandler) ReceivedAck(ackFrame *frames.AckFrame) (time.Duration, error) {
	if ackFrame.LargestObserved > h.lastSentPacketNumber {
		return 0, errAckForUnsentPacket
	}

	if ackFrame.LargestObserved <= h.LargestObserved { // duplicate or out-of-order AckFrame
		return 0, ErrDuplicateOrOutOfOrderAck
	}

	expectedEntropy, err := h.calculateExpectedEntropy(ackFrame)
	if err != nil {
		return 0, err
	}

	if byte(expectedEntropy) != ackFrame.Entropy {
		return 0, ErrEntropy
	}

	// Entropy ok. Now actually process the ACK packet
	h.LargestObserved = ackFrame.LargestObserved
	highestInOrderAckedPacketNumber := ackFrame.GetHighestInOrderPacketNumber()

	// Calculate the RTT
	timeDelta := time.Now().Sub(h.packetHistory[h.LargestObserved].sendTime)

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
			if nackRange.ContainsPacketNumber(i) {
				h.nackPacket(i)
			} else {
				h.ackPacket(i)
			}
		}
	}

	h.highestInOrderAckedPacketNumber = highestInOrderAckedPacketNumber

	return timeDelta, nil
}

func (h *sentPacketHandler) DequeuePacketForRetransmission() (packet *Packet) {
	if len(h.retransmissionQueue) == 0 {
		return nil
	}
	packet = h.retransmissionQueue[0]
	h.retransmissionQueue = h.retransmissionQueue[1:]
	return packet
}

func (h *sentPacketHandler) BytesInFlight() uint64 {
	return h.bytesInFlight
}
