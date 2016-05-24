package ackhandler

import (
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

var (
	// ErrDuplicateOrOutOfOrderAck occurs when a duplicate or an out-of-order ACK is received
	ErrDuplicateOrOutOfOrderAck = errors.New("SentPacketHandler: Duplicate or out-of-order ACK")
	// ErrEntropy occurs when an ACK with incorrect entropy is received
	ErrEntropy = qerr.Error(qerr.InvalidAckData, "wrong entropy")
	// ErrMapAccess occurs when a NACK contains invalid NACK ranges
	ErrMapAccess = qerr.Error(qerr.InvalidAckData, "Packet does not exist in PacketHistory")
	// ErrTooManyTrackedSentPackets occurs when the sentPacketHandler has to keep track of too many packets
	ErrTooManyTrackedSentPackets = errors.New("To many outstanding not-acked and not retransmitted packets.")
	errAckForUnsentPacket        = qerr.Error(qerr.InvalidAckData, "Received ACK for an unsent package")
)

var (
	errDuplicatePacketNumber      = errors.New("Packet number already exists in Packet History")
	errWrongPacketNumberIncrement = errors.New("Packet number must be increased by exactly 1")
)

type sentPacketHandler struct {
	lastSentPacketNumber            protocol.PacketNumber
	lastSentPacketEntropy           EntropyAccumulator
	highestInOrderAckedPacketNumber protocol.PacketNumber
	LargestObserved                 protocol.PacketNumber
	LargestObservedEntropy          EntropyAccumulator

	// TODO: Move into separate class as in chromium
	packetHistory map[protocol.PacketNumber]*Packet

	retransmissionQueue []*Packet
	stopWaitingManager  StopWaitingManager

	bytesInFlight protocol.ByteCount

	rttStats   *congestion.RTTStats
	congestion congestion.SendAlgorithm
}

// NewSentPacketHandler creates a new sentPacketHandler
func NewSentPacketHandler(stopWaitingManager StopWaitingManager) SentPacketHandler {
	rttStats := &congestion.RTTStats{}

	congestion := congestion.NewCubicSender(
		congestion.DefaultClock{},
		rttStats,
		false, /* don't use reno since chromium doesn't (why?) */
		protocol.InitialCongestionWindow,
		protocol.DefaultMaxCongestionWindow,
	)

	return &sentPacketHandler{
		packetHistory:      make(map[protocol.PacketNumber]*Packet),
		stopWaitingManager: stopWaitingManager,
		rttStats:           rttStats,
		congestion:         congestion,
	}
}

func (h *sentPacketHandler) ackPacket(packetNumber protocol.PacketNumber) *Packet {
	packet, ok := h.packetHistory[packetNumber]
	if ok && !packet.Retransmitted {
		h.bytesInFlight -= packet.Length
	}
	delete(h.packetHistory, packetNumber)

	h.stopWaitingManager.ReceivedAckForPacketNumber(packetNumber)

	return packet
}

func (h *sentPacketHandler) nackPacket(packetNumber protocol.PacketNumber) (*Packet, error) {
	packet, ok := h.packetHistory[packetNumber]
	if !ok {
		return nil, ErrMapAccess
	}

	// If the packet has already been retransmitted, do nothing.
	// We're probably only receiving another NACK for this packet because the
	// retransmission has not yet arrived at the client.
	if packet.Retransmitted {
		return nil, nil
	}

	packet.MissingReports++

	if packet.MissingReports > protocol.RetransmissionThreshold {
		h.queuePacketForRetransmission(packet)
		return packet, nil
	}
	return nil, nil
}

func (h *sentPacketHandler) queuePacketForRetransmission(packet *Packet) {
	h.bytesInFlight -= packet.Length
	h.retransmissionQueue = append(h.retransmissionQueue, packet)
	packet.Retransmitted = true

	// TODO: delete from packetHistory once we drop support for version smaller than QUIC 33
}

func (h *sentPacketHandler) SentPacket(packet *Packet) error {
	_, ok := h.packetHistory[packet.PacketNumber]
	if ok {
		return errDuplicatePacketNumber
	}
	if h.lastSentPacketNumber+1 != packet.PacketNumber {
		return errWrongPacketNumberIncrement
	}
	now := time.Now()
	packet.sendTime = now
	packet.rtoTime = now.Add(h.getRTO())
	if packet.Length == 0 {
		return errors.New("SentPacketHandler: packet cannot be empty")
	}
	h.bytesInFlight += packet.Length

	h.lastSentPacketEntropy.Add(packet.PacketNumber, packet.EntropyBit)
	packet.Entropy = h.lastSentPacketEntropy
	h.lastSentPacketNumber = packet.PacketNumber
	h.packetHistory[packet.PacketNumber] = packet

	h.congestion.OnPacketSent(
		time.Now(),
		h.BytesInFlight(),
		packet.PacketNumber,
		packet.Length,
		true, /* TODO: is retransmittable */
	)

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
				expectedEntropy.Subtract(i, packet.EntropyBit)
			}
		}
	}
	return expectedEntropy, nil
}

// TODO: Simplify return types
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

	// Update the RTT
	timeDelta := time.Now().Sub(h.packetHistory[h.LargestObserved].sendTime)
	// TODO: Don't always update RTT
	h.rttStats.UpdateRTT(timeDelta, ackFrame.DelayTime, time.Now())
	utils.Debugf("\tEstimated RTT: %dms", h.rttStats.SmoothedRTT()/time.Millisecond)

	var ackedPackets congestion.PacketVector
	var lostPackets congestion.PacketVector

	// ACK all packets below the highestInOrderAckedPacketNumber
	for i := h.highestInOrderAckedPacketNumber; i <= highestInOrderAckedPacketNumber; i++ {
		p := h.ackPacket(i)
		if p != nil {
			ackedPackets = append(ackedPackets, congestion.PacketInfo{Number: p.PacketNumber, Length: p.Length})
		}
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
				p, err := h.nackPacket(i)
				if err != nil {
					return err
				}
				if p != nil {
					lostPackets = append(lostPackets, congestion.PacketInfo{Number: p.PacketNumber, Length: p.Length})
				}
			} else {
				p := h.ackPacket(i)
				if p != nil {
					ackedPackets = append(ackedPackets, congestion.PacketInfo{Number: p.PacketNumber, Length: p.Length})
				}
			}
		}
	}

	h.highestInOrderAckedPacketNumber = highestInOrderAckedPacketNumber

	h.congestion.OnCongestionEvent(
		true, /* TODO: rtt updated */
		h.BytesInFlight(),
		ackedPackets,
		lostPackets,
	)

	return nil
}

func (h *sentPacketHandler) HasPacketForRetransmission() bool {
	h.queuePacketsRTO()

	if len(h.retransmissionQueue) > 0 {
		return true
	}
	return false
}

func (h *sentPacketHandler) DequeuePacketForRetransmission() (packet *Packet) {
	if !h.HasPacketForRetransmission() {
		return nil
	}

	queueLen := len(h.retransmissionQueue)
	// packets are usually NACKed in descending order. So use the slice as a stack
	packet = h.retransmissionQueue[queueLen-1]
	h.retransmissionQueue = h.retransmissionQueue[:queueLen-1]
	return packet
}

func (h *sentPacketHandler) BytesInFlight() protocol.ByteCount {
	return h.bytesInFlight
}

func (h *sentPacketHandler) GetLargestObserved() protocol.PacketNumber {
	return h.LargestObserved
}

func (h *sentPacketHandler) CongestionAllowsSending() bool {
	return h.BytesInFlight() <= h.congestion.GetCongestionWindow()
}

func (h *sentPacketHandler) CheckForError() error {
	length := len(h.retransmissionQueue) + len(h.packetHistory)
	if uint32(length) > protocol.MaxTrackedSentPackets {
		return ErrTooManyTrackedSentPackets
	}
	return nil
}

func (h *sentPacketHandler) getRTO() time.Duration {
	rto := h.congestion.RetransmissionDelay()
	if rto == 0 {
		rto = protocol.DefaultRetransmissionTime
	}
	return utils.MaxDuration(rto, protocol.MinRetransmissionTime)
}

func (h *sentPacketHandler) queuePacketsRTO() {
	queued := false
	now := time.Now()
	for _, p := range h.packetHistory {
		if p == nil || p.Retransmitted || p.rtoTime.After(now) {
			continue
		}
		h.queuePacketForRetransmission(p)
		queued = true
	}
	if queued {
		h.congestion.OnRetransmissionTimeout(true)
	}
}

func (h *sentPacketHandler) TimeOfFirstRTO() time.Time {
	var min time.Time
	for _, p := range h.packetHistory {
		if p == nil || p.Retransmitted {
			continue
		}
		if min.IsZero() || min.After(p.rtoTime) {
			min = p.rtoTime
		}
	}
	return min
}
