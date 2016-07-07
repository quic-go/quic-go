package ackhandlernew

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
	ErrTooManyTrackedSentPackets = errors.New("Too many outstanding non-acked and non-retransmitted packets")
	errAckForUnsentPacket        = qerr.Error(qerr.InvalidAckData, "Received ACK for an unsent package")
)

var errDuplicatePacketNumber = errors.New("Packet number already exists in Packet History")

type sentPacketHandler struct {
	lastSentPacketNumber protocol.PacketNumber
	lastSentPacketTime   time.Time
	LargestInOrderAcked  protocol.PacketNumber
	LargestAcked         protocol.PacketNumber

	largestReceivedPacketWithAck protocol.PacketNumber

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

	if h.LargestInOrderAcked == packetNumber-1 {
		h.LargestInOrderAcked++
	}

	delete(h.packetHistory, packetNumber)

	h.stopWaitingManager.ReceivedAckForPacketNumber(packetNumber)

	return packet
}

func (h *sentPacketHandler) nackPacket(packetNumber protocol.PacketNumber) (*Packet, error) {
	packet, ok := h.packetHistory[packetNumber]
	// This means that the packet has already been retransmitted, do nothing.
	// We're probably only receiving another NACK for this packet because the
	// retransmission has not yet arrived at the client.
	if !ok {
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

	// increase the LargestInOrderAcked, if this is the lowest packet that hasn't been acked yet
	if packet.PacketNumber == h.LargestInOrderAcked+1 {
		for i := packet.PacketNumber + 1; i < h.LargestAcked; i++ {
			_, ok := h.packetHistory[protocol.PacketNumber(i)]
			if !ok {
				h.LargestInOrderAcked = i
			} else {
				break
			}
		}
	}
}

func (h *sentPacketHandler) SentPacket(packet *Packet) error {
	_, ok := h.packetHistory[packet.PacketNumber]
	if ok {
		return errDuplicatePacketNumber
	}

	now := time.Now()
	h.lastSentPacketTime = now
	packet.sendTime = now
	if packet.Length == 0 {
		return errors.New("SentPacketHandler: packet cannot be empty")
	}
	h.bytesInFlight += packet.Length

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

// TODO: Simplify return types
func (h *sentPacketHandler) ReceivedAck(ackFrame *frames.AckFrameNew, withPacketNumber protocol.PacketNumber) error {
	if ackFrame.LargestAcked > h.lastSentPacketNumber {
		return errAckForUnsentPacket
	}

	// duplicate or out-of-order ACK
	if withPacketNumber <= h.largestReceivedPacketWithAck {
		return ErrDuplicateOrOutOfOrderAck
	}

	h.largestReceivedPacketWithAck = withPacketNumber

	h.LargestAcked = ackFrame.LargestAcked

	// Update the RTT
	timeDelta := time.Now().Sub(h.packetHistory[h.LargestAcked].sendTime)
	// TODO: Don't always update RTT
	h.rttStats.UpdateRTT(timeDelta, ackFrame.DelayTime, time.Now())
	if utils.Debug() {
		utils.Debugf("\tEstimated RTT: %dms", h.rttStats.SmoothedRTT()/time.Millisecond)
	}

	var ackedPackets congestion.PacketVector
	var lostPackets congestion.PacketVector

	// NACK packets below the LowestAcked
	for i := h.LargestInOrderAcked; i < ackFrame.LowestAcked; i++ {
		p, err := h.nackPacket(i)
		if err != nil {
			return err
		}
		if p != nil {
			lostPackets = append(lostPackets, congestion.PacketInfo{Number: p.PacketNumber, Length: p.Length})
		}
	}

	ackRangeIndex := 0
	for i := ackFrame.LowestAcked; i <= ackFrame.LargestAcked; i++ {
		if ackFrame.HasMissingRanges() {
			ackRange := ackFrame.AckRanges[len(ackFrame.AckRanges)-1-ackRangeIndex]

			if i > ackRange.LastPacketNumber && ackRangeIndex < len(ackFrame.AckRanges)-1 {
				ackRangeIndex++
				ackRange = ackFrame.AckRanges[len(ackFrame.AckRanges)-1-ackRangeIndex]
			}

			if i >= ackRange.FirstPacketNumber { // packet i contained in ACK range
				p := h.ackPacket(i)
				if p != nil {
					ackedPackets = append(ackedPackets, congestion.PacketInfo{Number: p.PacketNumber, Length: p.Length})
				}
			} else {
				p, err := h.nackPacket(i)
				if err != nil {
					return err
				}
				if p != nil {
					lostPackets = append(lostPackets, congestion.PacketInfo{Number: p.PacketNumber, Length: p.Length})
				}
			}
		} else {
			p := h.ackPacket(i)
			if p != nil {
				ackedPackets = append(ackedPackets, congestion.PacketInfo{Number: p.PacketNumber, Length: p.Length})
			}
		}
	}

	h.congestion.OnCongestionEvent(
		true, /* TODO: rtt updated */
		h.BytesInFlight(),
		ackedPackets,
		lostPackets,
	)

	return nil
}

// ProbablyHasPacketForRetransmission returns if there is a packet queued for retransmission
// There is one case where it gets the answer wrong:
// if a packet has already been queued for retransmission, but a belated ACK is received for this packet, this function will return true, although the packet will not be returend for retransmission by DequeuePacketForRetransmission()
func (h *sentPacketHandler) ProbablyHasPacketForRetransmission() bool {
	h.maybeQueuePacketsRTO()

	return len(h.retransmissionQueue) > 0
}

func (h *sentPacketHandler) DequeuePacketForRetransmission() (packet *Packet) {
	if !h.ProbablyHasPacketForRetransmission() {
		return nil
	}

	for len(h.retransmissionQueue) > 0 {
		queueLen := len(h.retransmissionQueue)
		// packets are usually NACKed in descending order. So use the slice as a stack
		packet = h.retransmissionQueue[queueLen-1]
		h.retransmissionQueue = h.retransmissionQueue[:queueLen-1]

		// this happens if a belated ACK arrives for this packet
		// no need to retransmit it
		_, ok := h.packetHistory[packet.PacketNumber]
		if !ok {
			continue
		}

		delete(h.packetHistory, packet.PacketNumber)
		return packet
	}

	return nil
}

func (h *sentPacketHandler) BytesInFlight() protocol.ByteCount {
	return h.bytesInFlight
}

func (h *sentPacketHandler) GetLargestAcked() protocol.PacketNumber {
	return h.LargestAcked
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

func (h *sentPacketHandler) maybeQueuePacketsRTO() {
	if time.Now().Before(h.TimeOfFirstRTO()) {
		return
	}

	for p := h.LargestInOrderAcked + 1; p <= h.lastSentPacketNumber; p++ {
		packet := h.packetHistory[p]
		if packet != nil && !packet.Retransmitted {
			packetsLost := congestion.PacketVector{congestion.PacketInfo{
				Number: packet.PacketNumber,
				Length: packet.Length,
			}}
			h.congestion.OnCongestionEvent(false, h.BytesInFlight(), nil, packetsLost)
			h.congestion.OnRetransmissionTimeout(true)
			h.queuePacketForRetransmission(packet)
			return
		}
	}
}

func (h *sentPacketHandler) getRTO() time.Duration {
	rto := h.congestion.RetransmissionDelay()
	if rto == 0 {
		rto = protocol.DefaultRetransmissionTime
	}
	return utils.MaxDuration(rto, protocol.MinRetransmissionTime)
}

func (h *sentPacketHandler) TimeOfFirstRTO() time.Time {
	if h.lastSentPacketTime.IsZero() {
		return time.Time{}
	}
	return h.lastSentPacketTime.Add(h.getRTO())
}
