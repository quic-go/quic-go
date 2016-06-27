package ackhandlernew

import (
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

// ErrDuplicatePacket occurres when a duplicate packet is received
var ErrDuplicatePacket = errors.New("ReceivedPacketHandler: Duplicate Packet")

var (
	errInvalidPacketNumber               = errors.New("ReceivedPacketHandler: Invalid packet number")
	errTooManyOutstandingReceivedPackets = qerr.Error(qerr.TooManyOutstandingReceivedPackets, "")
)

type receivedPacketHandler struct {
	highestInOrderObserved protocol.PacketNumber
	largestObserved        protocol.PacketNumber
	currentAckFrame        *frames.AckFrameNew
	stateChanged           bool // has an ACK for this state already been sent? Will be set to false every time a new packet arrives, and to false every time an ACK is sent

	packetHistory         *receivedPacketHistory
	receivedTimes         map[protocol.PacketNumber]time.Time
	lowestInReceivedTimes protocol.PacketNumber
}

// NewReceivedPacketHandler creates a new receivedPacketHandler
func NewReceivedPacketHandler() ReceivedPacketHandler {
	return &receivedPacketHandler{
		receivedTimes: make(map[protocol.PacketNumber]time.Time),
		packetHistory: newReceivedPacketHistory(),
	}
}

func (h *receivedPacketHandler) ReceivedPacket(packetNumber protocol.PacketNumber) error {
	if packetNumber == 0 {
		return errInvalidPacketNumber
	}
	_, ok := h.receivedTimes[packetNumber]
	if packetNumber <= h.highestInOrderObserved || ok {
		return ErrDuplicatePacket
	}

	h.packetHistory.ReceivedPacket(packetNumber)

	h.stateChanged = true
	h.currentAckFrame = nil

	if packetNumber > h.largestObserved {
		h.largestObserved = packetNumber
	}

	if packetNumber == h.highestInOrderObserved+1 {
		h.highestInOrderObserved = packetNumber
	}

	h.receivedTimes[packetNumber] = time.Now()

	h.garbageCollect()

	if uint32(len(h.receivedTimes)) > protocol.MaxTrackedReceivedPackets {
		return errTooManyOutstandingReceivedPackets
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

	h.packetHistory.DeleteBelow(f.LeastUnacked)

	h.garbageCollect()

	return nil
}

func (h *receivedPacketHandler) GetAckFrame(dequeue bool) (*frames.AckFrameNew, error) {
	if !h.stateChanged {
		return nil, nil
	}

	if dequeue {
		h.stateChanged = false
	}

	if h.currentAckFrame != nil {
		return h.currentAckFrame, nil
	}

	packetReceivedTime, ok := h.receivedTimes[h.largestObserved]
	if !ok {
		return nil, ErrMapAccess
	}

	ackRanges := h.packetHistory.GetAckRanges()
	h.currentAckFrame = &frames.AckFrameNew{
		LargestAcked:       h.largestObserved,
		LowestAcked:        ackRanges[len(ackRanges)-1].FirstPacketNumber,
		PacketReceivedTime: packetReceivedTime,
	}

	if len(ackRanges) > 1 {
		h.currentAckFrame.AckRanges = ackRanges
	}

	return h.currentAckFrame, nil
}

func (h *receivedPacketHandler) garbageCollect() {
	for i := h.lowestInReceivedTimes; i < h.highestInOrderObserved; i++ {
		delete(h.receivedTimes, i)
	}
	h.lowestInReceivedTimes = h.highestInOrderObserved
}
