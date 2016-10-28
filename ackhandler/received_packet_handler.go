package ackhandler

import (
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

var (
	// ErrDuplicatePacket occurres when a duplicate packet is received
	ErrDuplicatePacket = errors.New("ReceivedPacketHandler: Duplicate Packet")
	// ErrPacketSmallerThanLastStopWaiting occurs when a packet arrives with a packet number smaller than the largest LeastUnacked of a StopWaitingFrame. If this error occurs, the packet should be ignored
	ErrPacketSmallerThanLastStopWaiting = errors.New("ReceivedPacketHandler: Packet number smaller than highest StopWaiting")
)

var errInvalidPacketNumber = errors.New("ReceivedPacketHandler: Invalid packet number")

type receivedPacketHandler struct {
	largestObserved    protocol.PacketNumber
	ignorePacketsBelow protocol.PacketNumber
	currentAckFrame    *frames.AckFrame
	stateChanged       bool // has an ACK for this state already been sent? Will be set to false every time a new packet arrives, and to false every time an ACK is sent

	packetHistory *receivedPacketHistory

	largestObservedReceivedTime time.Time
}

// NewReceivedPacketHandler creates a new receivedPacketHandler
func NewReceivedPacketHandler() ReceivedPacketHandler {
	return &receivedPacketHandler{
		packetHistory: newReceivedPacketHistory(),
	}
}

func (h *receivedPacketHandler) ReceivedPacket(packetNumber protocol.PacketNumber) error {
	if packetNumber == 0 {
		return errInvalidPacketNumber
	}

	// if the packet number is smaller than the largest LeastUnacked value of a StopWaiting we received, we cannot detect if this packet has a duplicate number
	// the packet has to be ignored anyway
	if packetNumber <= h.ignorePacketsBelow {
		return ErrPacketSmallerThanLastStopWaiting
	}

	if h.packetHistory.IsDuplicate(packetNumber) {
		return ErrDuplicatePacket
	}

	err := h.packetHistory.ReceivedPacket(packetNumber)
	if err != nil {
		return err
	}

	h.stateChanged = true
	h.currentAckFrame = nil

	if packetNumber > h.largestObserved {
		h.largestObserved = packetNumber
		h.largestObservedReceivedTime = time.Now()
	}

	return nil
}

func (h *receivedPacketHandler) ReceivedStopWaiting(f *frames.StopWaitingFrame) error {
	// ignore if StopWaiting is unneeded, because we already received a StopWaiting with a higher LeastUnacked
	if h.ignorePacketsBelow >= f.LeastUnacked {
		return nil
	}

	h.ignorePacketsBelow = f.LeastUnacked - 1

	h.packetHistory.DeleteBelow(f.LeastUnacked)
	return nil
}

func (h *receivedPacketHandler) GetAckFrame(dequeue bool) (*frames.AckFrame, error) {
	if !h.stateChanged {
		return nil, nil
	}

	if dequeue {
		h.stateChanged = false
	}

	if h.currentAckFrame != nil {
		return h.currentAckFrame, nil
	}

	ackRanges := h.packetHistory.GetAckRanges()
	h.currentAckFrame = &frames.AckFrame{
		LargestAcked:       h.largestObserved,
		LowestAcked:        ackRanges[len(ackRanges)-1].FirstPacketNumber,
		PacketReceivedTime: h.largestObservedReceivedTime,
	}

	if len(ackRanges) > 1 {
		h.currentAckFrame.AckRanges = ackRanges
	}

	return h.currentAckFrame, nil
}
