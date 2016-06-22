package ackhandlernew

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// StopWaitingManager manages StopWaitingFrames
type stopWaitingManager struct {
	// sentStopWaitings            map[protocol.PacketNumber]protocol.PacketNumber // map[LeastUnacked]stopWaitingSentWithPacketNumber
	lastNewStopWaitingFirstSentWithPacketNumber protocol.PacketNumber
	maxRetransmittedPacketNumber                protocol.PacketNumber
	currentStopWaitingFrame                     *frames.StopWaitingFrame
	currentStopWaitingFrameSent                 bool
}

// NewStopWaitingManager creates a new StopWaitingManager
func NewStopWaitingManager() StopWaitingManager {
	return &stopWaitingManager{
		currentStopWaitingFrame: nil,
	}
}

// RegisterPacketForRetransmission prepares the StopWaitingFrame, if necessary
func (h *stopWaitingManager) RegisterPacketForRetransmission(packet *Packet) {
	// out-of-order retransmission. A StopWaitingFrame with a higher LeastUnacked was already queued (or sent in the past), no need to send another one again
	if packet.PacketNumber < h.maxRetransmittedPacketNumber {
		return
	}
	if h.currentStopWaitingFrame == nil || h.currentStopWaitingFrame.LeastUnacked <= packet.PacketNumber { // <= because for StopWaitingFrames LeastUnacked = packet.PacketNumber + 1
		h.currentStopWaitingFrame = &frames.StopWaitingFrame{
			LeastUnacked: packet.PacketNumber + 1,
			Entropy:      byte(packet.Entropy),
		}
		h.maxRetransmittedPacketNumber = packet.PacketNumber
		h.currentStopWaitingFrameSent = false
	}
}

// GetStopWaitingFrame gets the StopWaitingFrame that needs to be sent. It returns nil if no StopWaitingFrame needs to be sent
func (h *stopWaitingManager) GetStopWaitingFrame() *frames.StopWaitingFrame {
	return h.currentStopWaitingFrame
}

// SentStopWaitingWithPacket must be called after sending out a StopWaitingFrame with a packet
func (h *stopWaitingManager) SentStopWaitingWithPacket(packetNumber protocol.PacketNumber) {
	if !h.currentStopWaitingFrameSent {
		h.lastNewStopWaitingFirstSentWithPacketNumber = packetNumber
	}
	h.currentStopWaitingFrameSent = true
}

// ReceivedAckForPacketNumber should be called after receiving an ACK
func (h *stopWaitingManager) ReceivedAckForPacketNumber(packetNumber protocol.PacketNumber) {
	if packetNumber >= h.lastNewStopWaitingFirstSentWithPacketNumber {
		h.currentStopWaitingFrame = nil
	}
}
