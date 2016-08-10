package ackhandlerlegacy

// TODO: move to ackhandler once we remove support for QUIC 33

import (
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// A Packet is a packet
// +gen linkedlist
type Packet struct {
	PacketNumber protocol.PacketNumber
	Frames       []frames.Frame
	EntropyBit   bool
	Entropy      EntropyAccumulator
	Length       protocol.ByteCount

	MissingReports uint8
	// TODO: remove this when dropping support for QUIC 33
	Retransmitted bool // has this Packet ever been retransmitted

	SendTime time.Time
}

// GetStreamFramesForRetransmission gets all the streamframes for retransmission
func (p *Packet) GetStreamFramesForRetransmission() []*frames.StreamFrame {
	var streamFrames []*frames.StreamFrame
	for _, frame := range p.Frames {
		if streamFrame, isStreamFrame := frame.(*frames.StreamFrame); isStreamFrame {
			streamFrames = append(streamFrames, streamFrame)
		}
	}
	return streamFrames
}

// GetControlFramesForRetransmission gets all the control frames for retransmission
func (p *Packet) GetControlFramesForRetransmission() []frames.Frame {
	var controlFrames []frames.Frame
	for _, frame := range p.Frames {
		// omit ACKs
		if _, isStreamFrame := frame.(*frames.StreamFrame); isStreamFrame {
			continue
		}

		_, isAck := frame.(*frames.AckFrame)
		_, isStopWaiting := frame.(*frames.StopWaitingFrame)
		if !isAck && !isStopWaiting {
			controlFrames = append(controlFrames, frame)
		}
	}
	return controlFrames
}
