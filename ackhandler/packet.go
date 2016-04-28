package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// A Packet is a packet
type Packet struct {
	PacketNumber protocol.PacketNumber
	Frames       []frames.Frame
	EntropyBit   bool
	Entropy      EntropyAccumulator

	MissingReports uint8
	Retransmitted  bool // has this Packet ever been retransmitted

	sendTime time.Time
}

func (p *Packet) GetStreamFramesForRetransmission() []*frames.StreamFrame {
	streamFrames := make([]*frames.StreamFrame, 0)
	for _, frame := range p.Frames {
		if streamFrame, isStreamFrame := frame.(*frames.StreamFrame); isStreamFrame {
			streamFrames = append(streamFrames, streamFrame)
		}
	}
	return streamFrames
}

func (p *Packet) GetControlFramesForRetransmission() []frames.Frame {
	controlFrames := make([]frames.Frame, 0)
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
