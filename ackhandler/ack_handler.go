package ackhandler

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// The AckHandler handles ACKs
type AckHandler struct {
	LargestObserved protocol.PacketNumber
	Observed        map[protocol.PacketNumber]bool
}

// NewAckHandler creates a new AckHandler
func NewAckHandler() (*AckHandler, error) {
	ackHandler := &AckHandler{
		Observed: make(map[protocol.PacketNumber]bool),
	}
	return ackHandler, nil
}

// HandlePacket handles a packet
func (h *AckHandler) HandlePacket(packetNumber protocol.PacketNumber) {
	if packetNumber > h.LargestObserved {
		h.LargestObserved = packetNumber
	}
	h.Observed[packetNumber] = true
}

// GetNackRanges gets all the NACK ranges
func (h *AckHandler) GetNackRanges() []*frames.NackRange {
	// ToDo: improve performance
	var ranges []*frames.NackRange
	inRange := false
	// ToDo: fix types
	for i := 0; i < int(h.LargestObserved); i++ {
		packetNumber := protocol.PacketNumber(i)
		_, ok := h.Observed[packetNumber]
		if !ok {
			if !inRange {
				r := &frames.NackRange{
					FirstPacketNumber: packetNumber,
					Length:            1,
				}
				ranges = append(ranges, r)
				inRange = true
			} else {
				ranges[len(ranges)-1].Length++
			}
		} else {
			inRange = false
		}
	}
	return ranges
}
