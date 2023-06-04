package ackhandler

import (
	"fmt"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
)

type sentPacketHistory struct {
	packets []*Packet

	numOutstanding int

	highestPacketNumber protocol.PacketNumber
}

func newSentPacketHistory() *sentPacketHistory {
	return &sentPacketHistory{
		packets:             make([]*Packet, 0, 32),
		highestPacketNumber: protocol.InvalidPacketNumber,
	}
}

func (h *sentPacketHistory) SentNonAckElicitingPacket(pn protocol.PacketNumber, encLevel protocol.EncryptionLevel, t time.Time) {
	h.maybeAddSkippedPacketsBefore(pn, encLevel, t)
	h.highestPacketNumber = pn
	if len(h.packets) > 0 {
		h.packets = append(h.packets, nil)
	}
}

func (h *sentPacketHistory) SentAckElicitingPacket(p *Packet) {
	h.maybeAddSkippedPacketsBefore(p.PacketNumber, p.EncryptionLevel, p.SendTime)
	h.packets = append(h.packets, p)
	if p.outstanding() {
		h.numOutstanding++
	}
	h.highestPacketNumber = p.PacketNumber
}

func (h *sentPacketHistory) maybeAddSkippedPacketsBefore(pn protocol.PacketNumber, encLevel protocol.EncryptionLevel, t time.Time) {
	if pn <= h.highestPacketNumber {
		panic("non-sequential packet number use")
	}
	var start protocol.PacketNumber
	if h.highestPacketNumber != protocol.InvalidPacketNumber {
		start = h.highestPacketNumber + 1
	}
	for p := start; p < pn; p++ {
		h.packets = append(h.packets, &Packet{
			PacketNumber:    p,
			EncryptionLevel: encLevel,
			SendTime:        t,
			skippedPacket:   true,
		})
	}
}

// Iterate iterates through all packets.
func (h *sentPacketHistory) Iterate(cb func(*Packet) (cont bool, err error)) error {
	for _, p := range h.packets {
		if p == nil {
			continue
		}
		cont, err := cb(p)
		if err != nil {
			return err
		}
		if !cont {
			return nil
		}
	}
	return nil
}

// FirstOutstanding returns the first outstanding packet.
func (h *sentPacketHistory) FirstOutstanding() *Packet {
	if !h.HasOutstandingPackets() {
		return nil
	}
	for _, p := range h.packets {
		if p != nil && p.outstanding() {
			return p
		}
	}
	return nil
}

func (h *sentPacketHistory) Len() int {
	return len(h.packets)
}

func (h *sentPacketHistory) Remove(pn protocol.PacketNumber) error {
	idx, ok := h.getIndex(pn)
	if !ok {
		return fmt.Errorf("packet %d not found in sent packet history", pn)
	}
	p := h.packets[idx]
	if p.outstanding() {
		h.numOutstanding--
		if h.numOutstanding < 0 {
			panic("negative number of outstanding packets")
		}
	}
	h.packets[idx] = nil
	// clean up all skipped packets directly before this packet number
	for idx > 0 {
		idx--
		p := h.packets[idx]
		if p == nil || !p.skippedPacket {
			break
		}
		h.packets[idx] = nil
	}
	if idx == 0 {
		h.cleanupStart()
	}
	if len(h.packets) > 0 && h.packets[0] == nil {
		panic("remove failed")
	}
	return nil
}

// getIndex gets the index of packet p in the packets slice.
func (h *sentPacketHistory) getIndex(p protocol.PacketNumber) (int, bool) {
	if len(h.packets) == 0 {
		return 0, false
	}
	first := h.packets[0].PacketNumber
	if p < first {
		return 0, false
	}
	index := int(p - first)
	if index > len(h.packets)-1 {
		return 0, false
	}
	return index, true
}

func (h *sentPacketHistory) HasOutstandingPackets() bool {
	return h.numOutstanding > 0
}

// delete all nil entries at the beginning of the packets slice
func (h *sentPacketHistory) cleanupStart() {
	for i, p := range h.packets {
		if p != nil {
			h.packets = h.packets[i:]
			return
		}
	}
	h.packets = h.packets[:0]
}

func (h *sentPacketHistory) LowestPacketNumber() protocol.PacketNumber {
	if len(h.packets) == 0 {
		return protocol.InvalidPacketNumber
	}
	return h.packets[0].PacketNumber
}

func (h *sentPacketHistory) DeclareLost(pn protocol.PacketNumber) {
	idx, ok := h.getIndex(pn)
	if !ok {
		return
	}
	p := h.packets[idx]
	if p.outstanding() {
		h.numOutstanding--
		if h.numOutstanding < 0 {
			panic("negative number of outstanding packets")
		}
	}
	h.packets[idx] = nil
	if idx == 0 {
		h.cleanupStart()
	}
}
