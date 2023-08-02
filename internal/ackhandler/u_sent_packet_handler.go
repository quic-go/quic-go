package ackhandler

import "github.com/quic-go/quic-go/internal/protocol"

type uSentPacketHandler struct {
	*sentPacketHandler

	initialPacketNumberLength protocol.PacketNumberLen // [UQUIC]
}

func (h *uSentPacketHandler) PeekPacketNumber(encLevel protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	pnSpace := h.getPacketNumberSpace(encLevel)
	pn := pnSpace.pns.Peek()
	// See section 17.1 of RFC 9000.

	// [UQUIC] Otherwise it kinda breaks PN length mimicry.
	if encLevel == protocol.EncryptionInitial && h.initialPacketNumberLength != 0 {
		return pn, h.initialPacketNumberLength
	}
	// [/UQUIC]

	return pn, protocol.GetPacketNumberLengthForHeader(pn, pnSpace.largestAcked)
}

// [UQUIC]
func SetInitialPacketNumberLength(h SentPacketHandler, pnLen protocol.PacketNumberLen) {
	if sph, ok := h.(*uSentPacketHandler); ok {
		sph.initialPacketNumberLength = pnLen
	}
}
