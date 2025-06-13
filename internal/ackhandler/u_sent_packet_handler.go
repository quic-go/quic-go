package ackhandler

import "github.com/Noooste/uquic-go/internal/protocol"

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

	return pn, protocol.PacketNumberLengthForHeader(pn, pnSpace.largestAcked)
}

// [UQUIC]
func SetInitialPacketNumberLength(h SentPacketHandler, pnLen protocol.PacketNumberLen) {
	if sph, ok := h.(*uSentPacketHandler); ok {
		sph.initialPacketNumberLength = pnLen
	}
}

// func (h *uSentPacketHandler) OnLossDetectionTimeout() error {
// 	defer h.setLossDetectionTimer()
// 	earliestLossTime, encLevel := h.getLossTimeAndSpace()
// 	if !earliestLossTime.IsZero() {
// 		if h.logger.Debug() {
// 			h.logger.Debugf("Loss detection alarm fired in loss timer mode. Loss time: %s", earliestLossTime)
// 		}
// 		if h.tracer != nil && h.tracer.LossTimerExpired != nil {
// 			h.tracer.LossTimerExpired(logging.TimerTypeACK, encLevel)
// 		}
// 		// Early retransmit or time loss detection
// 		return h.detectLostPackets(time.Now(), encLevel)
// 	}

// 	// PTO
// 	// When all outstanding are acknowledged, the alarm is canceled in
// 	// setLossDetectionTimer. This doesn't reset the timer in the session though.
// 	// When OnAlarm is called, we therefore need to make sure that there are
// 	// actually packets outstanding.
// 	if h.bytesInFlight == 0 && !h.peerCompletedAddressValidation {
// 		h.ptoCount++
// 		h.numProbesToSend++
// 		if h.initialPackets != nil {
// 			h.ptoMode = SendPTOInitial
// 		} else if h.handshakePackets != nil {
// 			h.ptoMode = SendPTOHandshake
// 		} else {
// 			return errors.New("sentPacketHandler BUG: PTO fired, but bytes_in_flight is 0 and Initial and Handshake already dropped")
// 		}
// 		return nil
// 	}

// 	_, encLevel, ok := h.getPTOTimeAndSpace()
// 	if !ok {
// 		return nil
// 	}
// 	if ps := h.getPacketNumberSpace(encLevel); !ps.history.HasOutstandingPackets() && !h.peerCompletedAddressValidation {
// 		return nil
// 	}
// 	h.ptoCount++
// 	if h.logger.Debug() {
// 		h.logger.Debugf("Loss detection alarm for %s fired in PTO mode. PTO count: %d", encLevel, h.ptoCount)
// 	}
// 	if h.tracer != nil {
// 		if h.tracer.LossTimerExpired != nil {
// 			h.tracer.LossTimerExpired(logging.TimerTypePTO, encLevel)
// 		}
// 		if h.tracer.UpdatedPTOCount != nil {
// 			h.tracer.UpdatedPTOCount(h.ptoCount)
// 		}
// 	}
// 	h.numProbesToSend += 2
// 	//nolint:exhaustive // We never arm a PTO timer for 0-RTT packets.
// 	switch encLevel {
// 	case protocol.EncryptionInitial:
// 		// h.ptoMode = SendPTOInitial // or quic-go will send fallback initial packets with different FRAME architecture
// 	case protocol.EncryptionHandshake:
// 		h.ptoMode = SendPTOHandshake
// 	case protocol.Encryption1RTT:
// 		// skip a packet number in order to elicit an immediate ACK
// 		pn := h.PopPacketNumber(protocol.Encryption1RTT)
// 		h.getPacketNumberSpace(protocol.Encryption1RTT).history.SkippedPacket(pn)
// 		h.ptoMode = SendPTOAppData
// 	default:
// 		return fmt.Errorf("PTO timer in unexpected encryption level: %s", encLevel)
// 	}
// 	return nil
// }
