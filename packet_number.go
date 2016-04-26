package quic

import "github.com/lucas-clemente/quic-go/protocol"

func calculatePacketNumber(packetNumberLength uint8, lastPacketNumber protocol.PacketNumber, wirePacketNumber protocol.PacketNumber) protocol.PacketNumber {
	epochDelta := protocol.PacketNumber(1) << (packetNumberLength * 8)
	epoch := lastPacketNumber & ^(epochDelta - 1)
	prevEpochBegin := epoch - epochDelta
	nextEpochBegin := epoch + epochDelta
	return closestTo(
		lastPacketNumber+1,
		epoch+wirePacketNumber,
		closestTo(lastPacketNumber+1, prevEpochBegin+wirePacketNumber, nextEpochBegin+wirePacketNumber),
	)
}

func closestTo(target, a, b protocol.PacketNumber) protocol.PacketNumber {
	if delta(target, a) < delta(target, b) {
		return a
	}
	return b
}

func delta(a, b protocol.PacketNumber) protocol.PacketNumber {
	if a < b {
		return b - a
	}
	return a - b
}
