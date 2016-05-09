package quic

import "github.com/lucas-clemente/quic-go/protocol"

func inferPacketNumber(packetNumberLength protocol.PacketNumberLen, lastPacketNumber protocol.PacketNumber, wirePacketNumber protocol.PacketNumber) protocol.PacketNumber {
	epochDelta := protocol.PacketNumber(1) << (uint8(packetNumberLength) * 8)
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

func getPacketNumberLength(packetNumber protocol.PacketNumber, highestAckedPacketNumber protocol.PacketNumber) protocol.PacketNumberLen {
	diff := uint64(packetNumber - highestAckedPacketNumber)
	if diff < (2 << (uint8(protocol.PacketNumberLen1)*8 - 2)) {
		return protocol.PacketNumberLen1
	}
	if diff < (2 << (uint8(protocol.PacketNumberLen2)*8 - 2)) {
		return protocol.PacketNumberLen2
	}
	if diff < (2 << (uint8(protocol.PacketNumberLen4)*8 - 2)) {
		return protocol.PacketNumberLen4
	}
	// we do not check if there are less than 2^46 packets in flight, since flow control and congestion control will limit this number *a lot* sooner
	return protocol.PacketNumberLen6
}
