package protocol

// InferPacketNumber calculates the packet number based on the received packet number, its length and the last seen packet number
func InferPacketNumber(packetNumberLength PacketNumberLen, lastPacketNumber PacketNumber, wirePacketNumber PacketNumber) PacketNumber {
	epochDelta := PacketNumber(1) << (uint8(packetNumberLength) * 8)
	epoch := lastPacketNumber & ^(epochDelta - 1)
	prevEpochBegin := epoch - epochDelta
	nextEpochBegin := epoch + epochDelta
	return closestTo(
		lastPacketNumber+1,
		epoch+wirePacketNumber,
		closestTo(lastPacketNumber+1, prevEpochBegin+wirePacketNumber, nextEpochBegin+wirePacketNumber),
	)
}

func closestTo(target, a, b PacketNumber) PacketNumber {
	if delta(target, a) < delta(target, b) {
		return a
	}
	return b
}

func delta(a, b PacketNumber) PacketNumber {
	if a < b {
		return b - a
	}
	return a - b
}

// GetPacketNumberLengthForPublicHeader gets the length of the packet number for the public header
func GetPacketNumberLengthForPublicHeader(packetNumber PacketNumber, highestAckedPacketNumber PacketNumber) PacketNumberLen {
	diff := uint64(packetNumber - highestAckedPacketNumber)
	if diff < (2 << (uint8(PacketNumberLen1)*8 - 2)) {
		return PacketNumberLen1
	}
	if diff < (2 << (uint8(PacketNumberLen2)*8 - 2)) {
		return PacketNumberLen2
	}
	if diff < (2 << (uint8(PacketNumberLen4)*8 - 2)) {
		return PacketNumberLen4
	}
	// we do not check if there are less than 2^46 packets in flight, since flow control and congestion control will limit this number *a lot* sooner
	return PacketNumberLen6
}
