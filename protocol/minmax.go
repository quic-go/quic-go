package protocol

// MaxPacketNumber returns the max packet number
func MaxPacketNumber(a, b PacketNumber) PacketNumber {
	if a > b {
		return a
	}
	return b
}

// MinPacketNumber returns the min packet number
func MinPacketNumber(a, b PacketNumber) PacketNumber {
	if a < b {
		return a
	}
	return b
}
