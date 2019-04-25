package protocol

import "time"

type Packet struct {
	PacketNumber PacketNumber
	PacketType   PacketType
	Length       ByteCount
	SendTime     time.Time
}
