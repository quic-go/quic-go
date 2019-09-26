package protocol

import "time"

type Packet struct {
	PacketNumber PacketNumber
	Length       ByteCount
	SendTime     time.Time
}
