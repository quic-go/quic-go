package protocol

import "time"

type AckedPacketInfo struct {
	PacketNumber PacketNumber
	BytesAcked   ByteCount
	ReceivedTime time.Time
}

type LostPacketInfo struct {
	PacketNumber PacketNumber
	BytesLost    ByteCount
}
