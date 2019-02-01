package congestion

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"time"
)

// Information about a newly acknowledged packet.
type AckedPacket struct {

	packetNumber protocol.PacketNumber
	// Number of bytes sent in the packet that was acknowledged.
	bytesAcked protocol.PacketLength
	// The time |packetNumber| was received by the peer, according to the
	// optional timestamp the peer included in the ACK frame which acknowledged
	// |packetNumber|. Zero if no timestamp was available for this packet.
	receiveTimestamp time.Time
}

func NewAckedPacket(
	packetNumber protocol.PacketNumber,
	bytesAcked protocol.PacketLength,
	receiveTimestamp time.Time) *AckedPacket {
	return &AckedPacket{packetNumber: packetNumber, bytesAcked: bytesAcked, receiveTimestamp: receiveTimestamp}
};

// Information about a newly lost packet.
type LostPacket struct {


	packetNumber protocol.PacketNumber
	// Number of bytes sent in the packet that was lost.
	bytesLost protocol.PacketLength
}

func NewLostPacket(
	packetNumber protocol.PacketNumber,
	bytesLost protocol.PacketLength) *LostPacket {
	return &LostPacket{packetNumber: packetNumber, bytesLost: bytesLost}
}

type SerializedPacket struct {


	// Not owned.
	encryptedBuffer       string
	encryptedLength       protocol.PacketLength
	retransmittableFrames []wire.Frame
	hasCryptoHandshake    bool
	// -1: full padding to the end of a max-sized packet
	//  0: no padding
	//  otherwise: only pad up to numPaddingBytes bytes
	numPaddingBytes      int16;
	packetNumber         protocol.PacketNumber
	packetNumberLength   protocol.PacketNumberLen
	encryptionLevel      protocol.EncryptionLevel
	hasAck               bool
	hasStopWaiting       bool
	transmissionType     protocol.TransmissionType
	originalPacketNumber protocol.PacketNumber
	// The largest acked of the AckFrame in this packet if hasAck is true,
	// 0 otherwise.
	largestAcked protocol.PacketNumber
}

func NewSerializedPacket(
	encryptedBuffer string,
	encryptedLength protocol.PacketLength,
	packetNumber protocol.PacketNumber,
	packetNumberLength protocol.PacketNumberLen,
	hasAck bool,
	hasStopWaiting bool) *SerializedPacket {
	return &SerializedPacket{encryptedBuffer: encryptedBuffer, encryptedLength: encryptedLength, packetNumber: packetNumber, packetNumberLength: packetNumberLength, hasAck: hasAck, hasStopWaiting: hasStopWaiting}
}

