package congestion

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type TransmissionInfo struct {
	retransmittableFrames []wire.Frame
	encryptionLevel       protocol.EncryptionLevel
	packetNumberLength    protocol.PacketNumberLen
	bytesSent             protocol.PacketLength
	sent_time             time.Time
	// Reason why this packet was transmitted.
	transmissionType protocol.TransmissionType
	// In flight packets have not been abandoned or lost.
	inFlight bool
	// State of this packet.
	state protocol.SentPacketState
	// True if the packet contains stream data from the crypto stream.
	hasCryptoHandshake bool
	// Non-zero if the packet needs padding if it's retransmitted.
	numPaddingBytes int16
	// Stores the packet number of the next retransmission of this packet.
	// Zero if the packet has not been retransmitted.
	// TODO(fayang): rename this to first_sent_after_loss_ when deprecating
	// QUIC_VERSION_41.
	retransmission protocol.PacketNumber
	// The largestAcked in the ack frame, if the packet contains an ack.
	largestAcked protocol.PacketNumber
}

func (t *TransmissionInfo) SetState(state protocol.SentPacketState) {
	t.state = state
}

func (t *TransmissionInfo) SetInFlight(inFlight bool) {
	t.inFlight = inFlight
}

// Used by STL when assigning into a map.
func DefaultNewTransmissionInfo() *TransmissionInfo {
	return &TransmissionInfo{
		encryptionLevel:    protocol.EncryptionUnencrypted,
		packetNumberLength: protocol.PacketNumberLen1,
		bytesSent:          0,
		transmissionType:   protocol.NOT_RETRANSMISSION,
		inFlight:           false,
		state:              protocol.OUTSTANDING,
		hasCryptoHandshake: false,
		numPaddingBytes:    0,
	}
}

// Constructs a Transmission with a new all_transmissions set
// containing |packetNumber|.
func NewTransmissionInfo(
	level protocol.EncryptionLevel,
	packetNumberLength protocol.PacketNumberLen,
	transmissionType protocol.TransmissionType,
	sentTime time.Time,
	bytesSent protocol.PacketLength,
	hasCryptoHandshake bool,
	numPaddingBytes int) *TransmissionInfo {
	return &TransmissionInfo{
		encryptionLevel:    level,
		packetNumberLength: packetNumberLength,
		bytesSent:          bytesSent,
		sent_time:          sentTime,
		transmissionType:   transmissionType,
		inFlight:           false,
		state:              protocol.OUTSTANDING,
		hasCryptoHandshake: hasCryptoHandshake,
		numPaddingBytes:    int16(numPaddingBytes),
	}
}

func (t *TransmissionInfo) State() protocol.SentPacketState {
	return t.state
}

func (t *TransmissionInfo) LargestAcked() protocol.PacketNumber {
	return t.largestAcked
}

func (t *TransmissionInfo) SetLargestAcked(largestAcked protocol.PacketNumber) {
	t.largestAcked = largestAcked
}
