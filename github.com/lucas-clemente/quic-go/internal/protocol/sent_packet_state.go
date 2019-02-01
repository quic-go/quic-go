package protocol

type SentPacketState uint8

const (
	// The packet was never sent.
	NEVER_SENT SentPacketState = iota + 1
	// The packet has been acked.
	ACKED
	// This packet is not expected to be acked.
	UNACKABLE

	// States below are corresponding to retransmission types in TransmissionType.

	// This packet has been retransmitted when retransmission timer fires in
	// HANDSHAKE mode.
	HANDSHAKE_RETRANSMITTED
	// This packet is considered as lost, this is used for LOST_RETRANSMISSION.
	LOST
	// This packet has been retransmitted when TLP fires.
	TLP_RETRANSMITTED
	// This packet has been retransmitted when RTO fires.
	RTO_RETRANSMITTED
	// This packet has been retransmitted for probing purpose.
	PROBE_RETRANSMITTED
	LAST_PACKET_STATE = PROBE_RETRANSMITTED
	// The packet has been sent and waiting to be acked.
	OUTSTANDING
	FIRST_PACKET_STATE = OUTSTANDING
)
