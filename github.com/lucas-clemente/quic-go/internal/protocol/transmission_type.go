package protocol

type TransmissionType int8

const (
	// Retransmits due to handshake timeouts.
	HANDSHAKE_RETRANSMISSION TransmissionType = iota + 1
	// Retransmits all unacked packets.
	ALL_UNACKED_RETRANSMISSION
	// Retransmits all initially encrypted packets.
	ALL_INITIAL_RETRANSMISSION
	// Retransmits due to loss detection.
	LOSS_RETRANSMISSION
	// Retransmits due to retransmit time out.
	RTO_RETRANSMISSION
	// Tail loss probes.
	TLP_RETRANSMISSION
	// Retransmission in order to probe bandwidth.
	PROBING_RETRANSMISSION
	LAST_TRANSMISSION_TYPE                   = PROBING_RETRANSMISSION
	NOT_RETRANSMISSION      TransmissionType = 0
	FIRST_TRANSMISSION_TYPE                  = NOT_RETRANSMISSION
)
