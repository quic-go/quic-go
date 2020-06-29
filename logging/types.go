package logging

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// PacketType is the packet type of a QUIC packet
type PacketType protocol.PacketType

const (
	// PacketTypeInitial is the packet type of an Initial packet
	PacketTypeInitial PacketType = iota
	// PacketTypeHandshake is the packet type of a Handshake packet
	PacketTypeHandshake
	// PacketTypeRetry is the packet type of a Retry packet
	PacketTypeRetry
	// PacketType0RTT is the packet type of a 0-RTT packet
	PacketType0RTT
	// PacketTypeVersionNegotiation is the packet type of a Version Negotiation packet
	PacketTypeVersionNegotiation
	// PacketType1RTT is a 1-RTT packet
	PacketType1RTT
	// PacketTypeStatelessReset is a stateless reset
	PacketTypeStatelessReset
	// PacketTypeNotDetermined is the packet type when it could not be determined
	PacketTypeNotDetermined
)

func (t PacketType) String() string {
	switch t {
	case PacketTypeInitial:
		return "initial"
	case PacketTypeHandshake:
		return "handshake"
	case PacketTypeRetry:
		return "retry"
	case PacketType0RTT:
		return "0RTT"
	case PacketTypeVersionNegotiation:
		return "version_negotiation"
	case PacketTypeStatelessReset:
		return "stateless_reset"
	case PacketType1RTT:
		return "1RTT"
	case PacketTypeNotDetermined:
		return ""
	default:
		panic("unknown packet type")
	}
}

type PacketLossReason uint8

const (
	// PacketLossReorderingThreshold: when a packet is deemed lost due to reordering threshold
	PacketLossReorderingThreshold PacketLossReason = iota
	// PacketLossTimeThreshold: when a packet is deemed lost due to time threshold
	PacketLossTimeThreshold
)

func (r PacketLossReason) String() string {
	switch r {
	case PacketLossReorderingThreshold:
		return "reordering_threshold"
	case PacketLossTimeThreshold:
		return "time_threshold"
	default:
		panic("unknown loss reason")
	}
}

type PacketDropReason uint8

const (
	// PacketDropKeyUnavailable is used when a packet is dropped because keys are unavailable
	PacketDropKeyUnavailable PacketDropReason = iota
	// PacketDropUnknownConnectionID is used when a packet is dropped because the connection ID is unknown
	PacketDropUnknownConnectionID
	// PacketDropHeaderParseError is used when a packet is dropped because header parsing failed
	PacketDropHeaderParseError
	// PacketDropPayloadDecryptError is used when a packet is dropped because decrypting the payload failed
	PacketDropPayloadDecryptError
	// PacketDropProtocolViolation is used when a packet is dropped due to a protocol violation
	PacketDropProtocolViolation
	// PacketDropDOSPrevention is used when a packet is dropped to mitigate a DoS attack
	PacketDropDOSPrevention
	// PacketDropUnsupportedVersion is used when a packet is dropped because the version is not supported
	PacketDropUnsupportedVersion
	// PacketDropUnexpectedPacket is used when an unexpected packet is received
	PacketDropUnexpectedPacket
	// PacketDropUnexpectedSourceConnectionID is used when a packet with an unexpected source connection ID is received
	PacketDropUnexpectedSourceConnectionID
	// PacketDropUnexpectedVersion is used when a packet with an unexpected version is received
	PacketDropUnexpectedVersion
	// PacketDropDuplicate is used when a duplicate packet is received
	PacketDropDuplicate
)

func (r PacketDropReason) String() string {
	switch r {
	case PacketDropKeyUnavailable:
		return "key_unavailable"
	case PacketDropUnknownConnectionID:
		return "unknown_connection_id"
	case PacketDropHeaderParseError:
		return "header_parse_error"
	case PacketDropPayloadDecryptError:
		return "payload_decrypt_error"
	case PacketDropProtocolViolation:
		return "protocol_violation"
	case PacketDropDOSPrevention:
		return "dos_prevention"
	case PacketDropUnsupportedVersion:
		return "unsupported_version"
	case PacketDropUnexpectedPacket:
		return "unexpected_packet"
	case PacketDropUnexpectedSourceConnectionID:
		return "unexpected_source_connection_id"
	case PacketDropUnexpectedVersion:
		return "unexpected_version"
	case PacketDropDuplicate:
		return "duplicate"
	default:
		panic("unknown packet drop reason")
	}
}

// TimerType is the type of the loss detection timer
type TimerType uint8

const (
	// TimerTypeACK is the timer type for the early retransmit timer
	TimerTypeACK TimerType = iota
	// TimerTypePTO is the timer type for the PTO retransmit timer
	TimerTypePTO
)

func (t TimerType) String() string {
	switch t {
	case TimerTypeACK:
		return "ack"
	case TimerTypePTO:
		return "pto"
	default:
		panic("unknown timer type")
	}
}

// CloseReason is the reason why a session is closed
type CloseReason uint8

const (
	// CloseReasonHandshakeTimeout is used when the session is closed due to a handshake timeout
	// This reason is not defined in the qlog draft, but very useful for debugging.
	CloseReasonHandshakeTimeout CloseReason = iota
	// CloseReasonIdleTimeout is used when the session is closed due to an idle timeout
	// This reason is not defined in the qlog draft, but very useful for debugging.
	CloseReasonIdleTimeout
)

func (r CloseReason) String() string {
	switch r {
	case CloseReasonHandshakeTimeout:
		return "handshake_timeout"
	case CloseReasonIdleTimeout:
		return "idle_timeout"
	default:
		panic("unknown close reason")
	}
}
