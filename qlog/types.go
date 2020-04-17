package qlog

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
)

type owner uint8

const (
	ownerLocal owner = iota
	ownerRemote
)

func (o owner) String() string {
	switch o {
	case ownerLocal:
		return "local"
	case ownerRemote:
		return "remote"
	default:
		panic("unknown owner")
	}
}

type versionNumber protocol.VersionNumber

func (v versionNumber) String() string {
	return fmt.Sprintf("%x", uint32(v))
}

type streamType protocol.StreamType

func (s streamType) String() string {
	switch protocol.StreamType(s) {
	case protocol.StreamTypeUni:
		return "unidirectional"
	case protocol.StreamTypeBidi:
		return "bidirectional"
	default:
		panic("unknown stream type")
	}
}

type connectionID protocol.ConnectionID

func (c connectionID) String() string {
	return fmt.Sprintf("%x", []byte(c))
}

// category is the qlog event category.
type category uint8

const (
	categoryConnectivity category = iota
	categoryTransport
	categorySecurity
	categoryRecovery
)

func (c category) String() string {
	switch c {
	case categoryConnectivity:
		return "connectivity"
	case categoryTransport:
		return "transport"
	case categorySecurity:
		return "security"
	case categoryRecovery:
		return "recovery"
	default:
		panic("unknown category")
	}
}

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

func encLevelToPacketNumberSpace(encLevel protocol.EncryptionLevel) string {
	switch encLevel {
	case protocol.EncryptionInitial:
		return "initial"
	case protocol.EncryptionHandshake:
		return "handshake"
	case protocol.Encryption0RTT, protocol.Encryption1RTT:
		return "application_data"
	default:
		panic("unknown encryption level")
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

type keyType uint8

const (
	keyTypeServerInitial keyType = iota
	keyTypeClientInitial
	keyTypeServerHandshake
	keyTypeClientHandshake
	keyTypeServer0RTT
	keyTypeClient0RTT
	keyTypeServer1RTT
	keyTypeClient1RTT
)

func encLevelToKeyType(encLevel protocol.EncryptionLevel, pers protocol.Perspective) keyType {
	if pers == protocol.PerspectiveServer {
		switch encLevel {
		case protocol.EncryptionInitial:
			return keyTypeServerInitial
		case protocol.EncryptionHandshake:
			return keyTypeServerHandshake
		case protocol.Encryption0RTT:
			return keyTypeServer0RTT
		case protocol.Encryption1RTT:
			return keyTypeServer1RTT
		default:
			panic("unknown encryption level")
		}
	}
	switch encLevel {
	case protocol.EncryptionInitial:
		return keyTypeClientInitial
	case protocol.EncryptionHandshake:
		return keyTypeClientHandshake
	case protocol.Encryption0RTT:
		return keyTypeClient0RTT
	case protocol.Encryption1RTT:
		return keyTypeClient1RTT
	default:
		panic("unknown encryption level")
	}
}

func (t keyType) String() string {
	switch t {
	case keyTypeServerInitial:
		return "server_initial_secret"
	case keyTypeClientInitial:
		return "client_initial_secret"
	case keyTypeServerHandshake:
		return "server_handshake_secret"
	case keyTypeClientHandshake:
		return "client_handshake_secret"
	case keyTypeServer0RTT:
		return "server_0rtt_secret"
	case keyTypeClient0RTT:
		return "client_0rtt_secret"
	case keyTypeServer1RTT:
		return "server_1rtt_secret"
	case keyTypeClient1RTT:
		return "client_1rtt_secret"
	default:
		panic("unknown key type")
	}
}

type keyUpdateTrigger uint8

const (
	keyUpdateTLS keyUpdateTrigger = iota
	keyUpdateRemote
	keyUpdateLocal
)

func (t keyUpdateTrigger) String() string {
	switch t {
	case keyUpdateTLS:
		return "tls"
	case keyUpdateRemote:
		return "remote_update"
	case keyUpdateLocal:
		return "local_update"
	default:
		panic("unknown key update trigger")
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
	default:
		panic("unknown packet drop reason")
	}
}

type transportError uint64

func (e transportError) String() string {
	switch qerr.ErrorCode(e) {
	case qerr.NoError:
		return "no_error"
	case qerr.InternalError:
		return "internal_error"
	case qerr.ServerBusy:
		return "server_busy"
	case qerr.FlowControlError:
		return "flow_control_error"
	case qerr.StreamLimitError:
		return "stream_limit_error"
	case qerr.StreamStateError:
		return "stream_state_error"
	case qerr.FinalSizeError:
		return "final_size_error"
	case qerr.FrameEncodingError:
		return "frame_encoding_error"
	case qerr.TransportParameterError:
		return "transport_parameter_error"
	case qerr.ConnectionIDLimitError:
		return "connection_id_limit_error"
	case qerr.ProtocolViolation:
		return "protocol_violation"
	case qerr.InvalidToken:
		return "invalid_token"
	case qerr.ApplicationError:
		return "application_error"
	case qerr.CryptoBufferExceeded:
		return "crypto_buffer_exceeded"
	default:
		return ""
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
