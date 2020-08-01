package qlog

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/logging"
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

type versionNumber protocol.VersionNumber

func (v versionNumber) String() string {
	return fmt.Sprintf("%x", uint32(v))
}

func (packetHeader) IsNil() bool { return false }

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

type transportError uint64

func (e transportError) String() string {
	switch qerr.ErrorCode(e) {
	case qerr.NoError:
		return "no_error"
	case qerr.InternalError:
		return "internal_error"
	case qerr.ConnectionRefused:
		return "connection_refused"
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

type packetType logging.PacketType

func (t packetType) String() string {
	switch logging.PacketType(t) {
	case logging.PacketTypeInitial:
		return "initial"
	case logging.PacketTypeHandshake:
		return "handshake"
	case logging.PacketTypeRetry:
		return "retry"
	case logging.PacketType0RTT:
		return "0RTT"
	case logging.PacketTypeVersionNegotiation:
		return "version_negotiation"
	case logging.PacketTypeStatelessReset:
		return "stateless_reset"
	case logging.PacketType1RTT:
		return "1RTT"
	case logging.PacketTypeNotDetermined:
		return ""
	default:
		panic("unknown packet type")
	}
}

type packetLossReason logging.PacketLossReason

func (r packetLossReason) String() string {
	switch logging.PacketLossReason(r) {
	case logging.PacketLossReorderingThreshold:
		return "reordering_threshold"
	case logging.PacketLossTimeThreshold:
		return "time_threshold"
	default:
		panic("unknown loss reason")
	}
}

type packetDropReason logging.PacketDropReason

func (r packetDropReason) String() string {
	switch logging.PacketDropReason(r) {
	case logging.PacketDropKeyUnavailable:
		return "key_unavailable"
	case logging.PacketDropUnknownConnectionID:
		return "unknown_connection_id"
	case logging.PacketDropHeaderParseError:
		return "header_parse_error"
	case logging.PacketDropPayloadDecryptError:
		return "payload_decrypt_error"
	case logging.PacketDropProtocolViolation:
		return "protocol_violation"
	case logging.PacketDropDOSPrevention:
		return "dos_prevention"
	case logging.PacketDropUnsupportedVersion:
		return "unsupported_version"
	case logging.PacketDropUnexpectedPacket:
		return "unexpected_packet"
	case logging.PacketDropUnexpectedSourceConnectionID:
		return "unexpected_source_connection_id"
	case logging.PacketDropUnexpectedVersion:
		return "unexpected_version"
	case logging.PacketDropDuplicate:
		return "duplicate"
	default:
		panic("unknown packet drop reason")
	}
}

type timerType logging.TimerType

func (t timerType) String() string {
	switch logging.TimerType(t) {
	case logging.TimerTypeACK:
		return "ack"
	case logging.TimerTypePTO:
		return "pto"
	default:
		panic("unknown timer type")
	}
}

type timeoutReason logging.TimeoutReason

func (r timeoutReason) String() string {
	switch logging.TimeoutReason(r) {
	case logging.TimeoutReasonHandshake:
		return "handshake_timeout"
	case logging.TimeoutReasonIdle:
		return "idle_timeout"
	default:
		panic("unknown close reason")
	}
}

type congestionState logging.CongestionState

func (s congestionState) String() string {
	switch logging.CongestionState(s) {
	case logging.CongestionStateSlowStart:
		return "slow_start"
	case logging.CongestionStateCongestionAvoidance:
		return "congestion_avoidance"
	case logging.CongestionStateRecovery:
		return "recovery"
	case logging.CongestionStateApplicationLimited:
		return "application_limited"
	default:
		panic("unknown congestion state")
	}
}
