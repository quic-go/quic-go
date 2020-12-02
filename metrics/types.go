package metrics

import "github.com/lucas-clemente/quic-go/logging"

type perspective logging.Perspective

func (p perspective) String() string {
	switch logging.Perspective(p) {
	case logging.PerspectiveClient:
		return "client"
	case logging.PerspectiveServer:
		return "server"
	default:
		return "unknown perspective"
	}
}

type encryptionLevel logging.EncryptionLevel

func (e encryptionLevel) String() string {
	switch logging.EncryptionLevel(e) {
	case logging.EncryptionInitial:
		return "initial"
	case logging.EncryptionHandshake:
		return "handshake"
	case logging.Encryption0RTT:
		return "0-RTT"
	case logging.Encryption1RTT:
		return "1-RTT"
	default:
		return "unknown encryption level"
	}
}

type packetLossReason logging.PacketLossReason

func (r packetLossReason) String() string {
	switch logging.PacketLossReason(r) {
	case logging.PacketLossTimeThreshold:
		return "time_threshold"
	case logging.PacketLossReorderingThreshold:
		return "reordering_threshold"
	default:
		return "unknown packet loss reason"
	}
}

type packetType logging.PacketType

func (t packetType) String() string {
	switch logging.PacketType(t) {
	case logging.PacketTypeInitial:
		return "initial"
	case logging.PacketTypeHandshake:
		return "handshake"
	case logging.PacketTypeVersionNegotiation:
		return "version_negotiation"
	case logging.PacketTypeRetry:
		return "retry"
	case logging.PacketType0RTT:
		return "0-RTT"
	case logging.PacketType1RTT:
		return "1-RTT"
	default:
		return "unknown packet type"
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
		return "unknown timeout reason"
	}
}
