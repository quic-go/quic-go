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
		panic("unknown perspective")
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
		panic("unknown encryption level")
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
		panic("unknown packet loss reason")
	}
}
