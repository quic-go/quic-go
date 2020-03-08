package qlog

import (
	"fmt"
	"strconv"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

func toString(i int64) string {
	return strconv.FormatInt(i, 10)
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

type packetType protocol.PacketType

const (
	packetTypeInitial packetType = iota
	packetTypeHandshake
	packetTypeRetry
	packetType0RTT
	packetTypeVersionNegotiation
	packetType1RTT
)

func (t packetType) String() string {
	switch t {
	case packetTypeInitial:
		return "initial"
	case packetTypeHandshake:
		return "handshake"
	case packetTypeRetry:
		return "retry"
	case packetType0RTT:
		return "0RTT"
	case packetTypeVersionNegotiation:
		return "version_negotiation"
	case packetType1RTT:
		return "1RTT"
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
