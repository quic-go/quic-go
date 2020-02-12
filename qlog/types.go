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
