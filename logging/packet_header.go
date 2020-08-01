package logging

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// PacketTypeFromHeader determines the packet type from a *wire.Header.
func PacketTypeFromHeader(hdr *Header) PacketType {
	if !hdr.IsLongHeader {
		return PacketType1RTT
	}
	if hdr.Version == 0 {
		return PacketTypeVersionNegotiation
	}
	switch hdr.Type {
	case protocol.PacketTypeInitial:
		return PacketTypeInitial
	case protocol.PacketTypeHandshake:
		return PacketTypeHandshake
	case protocol.PacketType0RTT:
		return PacketType0RTT
	case protocol.PacketTypeRetry:
		return PacketTypeRetry
	default:
		return PacketTypeNotDetermined
	}
}

// PacketHeader is a QUIC packet header.
type PacketHeader struct {
	PacketType PacketType

	PacketNumber  PacketNumber
	PayloadLength ByteCount
	// Size of the QUIC packet (QUIC header + payload).
	// See https://github.com/quiclog/internet-drafts/issues/40.
	PacketSize ByteCount

	Version          VersionNumber
	SrcConnectionID  ConnectionID
	DestConnectionID ConnectionID
}
