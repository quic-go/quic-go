package qlog

import (
	"github.com/francoispqt/gojay"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// PacketTypeFromHeader determines the packet type from a *wire.Header.
func PacketTypeFromHeader(hdr *wire.Header) PacketType {
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

func getPacketTypeFromEncryptionLevel(encLevel protocol.EncryptionLevel) PacketType {
	switch encLevel {
	case protocol.EncryptionInitial:
		return PacketTypeInitial
	case protocol.EncryptionHandshake:
		return PacketTypeHandshake
	case protocol.Encryption0RTT:
		return PacketType0RTT
	case protocol.Encryption1RTT:
		return PacketType1RTT
	default:
		panic("unknown encryption level")
	}
}

func transformHeader(hdr *wire.Header) *packetHeader {
	return &packetHeader{
		PayloadLength:    hdr.Length,
		SrcConnectionID:  hdr.SrcConnectionID,
		DestConnectionID: hdr.DestConnectionID,
		Version:          hdr.Version,
	}
}

func transformExtendedHeader(hdr *wire.ExtendedHeader) *packetHeader {
	h := transformHeader(&hdr.Header)
	h.PacketNumber = hdr.PacketNumber
	return h
}

type packetHeader struct {
	PacketNumber  protocol.PacketNumber
	PayloadLength protocol.ByteCount
	// Size of the QUIC packet (QUIC header + payload).
	// See https://github.com/quiclog/internet-drafts/issues/40.
	PacketSize protocol.ByteCount

	Version          protocol.VersionNumber
	SrcConnectionID  protocol.ConnectionID
	DestConnectionID protocol.ConnectionID
}

func (h packetHeader) MarshalJSONObject(enc *gojay.Encoder) {
	enc.Int64KeyOmitEmpty("packet_number", int64(h.PacketNumber))
	enc.Int64KeyOmitEmpty("payload_length", int64(h.PayloadLength))
	enc.Int64KeyOmitEmpty("packet_size", int64(h.PacketSize))
	if h.Version != 0 {
		enc.StringKey("version", versionNumber(h.Version).String())
	}
	if h.SrcConnectionID.Len() > 0 {
		enc.IntKey("scil", h.SrcConnectionID.Len())
		enc.StringKey("scid", connectionID(h.SrcConnectionID).String())
	}
	if h.DestConnectionID.Len() > 0 {
		enc.IntKey("dcil", h.DestConnectionID.Len())
		enc.StringKey("dcid", connectionID(h.DestConnectionID).String())
	}
}

func (packetHeader) IsNil() bool { return false }
