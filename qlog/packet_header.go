package qlog

import (
	"github.com/francoispqt/gojay"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/logging"
)

func getPacketTypeFromEncryptionLevel(encLevel protocol.EncryptionLevel) packetType {
	var t logging.PacketType
	switch encLevel {
	case protocol.EncryptionInitial:
		t = logging.PacketTypeInitial
	case protocol.EncryptionHandshake:
		t = logging.PacketTypeHandshake
	case protocol.Encryption0RTT:
		t = logging.PacketType0RTT
	case protocol.Encryption1RTT:
		t = logging.PacketType1RTT
	default:
		panic("unknown encryption level")
	}
	return packetType(t)
}

func transformHeader(hdr *wire.Header) *packetHeader {
	return &packetHeader{
		PacketType:       logging.PacketTypeFromHeader(hdr),
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

// We don't log the packet type as a part of the header yet, see https://github.com/quiclog/internet-drafts/issues/40.
type packetHeader logging.PacketHeader

func (h packetHeader) MarshalJSONObject(enc *gojay.Encoder) {
	if h.PacketType != logging.PacketTypeRetry && h.PacketType != logging.PacketTypeVersionNegotiation {
		enc.Int64Key("packet_number", int64(h.PacketNumber))
	}
	enc.Int64KeyOmitEmpty("payload_length", int64(h.PayloadLength))
	enc.Int64KeyOmitEmpty("packet_size", int64(h.PacketSize))
	if h.Version != 0 {
		enc.StringKey("version", versionNumber(h.Version).String())
	}
	if h.PacketType != logging.PacketType1RTT {
		enc.IntKey("scil", h.SrcConnectionID.Len())
		if h.SrcConnectionID.Len() > 0 {
			enc.StringKey("scid", connectionID(h.SrcConnectionID).String())
		}
	}
	enc.IntKey("dcil", h.DestConnectionID.Len())
	if h.DestConnectionID.Len() > 0 {
		enc.StringKey("dcid", connectionID(h.DestConnectionID).String())
	}
}
