package qlog

import (
	"github.com/francoispqt/gojay"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

func transformHeader(hdr *wire.ExtendedHeader) *packetHeader {
	return &packetHeader{
		PacketNumber:     hdr.PacketNumber,
		PayloadLength:    hdr.Length,
		SrcConnectionID:  hdr.SrcConnectionID,
		DestConnectionID: hdr.DestConnectionID,
		Version:          hdr.Version,
	}
}

type packetHeader struct {
	PacketNumber  protocol.PacketNumber
	PacketSize    protocol.ByteCount
	PayloadLength protocol.ByteCount

	Version          protocol.VersionNumber
	SrcConnectionID  protocol.ConnectionID
	DestConnectionID protocol.ConnectionID
}

func (h packetHeader) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("packet_number", toString(int64(h.PacketNumber)))
	enc.Int64KeyOmitEmpty("packet_size", int64(h.PacketSize))
	enc.Int64KeyOmitEmpty("payload_length", int64(h.PayloadLength))
	if h.Version != 0 {
		enc.StringKey("version", versionNumber(h.Version).String())
	}
	if h.SrcConnectionID.Len() > 0 {
		enc.StringKey("scil", toString(int64(h.SrcConnectionID.Len())))
		enc.StringKey("scid", connectionID(h.SrcConnectionID).String())
	}
	if h.DestConnectionID.Len() > 0 {
		enc.StringKey("dcil", toString(int64(h.DestConnectionID.Len())))
		enc.StringKey("dcid", connectionID(h.DestConnectionID).String())
	}
}

func (packetHeader) IsNil() bool { return false }
