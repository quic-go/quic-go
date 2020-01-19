package qlog

import (
	"encoding/json"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type versionNumber protocol.VersionNumber

func (v versionNumber) MarshalJSON() ([]byte, error) {
	return escapeStr(fmt.Sprintf("%x", v)), nil
}

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
	PacketNumber  protocol.PacketNumber `json:"packet_number,string"`
	PacketSize    protocol.ByteCount    `json:"packet_size,omitempty"`
	PayloadLength protocol.ByteCount    `json:"payload_length,omitempty"`

	Version          protocol.VersionNumber `json:"version,omitempty"`
	SrcConnectionID  protocol.ConnectionID  `json:"scid,string,omitempty"`
	DestConnectionID protocol.ConnectionID  `json:"dcid,string,omitempty"`
}

func (h packetHeader) MarshalJSON() ([]byte, error) {
	type Alias packetHeader
	return json.Marshal(&struct {
		SrcConnectionIDLen  int           `json:"scil,string,omitempty"`
		SrcConnectionID     connectionID  `json:"scid,string,omitempty"`
		DestConnectionIDLen int           `json:"dcil,string,omitempty"`
		DestConnectionID    connectionID  `json:"dcid,string,omitempty"`
		Version             versionNumber `json:"version,omitempty"`
		Alias
	}{
		Alias:               (Alias)(h),
		SrcConnectionIDLen:  h.SrcConnectionID.Len(),
		SrcConnectionID:     connectionID(h.SrcConnectionID),
		DestConnectionIDLen: h.DestConnectionID.Len(),
		DestConnectionID:    connectionID(h.DestConnectionID),
		Version:             versionNumber(h.Version),
	})
}
