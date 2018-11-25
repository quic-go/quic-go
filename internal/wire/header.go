package wire

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// The Header is the version independent part of the header
type Header struct {
	Version          protocol.VersionNumber
	SrcConnectionID  protocol.ConnectionID
	DestConnectionID protocol.ConnectionID

	SupportedVersions []protocol.VersionNumber // sent in a Version Negotiation Packet

	typeByte byte
	len      int // how many bytes were read while parsing this header
}

// ParseHeader parses the version independent part of the header
func ParseHeader(b *bytes.Reader, shortHeaderConnIDLen int) (*Header, error) {
	startLen := b.Len()
	h, err := parseHeaderImpl(b, shortHeaderConnIDLen)
	if err != nil {
		return nil, err
	}
	h.len = startLen - b.Len()
	return h, nil
}

func parseHeaderImpl(b *bytes.Reader, shortHeaderConnIDLen int) (*Header, error) {
	typeByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}

	h := &Header{typeByte: typeByte}

	// If this is not a Long Header, it could either be a Public Header or a Short Header.
	if !h.IsLongHeader() {
		var err error
		h.DestConnectionID, err = protocol.ReadConnectionID(b, shortHeaderConnIDLen)
		if err != nil {
			return nil, err
		}
		return h, nil
	}
	// Long Header
	v, err := utils.BigEndian.ReadUint32(b)
	if err != nil {
		return nil, err
	}
	h.Version = protocol.VersionNumber(v)
	connIDLenByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	dcil, scil := decodeConnIDLen(connIDLenByte)
	h.DestConnectionID, err = protocol.ReadConnectionID(b, dcil)
	if err != nil {
		return nil, err
	}
	h.SrcConnectionID, err = protocol.ReadConnectionID(b, scil)
	if err != nil {
		return nil, err
	}
	if h.Version == 0 {
		if b.Len() == 0 {
			return nil, qerr.Error(qerr.InvalidVersionNegotiationPacket, "empty version list")
		}
		h.SupportedVersions = make([]protocol.VersionNumber, b.Len()/4)
		for i := 0; b.Len() > 0; i++ {
			v, err := utils.BigEndian.ReadUint32(b)
			if err != nil {
				return nil, qerr.InvalidVersionNegotiationPacket
			}
			h.SupportedVersions[i] = protocol.VersionNumber(v)
		}
	}
	return h, nil
}

// IsLongHeader says if this is a long header
func (h *Header) IsLongHeader() bool {
	return h.typeByte&0x80 > 0
}

// IsVersionNegotiation says if this a version negotiation packet
func (h *Header) IsVersionNegotiation() bool {
	return h.IsLongHeader() && h.Version == 0
}

// ParseExtended parses the version dependent part of the header.
// The Reader has to be set such that it points to the first byte of the header.
func (h *Header) ParseExtended(b *bytes.Reader, ver protocol.VersionNumber) (*ExtendedHeader, error) {
	if _, err := b.Seek(int64(h.len), io.SeekCurrent); err != nil {
		return nil, err
	}
	return h.toExtendedHeader().parse(b, ver)
}

func (h *Header) toExtendedHeader() *ExtendedHeader {
	return &ExtendedHeader{
		IsLongHeader:     h.IsLongHeader(),
		typeByte:         h.typeByte,
		DestConnectionID: h.DestConnectionID,
		SrcConnectionID:  h.SrcConnectionID,
		Version:          h.Version,
	}
}
