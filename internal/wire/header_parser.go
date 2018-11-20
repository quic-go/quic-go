package wire

import (
	"bytes"
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// The Header is the version independent part of the header
type Header struct {
	IsLongHeader     bool
	Version          protocol.VersionNumber
	SrcConnectionID  protocol.ConnectionID
	DestConnectionID protocol.ConnectionID

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
	h.IsLongHeader = typeByte&0x80 > 0

	// If this is not a Long Header, it could either be a Public Header or a Short Header.
	if !h.IsLongHeader {
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
	return h, nil
}

// Parse parses the version dependent part of the header.
// The Reader has to be set such that it points to the first byte of the header.
func (h *Header) Parse(b *bytes.Reader, ver protocol.VersionNumber) (*ExtendedHeader, error) {
	if _, err := b.Seek(int64(h.len), io.SeekCurrent); err != nil {
		return nil, err
	}
	if h.IsLongHeader {
		if h.Version == 0 { // Version Negotiation Packet
			return h.parseVersionNegotiationPacket(b)
		}
		return h.parseLongHeader(b, ver)
	}
	return h.parseShortHeader(b, ver)
}

func (h *Header) toExtendedHeader() *ExtendedHeader {
	return &ExtendedHeader{
		IsLongHeader:     h.IsLongHeader,
		DestConnectionID: h.DestConnectionID,
		SrcConnectionID:  h.SrcConnectionID,
		Version:          h.Version,
	}
}

func (h *Header) parseVersionNegotiationPacket(b *bytes.Reader) (*ExtendedHeader, error) {
	eh := h.toExtendedHeader()
	if b.Len() == 0 {
		return nil, qerr.Error(qerr.InvalidVersionNegotiationPacket, "empty version list")
	}
	eh.IsVersionNegotiation = true
	eh.SupportedVersions = make([]protocol.VersionNumber, b.Len()/4)
	for i := 0; b.Len() > 0; i++ {
		v, err := utils.BigEndian.ReadUint32(b)
		if err != nil {
			return nil, qerr.InvalidVersionNegotiationPacket
		}
		eh.SupportedVersions[i] = protocol.VersionNumber(v)
	}
	return eh, nil
}

func (h *Header) parseLongHeader(b *bytes.Reader, v protocol.VersionNumber) (*ExtendedHeader, error) {
	eh := h.toExtendedHeader()
	eh.Type = protocol.PacketType(h.typeByte & 0x7f)

	if eh.Type != protocol.PacketTypeInitial && eh.Type != protocol.PacketTypeRetry && eh.Type != protocol.PacketType0RTT && eh.Type != protocol.PacketTypeHandshake {
		return nil, qerr.Error(qerr.InvalidPacketHeader, fmt.Sprintf("Received packet with invalid packet type: %d", eh.Type))
	}

	if eh.Type == protocol.PacketTypeRetry {
		odcilByte, err := b.ReadByte()
		if err != nil {
			return nil, err
		}
		odcil := decodeSingleConnIDLen(odcilByte & 0xf)
		eh.OrigDestConnectionID, err = protocol.ReadConnectionID(b, odcil)
		if err != nil {
			return nil, err
		}
		eh.Token = make([]byte, b.Len())
		if _, err := io.ReadFull(b, eh.Token); err != nil {
			return nil, err
		}
		return eh, nil
	}

	if eh.Type == protocol.PacketTypeInitial {
		tokenLen, err := utils.ReadVarInt(b)
		if err != nil {
			return nil, err
		}
		if tokenLen > uint64(b.Len()) {
			return nil, io.EOF
		}
		eh.Token = make([]byte, tokenLen)
		if _, err := io.ReadFull(b, eh.Token); err != nil {
			return nil, err
		}
	}

	pl, err := utils.ReadVarInt(b)
	if err != nil {
		return nil, err
	}
	eh.Length = protocol.ByteCount(pl)
	pn, pnLen, err := utils.ReadVarIntPacketNumber(b)
	if err != nil {
		return nil, err
	}
	eh.PacketNumber = pn
	eh.PacketNumberLen = pnLen

	return eh, nil
}

func (h *Header) parseShortHeader(b *bytes.Reader, v protocol.VersionNumber) (*ExtendedHeader, error) {
	eh := h.toExtendedHeader()
	eh.KeyPhase = int(h.typeByte&0x40) >> 6

	pn, pnLen, err := utils.ReadVarIntPacketNumber(b)
	if err != nil {
		return nil, err
	}
	eh.PacketNumber = pn
	eh.PacketNumberLen = pnLen

	return eh, nil
}
