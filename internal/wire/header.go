package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// Header is the header of a QUIC packet.
// It contains fields that are only needed for the gQUIC Public Header and the IETF draft Header.
type Header struct {
	Raw               []byte
	ConnectionID      protocol.ConnectionID
	OmitConnectionID  bool
	PacketNumberLen   protocol.PacketNumberLen
	PacketNumber      protocol.PacketNumber
	Version           protocol.VersionNumber   // VersionNumber sent by the client
	SupportedVersions []protocol.VersionNumber // Version Number sent in a Version Negotiation Packet by the server

	// only needed for the gQUIC Public Header
	VersionFlag          bool
	ResetFlag            bool
	DiversificationNonce []byte

	// only needed for the IETF Header
	Type         protocol.PacketType
	IsLongHeader bool
	KeyPhase     int

	// only needed for logging
	isPublicHeader bool
}

// ParseHeader parses the header.
func ParseHeader(b *bytes.Reader, sentBy protocol.Perspective, version protocol.VersionNumber) (*Header, error) {
	var typeByte uint8
	if version == protocol.VersionUnknown {
		var err error
		typeByte, err = b.ReadByte()
		if err != nil {
			return nil, err
		}
		_ = b.UnreadByte() // unread the type byte
	}

	// There are two conditions this is a header in the IETF Header format:
	// 1. We already know the version (because this is a packet that belongs to an exisitng session).
	// 2. If this is a new packet, it must have the Long Format, which has the 0x80 bit set (which is always 0 in gQUIC).
	// There's a third option: This could be a packet with Short Format that arrives after a server lost state.
	// In that case, we'll try parsing the header as a gQUIC Public Header.
	if version.UsesTLS() || (version == protocol.VersionUnknown && typeByte&0x80 > 0) {
		return parseHeader(b, sentBy)
	}

	// This is a gQUIC Public Header.
	hdr, err := parsePublicHeader(b, sentBy, version)
	if err != nil {
		return nil, err
	}
	hdr.isPublicHeader = true // save that this is a Public Header, so we can log it correctly later
	return hdr, nil
}

// PeekConnectionID parses the connection ID from a QUIC packet's public header, sent by the client.
// This function should not be called for packets sent by the server, since on these packets the Connection ID could be omitted.
// If no error occurs, it restores the read position in the bytes.Reader.
func PeekConnectionID(b *bytes.Reader) (protocol.ConnectionID, error) {
	var connectionID protocol.ConnectionID
	if _, err := b.ReadByte(); err != nil {
		return 0, err
	}
	// unread the public flag byte
	defer b.UnreadByte()

	// Assume that the packet contains the Connection ID.
	// This is a valid assumption for all packets sent by the client, because the server doesn't allow the ommision of the Connection ID.
	connID, err := utils.BigEndian.ReadUint64(b)
	if err != nil {
		return 0, err
	}
	connectionID = protocol.ConnectionID(connID)
	// unread the connection ID
	for i := 0; i < 8; i++ {
		b.UnreadByte()
	}
	return connectionID, nil
}

// Write writes the Header.
func (h *Header) Write(b *bytes.Buffer, pers protocol.Perspective, version protocol.VersionNumber) error {
	if !version.UsesTLS() {
		h.isPublicHeader = true // save that this is a Public Header, so we can log it correctly later
		return h.writePublicHeader(b, pers, version)
	}
	return h.writeHeader(b)
}

// GetLength determines the length of the Header.
func (h *Header) GetLength(pers protocol.Perspective, version protocol.VersionNumber) (protocol.ByteCount, error) {
	if !version.UsesTLS() {
		return h.getPublicHeaderLength(pers)
	}
	return h.getHeaderLength()
}

// Log logs the Header
func (h *Header) Log() {
	if h.isPublicHeader {
		h.logPublicHeader()
	} else {
		h.logHeader()
	}
}
