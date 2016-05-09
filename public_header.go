package quic

import (
	"bytes"
	"errors"
	"io"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

var (
	errResetAndVersionFlagSet        = errors.New("PublicHeader: Reset Flag and Version Flag should not be set at the same time")
	errReceivedTruncatedConnectionID = errors.New("PublicHeader: Receiving packets with truncated ConnectionID is not supported")
	errInvalidConnectionID           = errors.New("PublicHeader: connection ID cannot be 0")
)

// The PublicHeader of a QUIC packet
type PublicHeader struct {
	Raw                  []byte
	VersionFlag          bool
	ResetFlag            bool
	ConnectionID         protocol.ConnectionID
	TruncateConnectionID bool
	VersionNumber        protocol.VersionNumber
	QuicVersion          uint32
	PacketNumberLen      protocol.PacketNumberLen
	PacketNumber         protocol.PacketNumber
}

// WritePublicHeader writes a public header
func (h *PublicHeader) WritePublicHeader(b *bytes.Buffer) error {
	publicFlagByte := uint8(0x30)
	if h.VersionFlag && h.ResetFlag {
		return errResetAndVersionFlagSet
	}
	if h.VersionFlag {
		publicFlagByte |= 0x01
	}
	if h.ResetFlag {
		publicFlagByte |= 0x02
	}
	if !h.TruncateConnectionID {
		publicFlagByte |= 0x08
	}

	b.WriteByte(publicFlagByte)

	if !h.TruncateConnectionID {
		utils.WriteUint64(b, uint64(h.ConnectionID))
	}

	utils.WriteUint48(b, uint64(h.PacketNumber)) // TODO: Send shorter packet number if possible
	return nil
}

// ParsePublicHeader parses a QUIC packet's public header
func ParsePublicHeader(b io.ByteReader) (*PublicHeader, error) {
	header := &PublicHeader{}

	// First byte
	publicFlagByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	header.VersionFlag = publicFlagByte&0x01 > 0
	header.ResetFlag = publicFlagByte&0x02 > 0

	// TODO: Add this check when we drop support for <v33
	// if publicFlagByte&0x04 > 0 {
	// 	return nil, errors.New("diversification nonces should only be sent by servers")
	// }

	if publicFlagByte&0x08 == 0 {
		return nil, errReceivedTruncatedConnectionID
	}

	switch publicFlagByte & 0x30 {
	case 0x30:
		header.PacketNumberLen = protocol.PacketNumberLen6
	case 0x20:
		header.PacketNumberLen = protocol.PacketNumberLen4
	case 0x10:
		header.PacketNumberLen = protocol.PacketNumberLen2
	case 0x00:
		header.PacketNumberLen = protocol.PacketNumberLen1
	}

	// Connection ID
	connID, err := utils.ReadUint64(b)
	if err != nil {
		return nil, err
	}
	header.ConnectionID = protocol.ConnectionID(connID)
	if header.ConnectionID == 0 {
		return nil, errInvalidConnectionID
	}

	// Version (optional)
	if header.VersionFlag {
		var versionTag uint32
		versionTag, err = utils.ReadUint32(b)
		if err != nil {
			return nil, err
		}
		header.VersionNumber = protocol.VersionTagToNumber(versionTag)
	}

	// Packet number
	packetNumber, err := utils.ReadUintN(b, uint8(header.PacketNumberLen))
	if err != nil {
		return nil, err
	}
	header.PacketNumber = protocol.PacketNumber(packetNumber)

	return header, nil
}
