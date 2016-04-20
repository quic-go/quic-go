package quic

import (
	"bytes"
	"errors"
	"io"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// The PublicHeader of a QUIC packet
type PublicHeader struct {
	VersionFlag     bool
	ResetFlag       bool
	ConnectionID    protocol.ConnectionID
	VersionNumber   protocol.VersionNumber
	QuicVersion     uint32
	PacketNumberLen uint8
	PacketNumber    protocol.PacketNumber
}

// WritePublicHeader writes a public header
func (h *PublicHeader) WritePublicHeader(b *bytes.Buffer) error {
	publicFlagByte := uint8(0x0C | 0x20)
	if h.VersionFlag && h.ResetFlag {
		return errors.New("Reset Flag and Version Flag should not be set at the same time")
	}
	if h.VersionFlag {
		publicFlagByte |= 0x01
	}
	if h.ResetFlag {
		publicFlagByte |= 0x02
	}

	b.WriteByte(publicFlagByte)
	utils.WriteUint64(b, uint64(h.ConnectionID)) // TODO: Send shorter connection id if possible
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

	var connectionIDLen uint8
	switch publicFlagByte & 0x0C {
	case 0x0C:
		connectionIDLen = 8
	case 0x08:
		connectionIDLen = 4
	case 0x04:
		connectionIDLen = 1
	}
	switch publicFlagByte & 0x30 {
	case 0x30:
		header.PacketNumberLen = 6
	case 0x20:
		header.PacketNumberLen = 4
	case 0x10:
		header.PacketNumberLen = 2
	case 0x00:
		header.PacketNumberLen = 1
	}

	// Connection ID
	connID, err := utils.ReadUintN(b, connectionIDLen)
	if err != nil {
		return nil, err
	}
	header.ConnectionID = protocol.ConnectionID(connID)
	if header.ConnectionID == 0 {
		return nil, errors.New("PublicHeader: connection ID cannot be 0")
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
	pcktNumber, err := utils.ReadUintN(b, header.PacketNumberLen)
	if err != nil {
		return nil, err
	}
	header.PacketNumber = protocol.PacketNumber(pcktNumber)

	return header, nil
}
