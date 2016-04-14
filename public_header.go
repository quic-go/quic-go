package quic

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/utils"
)

// The PublicHeader of a QUIC packet
type PublicHeader struct {
	VersionFlag  bool
	ResetFlag    bool
	ConnectionID uint64
	QuicVersion  uint32
	PacketNumber uint64
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

	var connectionIDLen, packetNumberLen uint8
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
		packetNumberLen = 6
	case 0x20:
		packetNumberLen = 4
	case 0x10:
		packetNumberLen = 2
	case 0x00:
		packetNumberLen = 1
	}

	// Connection ID
	header.ConnectionID, err = utils.ReadUintN(b, connectionIDLen)
	if err != nil {
		return nil, err
	}

	// Version (optional)

	if header.VersionFlag {
		header.QuicVersion, err = utils.ReadUint32BigEndian(b)
		if err != nil {
			return nil, err
		}
	}

	// Packet number
	header.PacketNumber, err = utils.ReadUintN(b, packetNumberLen)
	if err != nil {
		return nil, err
	}

	return header, nil
}

// WritePublicHeader writes a public header
func WritePublicHeader(b *bytes.Buffer, h *PublicHeader) {
	publicFlagByte := uint8(0x0C | 0x20)
	b.WriteByte(publicFlagByte)
	utils.WriteUint64(b, h.ConnectionID)         // TODO: Send shorter connection id if possible
	utils.WriteUint32(b, uint32(h.PacketNumber)) // TODO: Send shorter packet number if possible
}
