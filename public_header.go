package quic

import (
	"bytes"
	"io"
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
	header.ConnectionID, err = readUintN(b, connectionIDLen)
	if err != nil {
		return nil, err
	}

	// Version (optional)
	if header.VersionFlag {
		var v uint64
		v, err = readUintN(b, 4)
		if err != nil {
			return nil, err
		}
		header.QuicVersion = uint32(v)
	}

	// Packet number
	header.PacketNumber, err = readUintN(b, packetNumberLen)
	if err != nil {
		return nil, err
	}

	return header, nil
}
