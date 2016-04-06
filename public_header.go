package quic

import "io"

// The PublicHeader of a QUIC packet
type PublicHeader struct {
	VersionFlag bool
	ResetFlag   bool

	ConnectionIDLength uint8
	ConnectionID       uint64

	QuicVersion uint32

	PacketNumberLength uint8
	PacketNumber       uint64
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
	switch publicFlagByte & 0x0C {
	case 0x0C:
		header.ConnectionIDLength = 8
	case 0x08:
		header.ConnectionIDLength = 4
	case 0x04:
		header.ConnectionIDLength = 1
	}
	switch publicFlagByte & 0x30 {
	case 0x30:
		header.PacketNumberLength = 6
	case 0x20:
		header.PacketNumberLength = 4
	case 0x10:
		header.PacketNumberLength = 2
	case 0x00:
		header.PacketNumberLength = 1
	}

	// Connection ID
	header.ConnectionID, err = readUint64(b, header.ConnectionIDLength)
	if err != nil {
		return nil, err
	}

	// Version (optional)
	if header.VersionFlag {
		var v uint64
		v, err = readUint64(b, 4)
		if err != nil {
			return nil, err
		}
		header.QuicVersion = uint32(v)
	}

	// Packet number
	header.PacketNumber, err = readUint64(b, header.PacketNumberLength)
	if err != nil {
		return nil, err
	}

	return header, nil
}

func readUint64(b io.ByteReader, length uint8) (uint64, error) {
	var res uint64
	for i := uint8(0); i < length; i++ {
		bt, err := b.ReadByte()
		if err != nil {
			return 0, err
		}
		res = res<<8 + uint64(bt)
	}
	return res, nil
}
