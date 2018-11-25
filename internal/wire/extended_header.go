package wire

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// ExtendedHeader is the header of a QUIC packet.
type ExtendedHeader struct {
	Header

	Raw []byte

	OrigDestConnectionID protocol.ConnectionID // only needed in the Retry packet

	PacketNumberLen protocol.PacketNumberLen
	PacketNumber    protocol.PacketNumber

	IsVersionNegotiation bool
	SupportedVersions    []protocol.VersionNumber // Version Number sent in a Version Negotiation Packet by the server

	Type     protocol.PacketType
	KeyPhase int
	Length   protocol.ByteCount
	Token    []byte
}

func (h *ExtendedHeader) parse(b *bytes.Reader, v protocol.VersionNumber) (*ExtendedHeader, error) {
	if h.IsLongHeader {
		return h.parseLongHeader(b, v)
	}
	return h.parseShortHeader(b, v)
}

func (h *ExtendedHeader) parseLongHeader(b *bytes.Reader, v protocol.VersionNumber) (*ExtendedHeader, error) {
	h.Type = protocol.PacketType(h.typeByte & 0x7f)

	if h.Type != protocol.PacketTypeInitial && h.Type != protocol.PacketTypeRetry && h.Type != protocol.PacketType0RTT && h.Type != protocol.PacketTypeHandshake {
		return nil, qerr.Error(qerr.InvalidPacketHeader, fmt.Sprintf("Received packet with invalid packet type: %d", h.Type))
	}

	if h.Type == protocol.PacketTypeRetry {
		odcilByte, err := b.ReadByte()
		if err != nil {
			return nil, err
		}
		odcil := decodeSingleConnIDLen(odcilByte & 0xf)
		h.OrigDestConnectionID, err = protocol.ReadConnectionID(b, odcil)
		if err != nil {
			return nil, err
		}
		h.Token = make([]byte, b.Len())
		if _, err := io.ReadFull(b, h.Token); err != nil {
			return nil, err
		}
		return h, nil
	}

	if h.Type == protocol.PacketTypeInitial {
		tokenLen, err := utils.ReadVarInt(b)
		if err != nil {
			return nil, err
		}
		if tokenLen > uint64(b.Len()) {
			return nil, io.EOF
		}
		h.Token = make([]byte, tokenLen)
		if _, err := io.ReadFull(b, h.Token); err != nil {
			return nil, err
		}
	}

	pl, err := utils.ReadVarInt(b)
	if err != nil {
		return nil, err
	}
	h.Length = protocol.ByteCount(pl)
	pn, pnLen, err := utils.ReadVarIntPacketNumber(b)
	if err != nil {
		return nil, err
	}
	h.PacketNumber = pn
	h.PacketNumberLen = pnLen

	return h, nil
}

func (h *ExtendedHeader) parseShortHeader(b *bytes.Reader, v protocol.VersionNumber) (*ExtendedHeader, error) {
	h.KeyPhase = int(h.typeByte&0x40) >> 6

	pn, pnLen, err := utils.ReadVarIntPacketNumber(b)
	if err != nil {
		return nil, err
	}
	h.PacketNumber = pn
	h.PacketNumberLen = pnLen

	return h, nil
}

// Write writes the Header.
func (h *ExtendedHeader) Write(b *bytes.Buffer, ver protocol.VersionNumber) error {
	if h.IsLongHeader {
		return h.writeLongHeader(b, ver)
	}
	return h.writeShortHeader(b, ver)
}

// TODO: add support for the key phase
func (h *ExtendedHeader) writeLongHeader(b *bytes.Buffer, v protocol.VersionNumber) error {
	b.WriteByte(byte(0x80 | h.Type))
	utils.BigEndian.WriteUint32(b, uint32(h.Version))
	connIDLen, err := encodeConnIDLen(h.DestConnectionID, h.SrcConnectionID)
	if err != nil {
		return err
	}
	b.WriteByte(connIDLen)
	b.Write(h.DestConnectionID.Bytes())
	b.Write(h.SrcConnectionID.Bytes())

	if h.Type == protocol.PacketTypeInitial {
		utils.WriteVarInt(b, uint64(len(h.Token)))
		b.Write(h.Token)
	}

	if h.Type == protocol.PacketTypeRetry {
		odcil, err := encodeSingleConnIDLen(h.OrigDestConnectionID)
		if err != nil {
			return err
		}
		// randomize the first 4 bits
		odcilByte := make([]byte, 1)
		_, _ = rand.Read(odcilByte) // it's safe to ignore the error here
		odcilByte[0] = (odcilByte[0] & 0xf0) | odcil
		b.Write(odcilByte)
		b.Write(h.OrigDestConnectionID.Bytes())
		b.Write(h.Token)
		return nil
	}

	utils.WriteVarInt(b, uint64(h.Length))
	return utils.WriteVarIntPacketNumber(b, h.PacketNumber, h.PacketNumberLen)
}

func (h *ExtendedHeader) writeShortHeader(b *bytes.Buffer, v protocol.VersionNumber) error {
	typeByte := byte(0x30)
	typeByte |= byte(h.KeyPhase << 6)

	b.WriteByte(typeByte)
	b.Write(h.DestConnectionID.Bytes())
	return utils.WriteVarIntPacketNumber(b, h.PacketNumber, h.PacketNumberLen)
}

// GetLength determines the length of the Header.
func (h *ExtendedHeader) GetLength(v protocol.VersionNumber) protocol.ByteCount {
	if h.IsLongHeader {
		length := 1 /* type byte */ + 4 /* version */ + 1 /* conn id len byte */ + protocol.ByteCount(h.DestConnectionID.Len()+h.SrcConnectionID.Len()) + protocol.ByteCount(h.PacketNumberLen) + utils.VarIntLen(uint64(h.Length))
		if h.Type == protocol.PacketTypeInitial {
			length += utils.VarIntLen(uint64(len(h.Token))) + protocol.ByteCount(len(h.Token))
		}
		return length
	}

	length := protocol.ByteCount(1 /* type byte */ + h.DestConnectionID.Len())
	length += protocol.ByteCount(h.PacketNumberLen)
	return length
}

// Log logs the Header
func (h *ExtendedHeader) Log(logger utils.Logger) {
	if h.IsLongHeader {
		var token string
		if h.Type == protocol.PacketTypeInitial || h.Type == protocol.PacketTypeRetry {
			if len(h.Token) == 0 {
				token = "Token: (empty), "
			} else {
				token = fmt.Sprintf("Token: %#x, ", h.Token)
			}
			if h.Type == protocol.PacketTypeRetry {
				logger.Debugf("\tLong Header{Type: %s, DestConnectionID: %s, SrcConnectionID: %s, %sOrigDestConnectionID: %s, Version: %s}", h.Type, h.DestConnectionID, h.SrcConnectionID, token, h.OrigDestConnectionID, h.Version)
				return
			}
		}
		logger.Debugf("\tLong Header{Type: %s, DestConnectionID: %s, SrcConnectionID: %s, %sPacketNumber: %#x, PacketNumberLen: %d, Length: %d, Version: %s}", h.Type, h.DestConnectionID, h.SrcConnectionID, token, h.PacketNumber, h.PacketNumberLen, h.Length, h.Version)
	} else {
		logger.Debugf("\tShort Header{DestConnectionID: %s, PacketNumber: %#x, PacketNumberLen: %d, KeyPhase: %d}", h.DestConnectionID, h.PacketNumber, h.PacketNumberLen, h.KeyPhase)
	}
}

func encodeConnIDLen(dest, src protocol.ConnectionID) (byte, error) {
	dcil, err := encodeSingleConnIDLen(dest)
	if err != nil {
		return 0, err
	}
	scil, err := encodeSingleConnIDLen(src)
	if err != nil {
		return 0, err
	}
	return scil | dcil<<4, nil
}

func encodeSingleConnIDLen(id protocol.ConnectionID) (byte, error) {
	len := id.Len()
	if len == 0 {
		return 0, nil
	}
	if len < 4 || len > 18 {
		return 0, fmt.Errorf("invalid connection ID length: %d bytes", len)
	}
	return byte(len - 3), nil
}

func decodeConnIDLen(enc byte) (int /*dest conn id len*/, int /*src conn id len*/) {
	return decodeSingleConnIDLen(enc >> 4), decodeSingleConnIDLen(enc & 0xf)
}

func decodeSingleConnIDLen(enc uint8) int {
	if enc == 0 {
		return 0
	}
	return int(enc) + 3
}
