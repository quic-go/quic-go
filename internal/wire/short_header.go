package wire

import (
	"errors"
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type ShortHeader struct {
	DestConnectionID protocol.ConnectionID
	PacketNumber     protocol.PacketNumber
	PacketNumberLen  protocol.PacketNumberLen
	KeyPhase         protocol.KeyPhaseBit
}

func ParseShortHeader(data []byte, connIDLen int) (*ShortHeader, error) {
	if len(data) == 0 {
		return nil, io.EOF
	}
	if data[0]&0x80 > 0 {
		return nil, errors.New("not a short header packet")
	}
	if data[0]&0x40 == 0 {
		return nil, errors.New("not a QUIC packet")
	}
	pnLen := protocol.PacketNumberLen(data[0]&0b11) + 1
	if len(data) < 1+int(pnLen)+connIDLen {
		return nil, io.EOF
	}
	destConnID := protocol.ParseConnectionID(data[1 : 1+connIDLen])

	pos := 1 + connIDLen
	var pn protocol.PacketNumber
	switch pnLen {
	case protocol.PacketNumberLen1:
		pn = protocol.PacketNumber(data[pos])
	case protocol.PacketNumberLen2:
		pn = protocol.PacketNumber(utils.BigEndian.Uint16(data[pos : pos+2]))
	case protocol.PacketNumberLen3:
		pn = protocol.PacketNumber(utils.BigEndian.Uint24(data[pos : pos+3]))
	case protocol.PacketNumberLen4:
		pn = protocol.PacketNumber(utils.BigEndian.Uint32(data[pos : pos+4]))
	default:
		return nil, fmt.Errorf("invalid packet number length: %d", pnLen)
	}
	kp := protocol.KeyPhaseZero
	if data[0]&0b100 > 0 {
		kp = protocol.KeyPhaseOne
	}

	var err error
	if data[0]&0x18 != 0 {
		err = ErrInvalidReservedBits
	}
	return &ShortHeader{
		DestConnectionID: destConnID,
		PacketNumber:     pn,
		PacketNumberLen:  pnLen,
		KeyPhase:         kp,
	}, err
}

func (h *ShortHeader) Len() protocol.ByteCount {
	return 1 + protocol.ByteCount(h.DestConnectionID.Len()) + protocol.ByteCount(h.PacketNumberLen)
}

// Log logs the Header
func (h *ShortHeader) Log(logger utils.Logger) {
	logger.Debugf("\tShort Header{DestConnectionID: %s, PacketNumber: %d, PacketNumberLen: %d, KeyPhase: %s}", h.DestConnectionID, h.PacketNumber, h.PacketNumberLen, h.KeyPhase)
}
